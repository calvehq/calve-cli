//! Host-side session framing shared by every ABI 1 host implementation (rev 10 §6.2–§6.5b).
//!
//! A [`Driver`] moves raw request bytes to a guest and raw response bytes back; Calve's
//! production host (`calve-app` sandbox) and the independent `calve-testkit` mini host both
//! implement it and share no wasm code. [`Session`] adds the message layer (hello/0,
//! negotiation against signed metadata, `seq`, the `ok`/`err` envelope), and [`capture`] and
//! [`relate`] drive the streaming state machines with the contract's verifiers.

use serde_json::{Value, json};

use crate::digest::{LineHasher, input_digest};
use crate::hello::{Hello, HelloRequest, HostHello, Negotiated};
use crate::metadata::Metadata;
use crate::session::{
    CaptureBegin, CaptureChunk, CaptureChunkOk, CaptureFinishOk, CaptureVerifier, Group,
    KindOutcome, RelateBegin, RelateChunkOk, RelateFinishOk, RelateGroups, RelateVerifier,
    Relation, op,
};
use crate::wire::{Response, Tuple, WireError};
use crate::{jcs, negotiate};

/// Host-side outcome classes (§6.3 host codes), plus a guest-reported wire error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    Trapped(String),
    AbiViolation(String),
    OutOfFuel,
    DeadlineExceeded,
    OutOfMemory,
    Cancelled,
    /// Negotiation failed (`INCOMPATIBLE_CIC`): abi, wire, capability or schema.
    Incompatible(String),
    Internal(String),
    /// A guest `{"err": …}` with its wire code.
    Guest(WireError),
}

impl HostError {
    pub fn code(&self) -> &str {
        match self {
            HostError::Trapped(_) => "TRAPPED",
            HostError::AbiViolation(_) => "ABI_VIOLATION",
            HostError::OutOfFuel => "OUT_OF_FUEL",
            HostError::DeadlineExceeded => "DEADLINE_EXCEEDED",
            HostError::OutOfMemory => "OUT_OF_MEMORY",
            HostError::Cancelled => "CANCELLED",
            HostError::Incompatible(_) => "INCOMPATIBLE_CIC",
            HostError::Internal(_) => "INTERNAL",
            HostError::Guest(e) => &e.code,
        }
    }

    /// `CODE detail` — the form carried over the supervised sandbox's error frame.
    pub fn encode(&self) -> String {
        let detail = match self {
            HostError::Trapped(d)
            | HostError::AbiViolation(d)
            | HostError::Incompatible(d)
            | HostError::Internal(d) => d.as_str(),
            HostError::Guest(e) => &e.message,
            _ => "",
        };
        format!("{} {detail}", self.code())
    }

    pub fn decode(s: &str) -> HostError {
        let (code, detail) = s.split_once(' ').unwrap_or((s, ""));
        let d = detail.to_owned();
        match code {
            "TRAPPED" => HostError::Trapped(d),
            "ABI_VIOLATION" => HostError::AbiViolation(d),
            "OUT_OF_FUEL" => HostError::OutOfFuel,
            "DEADLINE_EXCEEDED" => HostError::DeadlineExceeded,
            "OUT_OF_MEMORY" => HostError::OutOfMemory,
            "CANCELLED" => HostError::Cancelled,
            "INCOMPATIBLE_CIC" => HostError::Incompatible(d),
            _ => HostError::Internal(s.to_owned()),
        }
    }
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.encode().trim_end())
    }
}

impl std::error::Error for HostError {}

/// One ABI 1 host implementation: raw request bytes in, raw response bytes out.
pub trait Driver {
    fn init(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError>;
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError>;
}

impl<T: Driver + ?Sized> Driver for &mut T {
    fn init(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        (**self).init(req)
    }
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        (**self).call(req)
    }
}

impl Driver for Box<dyn Driver> {
    fn init(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        (**self).init(req)
    }
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        (**self).call(req)
    }
}

impl Driver for Box<dyn Driver + Send> {
    fn init(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        (**self).init(req)
    }
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        (**self).call(req)
    }
}

pub fn canon(v: &Value) -> Result<Vec<u8>, HostError> {
    jcs::to_vec(v).map_err(|_| HostError::Internal("float in a host message".into()))
}

/// One CIC session over a fresh guest instance (§6.2 lifecycle): `hello/0`, negotiation
/// against the signed metadata, then framed requests with `seq` from 1. Any host error ends
/// the session; the instance is never reused.
pub struct Session<D: Driver> {
    pub d: D,
    pub negotiated: Negotiated,
    seq: u64,
    dead: bool,
    /// Raw request/response bytes, kept only when recording goldens.
    pub transcript: Option<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl<D: Driver> Session<D> {
    pub fn open(d: D, host: &HostHello, meta: &Metadata) -> Result<Self, HostError> {
        Self::open_with(d, host, meta, false)
    }

    pub fn open_recording(d: D, host: &HostHello, meta: &Metadata) -> Result<Self, HostError> {
        Self::open_with(d, host, meta, true)
    }

    fn open_with(
        mut d: D,
        host: &HostHello,
        meta: &Metadata,
        record: bool,
    ) -> Result<Self, HostError> {
        let hello = HelloRequest {
            hello: 0,
            host: host.clone(),
            x: None,
        };
        let req = canon(&serde_json::to_value(hello).expect("hello"))?;
        let resp = d.init(&req)?;
        let reply: Hello = serde_json::from_slice(&resp)
            .map_err(|e| HostError::AbiViolation(format!("hello: {e}")))?;
        if reply.hello != 0 {
            return Err(HostError::AbiViolation("hello is not 0".into()));
        }
        if reply.guest.extension_id != meta.extension_id || reply.guest.version != meta.version {
            return Err(HostError::AbiViolation(
                "hello identity differs from the signed metadata".into(),
            ));
        }
        let negotiated = negotiate(host, &reply.guest, &meta.declared()).map_err(|e| match e {
            crate::hello::NegotiationError::MetadataMismatch(axis) => {
                HostError::AbiViolation(format!("hello {axis} differs from the signed metadata"))
            }
            other => HostError::Incompatible(format!("{other:?}")),
        })?;
        Ok(Session {
            d,
            negotiated,
            seq: 0,
            dead: false,
            transcript: record.then(|| vec![(req, resp)]),
        })
    }

    /// One request; the outer error is a host failure (session over), the inner one a guest
    /// wire error (session continues only if the caller chooses).
    pub fn raw(&mut self, op: &str, body: Value) -> Result<Result<Value, WireError>, HostError> {
        if self.dead {
            return Err(HostError::Internal("session already failed".into()));
        }
        let r = self.raw_inner(op, body);
        self.dead |= r.is_err();
        r
    }

    fn raw_inner(&mut self, op: &str, body: Value) -> Result<Result<Value, WireError>, HostError> {
        let cap = op.split('.').next().unwrap_or(op);
        if !self.negotiated.capabilities.contains(&format!("{cap}.v1")) {
            return Err(HostError::Guest(WireError {
                code: "UNSUPPORTED_OP".into(),
                message: format!("{op} is not negotiated"),
                retryable: false,
            }));
        }
        self.seq += 1;
        let req =
            canon(&json!({"v": self.negotiated.wire(), "seq": self.seq, "op": op, "body": body}))?;
        let resp = self.d.call(&req)?;
        if let Some(t) = &mut self.transcript {
            t.push((req, resp.clone()));
        }
        let r: Response = serde_json::from_slice(&resp)
            .map_err(|e| HostError::AbiViolation(format!("envelope: {e}")))?;
        if r.seq != self.seq {
            return Err(HostError::AbiViolation(format!(
                "seq {} != {}",
                r.seq, self.seq
            )));
        }
        match (r.ok, r.err) {
            (Some(v), None) => Ok(Ok(v)),
            (None, Some(e)) => Ok(Err(e)),
            _ => Err(HostError::AbiViolation("exactly one of ok/err".into())),
        }
    }

    pub fn request(&mut self, op: &str, body: Value) -> Result<Value, HostError> {
        let r = self.raw(op, body)?;
        r.map_err(|e| {
            self.dead = true;
            HostError::Guest(e)
        })
    }
}

fn typed<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, HostError> {
    serde_json::from_value(v).map_err(|e| HostError::AbiViolation(e.to_string()))
}

pub fn manifest_digest<'a>(m: impl IntoIterator<Item = &'a crate::wire::Entry>) -> String {
    let mut h = LineHasher::new();
    for e in m {
        h.push(&serde_json::to_value(e).expect("entry"))
            .expect("integer-only");
    }
    h.finish()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureOut {
    pub input_digest: String,
    pub output_digest: String,
    pub total_ops: u64,
}

/// Host side of a capture session (§6.5): `begin`, chunks of at most `batch` tuples, `finish`.
/// Tuples arrive from any source in path order (the caller's merge join); every op of every
/// chunk is validated, then handed to `sink` in order (production: the on-disk spool).
/// `expected_tuples` is the merge-join count, known before `begin`.
#[allow(clippy::too_many_arguments)]
pub fn capture<D: Driver>(
    s: &mut Session<D>,
    base_digest: &str,
    work_digest: &str,
    expected_tuples: u64,
    params: Value,
    tuples: impl IntoIterator<Item = Tuple>,
    batch: usize,
    mut sink: impl FnMut(&Value) -> Result<(), HostError>,
) -> Result<CaptureOut, HostError> {
    let begin = CaptureBegin {
        base_digest: base_digest.into(),
        expected_tuples,
        params: params.clone(),
        work_digest: work_digest.into(),
    };
    s.request(
        op::CAPTURE_BEGIN,
        serde_json::to_value(begin).expect("begin"),
    )?;
    let mut v = CaptureVerifier::default();
    let mut th = LineHasher::new();
    let (mut index, mut sent_total, mut buf) = (0u64, 0u64, Vec::with_capacity(batch.max(1)));
    let mut flush = |buf: &mut Vec<Tuple>,
                     s: &mut Session<D>,
                     v: &mut CaptureVerifier|
     -> Result<(), HostError> {
        let sent = CaptureChunk {
            index,
            tuples: std::mem::take(buf),
        };
        let got: CaptureChunkOk = typed(s.request(
            op::CAPTURE_CHUNK,
            serde_json::to_value(&sent).expect("chunk"),
        )?)?;
        v.chunk(&sent, &got).map_err(HostError::AbiViolation)?;
        for o in &got.ops {
            sink(o)?;
        }
        index += 1;
        Ok(())
    };
    for t in tuples {
        th.push(&serde_json::to_value(&t).expect("tuple"))
            .map_err(|_| HostError::Internal("float in a tuple".into()))?;
        sent_total += 1;
        buf.push(t);
        if buf.len() >= batch.max(1) {
            flush(&mut buf, s, &mut v)?;
        }
    }
    if !buf.is_empty() {
        flush(&mut buf, s, &mut v)?;
    }
    if sent_total != expected_tuples {
        return Err(HostError::Internal(format!(
            "tuple source produced {sent_total}, expected {expected_tuples}"
        )));
    }
    let fin: CaptureFinishOk =
        typed(s.request(op::CAPTURE_FINISH, json!({"total_tuples": sent_total}))?)?;
    let o = v.finish(&fin).map_err(HostError::AbiViolation)?;
    let wire = s.negotiated.wire();
    let i = input_digest(
        &wire,
        "capture",
        &params,
        base_digest,
        work_digest,
        &th.finish(),
    );
    Ok(CaptureOut {
        input_digest: i,
        output_digest: o,
        total_ops: fin.total_ops,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct RelateOut {
    /// Accepted relations in canonical order: by kind, then members.
    pub relations: Vec<Relation>,
    pub kinds: Vec<KindOutcome>,
    /// Digest of `relations` in that canonical order (§6.6: invariant over batch and group
    /// chunk sizes). The wire digest the guest reported, which follows delivery order, was
    /// checked by the verifier.
    pub r: String,
}

/// Host side of a relate session (§6.5b) over an already-grouped stream with its commitment.
/// Relations are returned only after `finish` verified everything (atomicity): any error
/// discards them all.
#[allow(clippy::too_many_arguments)]
pub fn relate<D: Driver>(
    s: &mut Session<D>,
    meta: &Metadata,
    source_o: &str,
    params: Value,
    max_group: u64,
    commitment: (u64, u64, String),
    groups: impl IntoIterator<Item = Group>,
    chunk: usize,
) -> Result<RelateOut, HostError> {
    let (tg, tm, c) = commitment;
    let begin = RelateBegin {
        groups_commitment: c,
        max_group,
        params,
        source_o: source_o.into(),
        total_groups: tg,
        total_members: tm,
    };
    s.request(
        op::RELATE_BEGIN,
        serde_json::to_value(&begin).expect("begin"),
    )?;
    let mut v = RelateVerifier::new(meta, begin);
    let (mut index, mut buf) = (0u64, Vec::with_capacity(chunk.max(1)));
    let mut send = |buf: &mut Vec<Group>,
                    s: &mut Session<D>,
                    v: &mut RelateVerifier|
     -> Result<(), HostError> {
        let sent = RelateGroups {
            groups: std::mem::take(buf),
            index,
        };
        let got: RelateChunkOk = typed(s.request(
            op::RELATE_GROUPS,
            serde_json::to_value(&sent).expect("groups"),
        )?)?;
        v.chunk(&sent, got).map_err(HostError::AbiViolation)?;
        index += 1;
        Ok(())
    };
    for g in groups {
        buf.push(g);
        if buf.len() >= chunk.max(1) {
            send(&mut buf, s, &mut v)?;
        }
    }
    if !buf.is_empty() {
        send(&mut buf, s, &mut v)?;
    }
    let fin: RelateFinishOk = typed(s.request(
        op::RELATE_FINISH,
        json!({"total_groups": tg, "total_members": tm}),
    )?)?;
    let (mut relations, kinds, _wire_r) = v.finish(fin).map_err(HostError::AbiViolation)?;
    // Delivery order depends on how groups were chunked; what Calve records must not.
    relations.sort_by(|a, b| (&a.kind, &a.members).cmp(&(&b.kind, &b.members)));
    let mut h = LineHasher::new();
    for rel in &relations {
        h.push(&serde_json::to_value(rel).expect("relation"))
            .map_err(|_| HostError::AbiViolation("float in relation".into()))?;
    }
    Ok(RelateOut {
        relations,
        kinds,
        r: h.finish(),
    })
}

/// Frame codec for the supervised sandbox (§6.7): `[tag u8][len u32 LE][bytes]`.
/// Requests: tag 0 = init, 1 = call. Replies: tag 0 = ok bytes, 1 = [`HostError::encode`].
pub mod frame {
    use std::io::{Error, ErrorKind, Read, Result, Write};

    pub const INIT: u8 = 0;
    pub const CALL: u8 = 1;
    pub const OK: u8 = 0;
    pub const ERR: u8 = 1;

    pub fn write(w: &mut impl Write, tag: u8, bytes: &[u8]) -> Result<()> {
        let len = u32::try_from(bytes.len())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "frame too large"))?;
        w.write_all(&[tag])?;
        w.write_all(&len.to_le_bytes())?;
        w.write_all(bytes)?;
        w.flush()
    }

    /// Reads one frame of at most `max` bytes.
    pub fn read(r: &mut impl Read, max: u32) -> Result<(u8, Vec<u8>)> {
        let mut h = [0u8; 5];
        r.read_exact(&mut h)?;
        let len = u32::from_le_bytes([h[1], h[2], h[3], h[4]]);
        if len > max {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "frame exceeds the limit",
            ));
        }
        let mut b = vec![0u8; len as usize];
        r.read_exact(&mut b)?;
        Ok((h[0], b))
    }
}
