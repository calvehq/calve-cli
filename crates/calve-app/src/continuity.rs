//! Cross-store identity and event continuity (rev 10 §11, ADR 0010).
//!
//! Journal identity is `(namespace_id, genesis_hash)` (the hash of the Namespace's first event),
//! recorded with the Project id in `store_binding`. On every open Calve verifies, with OpenAEVC's
//! own `verify_chain`, that the journal from the recorded checkpoint to the head extends the
//! checkpointed one; a writer then advances the checkpoint. The latest signed journal checkpoint
//! (runtime-signed object, FG10) is pinned too: its signature must verify with the Project's
//! runtime key and its `event_hash` must equal the current journal at that sequence, so a history
//! rewritten from the checkpoint on is detected even if every later hash was recomputed.
//!
//! Outcomes: `RECOVERY_REQUIRED` with `detail.reason` = `identity_mismatch` (another Project's
//! database, a fresh store), `continuity` (a gap, a broken link, a modified event, a signed
//! checkpoint that no longer matches) or `openaevc_behind` (the head is below the checkpoint).
//! Calve never writes OpenAEVC to repair; it only refuses.
use openaevc::protocol::{Digest, Event, JournalCheckpoint, ObjectEnvelope, PublicKey};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};

use crate::{ProjectIdentity, Result};

const PAGE: u32 = 1000;

/// Where events come from: the runtime (writers) or the store's read API (read-only inspect).
pub trait Events {
    /// Events with sequence > `after`, ascending, at most `limit`.
    fn events(&self, after: u64, limit: u32) -> Result<Vec<Event>>;
    /// The envelope of an object by digest.
    fn object(&self, digest: &Digest) -> Result<Option<ObjectEnvelope>>;
    /// The newest signed journal checkpoint `(digest, envelope)`, if one was written.
    fn latest_checkpoint(&self) -> Result<Option<(Digest, ObjectEnvelope)>>;
}

fn recovery(reason: &str, message: impl Into<String>, extra: Value) -> crate::Error {
    let mut detail = json!({"reason": reason});
    if let (Some(d), Some(e)) = (detail.as_object_mut(), extra.as_object()) {
        d.extend(e.clone());
    }
    crate::detailed("RECOVERY_REQUIRED", message, detail)
}

/// The binding stored in the product database, if any.
#[derive(Debug, Clone)]
pub struct Binding {
    pub project_id: String,
    pub namespace_id: String,
    pub genesis_hash: String,
    pub checkpoint_seq: u64,
    pub checkpoint_hash: String,
    pub signed_checkpoint: Option<Value>,
}

pub fn binding(db: &Connection) -> Result<Option<Binding>> {
    Ok(db
        .query_row(
            "SELECT project_id,namespace_id,genesis_hash,checkpoint_seq,checkpoint_hash,signed_checkpoint FROM store_binding WHERE id=1",
            [],
            |r| {
                Ok(Binding {
                    project_id: r.get(0)?,
                    namespace_id: r.get(1)?,
                    genesis_hash: r.get(2)?,
                    checkpoint_seq: r.get::<_, i64>(3)? as u64,
                    checkpoint_hash: r.get(4)?,
                    signed_checkpoint: r
                        .get::<_, Option<String>>(5)?
                        .and_then(|s| serde_json::from_str(&s).ok()),
                })
            },
        )
        .optional()?)
}

fn event_at(src: &impl Events, seq: u64) -> Result<Option<Event>> {
    if seq == 0 {
        return Ok(None);
    }
    Ok(src
        .events(seq - 1, 1)?
        .into_iter()
        .next()
        .filter(|e| e.sequence == seq))
}

/// A signed checkpoint that is genuine (runtime key) and agrees with the current journal.
fn check_signed(
    src: &impl Events,
    env: &ObjectEnvelope,
    runtime_key: &PublicKey,
) -> std::result::Result<JournalCheckpoint, String> {
    let body: JournalCheckpoint =
        serde_json::from_value(env.body.clone()).map_err(|e| format!("checkpoint body: {e}"))?;
    let digest = openaevc::core::signing_digest(env).map_err(|e| e.message)?;
    let signed = env.signatures.iter().any(|s| {
        s.public_key == *runtime_key
            && openaevc::crypto::verify_entry(
                s,
                openaevc::crypto::Domain::Object,
                digest.as_bytes(),
            )
            .is_ok()
    });
    if !signed {
        return Err("the journal checkpoint is not signed by this Project's runtime key".into());
    }
    match event_at(src, body.sequence).map_err(|e| e.to_string())? {
        Some(e) if e.hash == body.event_hash => Ok(body),
        Some(_) => Err(format!(
            "event {} differs from the signed journal checkpoint",
            body.sequence
        )),
        None => Err(format!(
            "event {} of the signed journal checkpoint is missing",
            body.sequence
        )),
    }
}

/// Verifies identity and continuity; a `writer` records the binding and advances the checkpoint.
/// Returns a report for `recover inspect` / status.
pub fn verify(
    db: &Connection,
    identity: &ProjectIdentity,
    src: &impl Events,
    runtime_key: &PublicKey,
    writer: bool,
) -> Result<Value> {
    let genesis = src
        .events(0, 1)?
        .into_iter()
        .next()
        .ok_or_else(|| recovery("continuity", "the OpenAEVC journal is empty", json!({})))?;
    let bound = binding(db)?;
    if let Some(b) = &bound {
        let expected = (
            identity.project_id.as_str(),
            identity.namespace_id.to_string(),
            genesis.hash.to_string(),
        );
        if (
            b.project_id.as_str(),
            b.namespace_id.clone(),
            b.genesis_hash.clone(),
        ) != expected
        {
            return Err(recovery(
                "identity_mismatch",
                "the product database is bound to another Project or OpenAEVC store",
                json!({"bound": {"project_id": b.project_id, "namespace_id": b.namespace_id, "genesis_hash": b.genesis_hash},
                    "found": {"project_id": expected.0, "namespace_id": expected.1, "genesis_hash": expected.2}}),
            ));
        }
    }
    let (mut seq, mut hash) = match &bound {
        Some(b) => {
            let at = b.checkpoint_seq;
            match event_at(src, at)? {
                None => {
                    return Err(recovery(
                        "openaevc_behind",
                        format!("the OpenAEVC journal ends before the recorded checkpoint {at}"),
                        json!({"checkpoint_seq": at}),
                    ));
                }
                Some(e) if e.hash.to_string() != b.checkpoint_hash => {
                    return Err(recovery(
                        "continuity",
                        format!("event {at} differs from the recorded checkpoint"),
                        json!({"checkpoint_seq": at}),
                    ));
                }
                Some(e) => (e.sequence, e.hash),
            }
        }
        None => (0, Digest::ZERO),
    };
    let from = seq;
    loop {
        let page = src.events(seq, PAGE)?;
        if page.is_empty() {
            break;
        }
        (seq, hash) = openaevc::core::events::verify_chain(&page, seq, hash).map_err(|e| {
            recovery(
                "continuity",
                format!(
                    "the OpenAEVC journal does not extend the checkpoint: {}",
                    e.message
                ),
                json!({"checkpoint_seq": from}),
            )
        })?;
    }
    // The pinned signed checkpoint must still agree; then pin the newest one.
    let mut pinned = bound.as_ref().and_then(|b| b.signed_checkpoint.clone());
    if let Some(p) = &pinned {
        let digest: Digest = p["digest"]
            .as_str()
            .and_then(|d| d.parse().ok())
            .ok_or_else(|| recovery("continuity", "malformed pinned checkpoint", json!({})))?;
        let env = src.object(&digest)?.ok_or_else(|| {
            recovery(
                "continuity",
                "the pinned signed journal checkpoint is missing",
                json!({"digest": digest}),
            )
        })?;
        check_signed(src, &env, runtime_key)
            .map_err(|why| recovery("continuity", why, json!({"digest": digest})))?;
    }
    if let Some((digest, env)) = src.latest_checkpoint()? {
        let body = check_signed(src, &env, runtime_key)
            .map_err(|why| recovery("continuity", why, json!({"digest": digest})))?;
        pinned = Some(
            json!({"digest": digest, "sequence": body.sequence, "event_hash": body.event_hash}),
        );
    }
    if writer {
        db.execute(
            "INSERT INTO store_binding(id,project_id,namespace_id,genesis_hash,checkpoint_seq,checkpoint_hash,signed_checkpoint,updated_at)
             VALUES (1,?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(id) DO UPDATE SET checkpoint_seq=excluded.checkpoint_seq,
               checkpoint_hash=excluded.checkpoint_hash, signed_checkpoint=excluded.signed_checkpoint,
               updated_at=excluded.updated_at",
            rusqlite::params![
                identity.project_id,
                identity.namespace_id.to_string(),
                genesis.hash.to_string(),
                seq as i64,
                hash.to_string(),
                pinned.as_ref().map(Value::to_string),
                crate::now()?
            ],
        )?;
    }
    Ok(
        json!({"genesis_hash": genesis.hash, "bound": bound.is_some(), "verified_from": from,
        "head": seq, "head_hash": hash, "signed_checkpoint": pinned}),
    )
}

/// Events through the open runtime, with the Project's own session.
pub struct RuntimeEvents<'a> {
    pub runtime: &'a openaevc::runtime::Runtime,
    pub session: &'a openaevc_sdk::Session,
}

impl RuntimeEvents<'_> {
    fn query(&self, q: openaevc::protocol::Query) -> Result<Value> {
        Ok(self.runtime.query(self.session.envelope(q)?)?)
    }
}

impl Events for RuntimeEvents<'_> {
    fn events(&self, after: u64, limit: u32) -> Result<Vec<Event>> {
        Ok(serde_json::from_value(self.query(
            openaevc::protocol::Query::ListEvents {
                after,
                limit: Some(limit),
                kinds: vec![],
            },
        )?)?)
    }

    fn object(&self, digest: &Digest) -> Result<Option<ObjectEnvelope>> {
        match self.query(openaevc::protocol::Query::GetObject { digest: *digest }) {
            Ok(v) => Ok(Some(serde_json::from_value(v["envelope"].clone())?)),
            Err(crate::Error::Protocol(e)) if e.code == openaevc::protocol::ErrorCode::NotFound => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn latest_checkpoint(&self) -> Result<Option<(Digest, ObjectEnvelope)>> {
        match self.query(openaevc::protocol::Query::GetJournalCheckpoint {}) {
            Ok(v) => Ok(Some((
                serde_json::from_value(v["digest"].clone())?,
                serde_json::from_value(v["envelope"].clone())?,
            ))),
            Err(crate::Error::Protocol(e)) if e.code == openaevc::protocol::ErrorCode::NotFound => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Events through the store's read API, without a runtime (read-only `recover inspect`).
pub struct StoreEvents<'a> {
    pub store: &'a openaevc::store::SqliteStore,
    pub namespace: openaevc::protocol::NamespaceId,
}

impl Events for StoreEvents<'_> {
    fn events(&self, after: u64, limit: u32) -> Result<Vec<Event>> {
        use openaevc::store::Store;
        Ok(self
            .store
            .read_events(&self.namespace, after, limit as usize)?)
    }

    fn object(&self, digest: &Digest) -> Result<Option<ObjectEnvelope>> {
        use openaevc::store::Store;
        Ok(self.store.get_object(digest)?.map(|o| o.envelope().clone()))
    }

    /// Inspect checks the pinned checkpoint only.
    fn latest_checkpoint(&self) -> Result<Option<(Digest, ObjectEnvelope)>> {
        Ok(None)
    }
}
