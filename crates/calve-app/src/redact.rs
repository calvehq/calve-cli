//! Secret redaction (rev 10 §16.1, ADR 0015). Every secret value Calve resolves is turned into a
//! pattern set — raw, base64 (standard and URL-safe, at byte offsets 0/1/2, only the characters
//! fully determined by the secret), percent-encoded (upper/lower hex), JSON-escaped and hex
//! (lower/upper) — matched with Aho-Corasick and replaced by [`MARK`].
//!
//! Streams are redacted independently ([`StreamRedactor`]): each holds back the last
//! `longest pattern − 1` bytes until they can no longer start a match and flushes at EOF, so a
//! secret split across writes (even 1-byte writes) is still found. Residuals (user-approved,
//! asserted by tests): splits across *different* streams, arbitrary transformations, base64 edge
//! characters that depend on neighbouring bytes, and channels outside Calve's sinks.
//!
//! The process-wide registry ([`register`]) lets sinks that never see the secret directly
//! (errors, faults, bundles) redact too; values are held in `Zeroizing` buffers and dropped with
//! the returned guard.

use std::sync::{Arc, Mutex};

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine as _;
use zeroize::Zeroizing;

/// What a redacted secret is replaced with.
pub const MARK: &str = "[REDACTED]";

/// Secrets shorter than this over-match (a config-time warning; redaction still applies).
pub const SHORT_SECRET: usize = 4;

/// Every encoded form of `secret` that the redactor matches (deduplicated, non-empty).
pub fn patterns(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![secret.to_vec()];
    if secret.is_empty() {
        return vec![];
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        for k in 0..3usize {
            let mut data = vec![0u8; k];
            data.extend_from_slice(secret);
            let enc = engine.encode(&data).into_bytes();
            // Character i covers bits [6i, 6i+6); keep those inside the secret's bits.
            let first = (8 * k).div_ceil(6);
            let end = (8 * (k + secret.len())) / 6; // exclusive
            if first < end && end <= enc.len() {
                out.push(enc[first..end].to_vec());
            }
        }
    }
    let percent = |upper: bool| -> Vec<u8> {
        let mut s = String::new();
        for &b in secret {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                s.push(b as char);
            } else if upper {
                s.push_str(&format!("%{b:02X}"));
            } else {
                s.push_str(&format!("%{b:02x}"));
            }
        }
        s.into_bytes()
    };
    out.push(percent(true));
    out.push(percent(false));
    if let Ok(text) = std::str::from_utf8(secret)
        && let Ok(json) = serde_json::to_string(text)
    {
        out.push(json.as_bytes()[1..json.len() - 1].to_vec());
    }
    out.push(hex(secret, false));
    out.push(hex(secret, true));
    out.sort();
    out.dedup();
    out.retain(|p| !p.is_empty());
    out
}

fn hex(b: &[u8], upper: bool) -> Vec<u8> {
    b.iter()
        .map(|x| {
            if upper {
                format!("{x:02X}")
            } else {
                format!("{x:02x}")
            }
        })
        .collect::<String>()
        .into_bytes()
}

/// A compiled pattern set for some secrets.
#[derive(Clone)]
pub struct Redactor {
    ac: Option<Arc<AhoCorasick>>,
    longest: usize,
}

impl Redactor {
    pub fn new<S: AsRef<[u8]>>(secrets: impl IntoIterator<Item = S>) -> Self {
        let pats: Vec<Vec<u8>> = secrets
            .into_iter()
            .flat_map(|s| patterns(s.as_ref()))
            .collect();
        let longest = pats.iter().map(Vec::len).max().unwrap_or(0);
        let ac = (!pats.is_empty()).then(|| {
            Arc::new(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&pats)
                    .expect("literal patterns always compile"),
            )
        });
        Self { ac, longest }
    }

    pub fn is_empty(&self) -> bool {
        self.ac.is_none()
    }

    /// Redacts a complete buffer.
    pub fn bytes(&self, input: &[u8]) -> Vec<u8> {
        match &self.ac {
            Some(ac) => {
                let mut out = Vec::with_capacity(input.len());
                ac.replace_all_with_bytes(input, &mut out, |_, _, dst| {
                    dst.extend_from_slice(MARK.as_bytes());
                    true
                });
                out
            }
            None => input.to_vec(),
        }
    }

    pub fn text(&self, input: &str) -> String {
        if self.ac.is_none() {
            return input.to_owned();
        }
        String::from_utf8_lossy(&self.bytes(input.as_bytes())).into_owned()
    }

    /// A fresh per-stream state.
    pub fn stream(&self) -> StreamRedactor {
        StreamRedactor {
            r: self.clone(),
            pending: Vec::new(),
        }
    }
}

/// Redaction state of one stream: never shared between stdout and stderr.
pub struct StreamRedactor {
    r: Redactor,
    pending: Vec<u8>,
}

impl StreamRedactor {
    /// Feeds bytes; returns the redacted bytes that can no longer be part of a match.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(ac) = self.r.ac.clone() else {
            return chunk.to_vec();
        };
        self.pending.extend_from_slice(chunk);
        // Any match not yet complete starts at or after `cut`.
        let cut = self.pending.len().saturating_sub(self.r.longest - 1);
        let mut out = Vec::new();
        let mut emitted = 0;
        for m in ac.find_iter(&self.pending[..]) {
            if m.start() >= cut {
                break;
            }
            out.extend_from_slice(&self.pending[emitted..m.start()]);
            out.extend_from_slice(MARK.as_bytes());
            emitted = m.end();
        }
        let keep_from = cut.max(emitted);
        out.extend_from_slice(&self.pending[emitted..keep_from]);
        self.pending.drain(..keep_from);
        out
    }

    /// End of stream: everything left, redacted.
    pub fn finish(&mut self) -> Vec<u8> {
        let rest = std::mem::take(&mut self.pending);
        self.r.bytes(&rest)
    }
}

type Registry = Mutex<Vec<(u64, Zeroizing<Vec<u8>>)>>;

fn registry() -> &'static Registry {
    static R: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
}

/// Keeps secrets registered process-wide until dropped.
pub struct Registered(Vec<u64>);

impl Drop for Registered {
    fn drop(&mut self) {
        if let Ok(mut r) = registry().lock() {
            r.retain(|(id, _)| !self.0.contains(id));
        }
    }
}

/// Registers secret values for every sink of this process (faults, bundles, journals).
pub fn register<S: AsRef<[u8]>>(secrets: impl IntoIterator<Item = S>) -> Registered {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut ids = vec![];
    if let Ok(mut r) = registry().lock() {
        for s in secrets {
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            r.push((id, Zeroizing::new(s.as_ref().to_vec())));
            ids.push(id);
        }
    }
    Registered(ids)
}

/// A redactor for every secret currently registered in this process.
pub fn active() -> Redactor {
    match registry().lock() {
        Ok(r) => Redactor::new(r.iter().map(|(_, s)| s.as_slice())),
        Err(_) => Redactor::new(Vec::<Vec<u8>>::new()),
    }
}

/// Redacts `text` against every registered secret.
pub fn text(text: &str) -> String {
    active().text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encodings(secret: &str) -> Vec<String> {
        let b = secret.as_bytes();
        let mut v = vec![secret.to_owned()];
        for e in [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::URL_SAFE,
        ] {
            for prefix in ["", "x", "xy"] {
                v.push(e.encode([prefix.as_bytes(), b].concat()));
            }
        }
        v.push(serde_json::to_string(secret).unwrap());
        v.push(String::from_utf8(hex(b, false)).unwrap());
        v.push(String::from_utf8(hex(b, true)).unwrap());
        v
    }

    #[test]
    fn every_encoding_and_offset_is_redacted() {
        for secret in ["s3cr3t-Tok/en+==", "abc", &"k".repeat(4096), "pa\"ss\\wörd"] {
            let r = Redactor::new([secret]);
            for enc in encodings(secret) {
                let out = r.text(&format!("before {enc} after"));
                assert!(out.contains(MARK), "{secret:.20} as {enc:.40}: {out:.80}");
                // The secret's own determined characters never survive (short secrets only:
                // the scan is quadratic).
                for p in patterns(secret.as_bytes())
                    .into_iter()
                    .filter(|_| secret.len() < 64)
                {
                    if p.len() >= 4 {
                        assert!(
                            !out.as_bytes().windows(p.len()).any(|w| w == p.as_slice()),
                            "{enc:.40}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn one_byte_writes_are_redacted_per_stream() {
        let secret = "hunter2-very-secret";
        let r = Redactor::new([secret]);
        let input = format!(
            "a{secret}b{}c\n",
            base64::engine::general_purpose::STANDARD.encode(secret)
        );
        let mut s = r.stream();
        let mut out = vec![];
        for b in input.as_bytes() {
            out.extend(s.feed(&[*b]));
        }
        out.extend(s.finish());
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.matches(MARK).count(), 2, "{out}");
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn a_split_across_streams_is_not_redacted_residual() {
        let r = Redactor::new(["topsecret"]);
        let (mut out, mut err) = (r.stream(), r.stream());
        let mut o = out.feed(b"top");
        o.extend(out.finish());
        let mut e = err.feed(b"secret");
        e.extend(err.finish());
        assert_eq!([o, e].concat(), b"topsecret", "documented residual");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]
        /// Chunking never changes the result, and the raw secret never survives.
        #[test]
        fn streaming_equals_whole_buffer_redaction(
            secret in "[ -~]{4,40}",
            before in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            after in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            cuts in proptest::collection::vec(1usize..17, 1..40),
        ) {
            let r = Redactor::new([secret.as_str()]);
            let input = [before.as_slice(), secret.as_bytes(), after.as_slice()].concat();
            let whole = r.bytes(&input);
            let mut s = r.stream();
            let (mut out, mut at, mut i) = (vec![], 0, 0);
            while at < input.len() {
                let n = cuts[i % cuts.len()].min(input.len() - at);
                out.extend(s.feed(&input[at..at + n]));
                at += n;
                i += 1;
            }
            out.extend(s.finish());
            proptest::prop_assert_eq!(&out, &whole);
            proptest::prop_assert!(!out.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
    }

    #[test]
    fn faults_are_redacted() {
        let token = "fault-sink-secret-9876";
        let _g = register([token]);
        let f = crate::app::fault(crate::Error::Message(format!(
            "STALE_VIEW: worker said {token} and {}",
            base64::engine::general_purpose::STANDARD.encode(token)
        )));
        assert_eq!(f.code, "STALE_VIEW");
        assert!(
            !f.message.contains(token) && f.message.matches(MARK).count() == 2,
            "{}",
            f.message
        );
    }

    #[test]
    fn registry_is_scoped_to_the_guard() {
        let token = "registry-scoped-token-123";
        let g = register([token]);
        assert!(!text(&format!("x {token}")).contains(token));
        drop(g);
        assert!(text(&format!("x {token}")).contains(token));
    }
}
