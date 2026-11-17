//! Exact-envelope command journaling (rev 10 §12, F22; FG8).
//!
//! Calve's request id and correlation id identify *Calve* requests (request log, idempotency-key
//! prefixes). OpenAEVC's own idempotency is per signed envelope: the same envelope (request id,
//! nonce, timestamp, bytes) returns the original receipt while its request record exists, i.e.
//! within the replay window. So an operation that must survive a crash journals the **exact
//! signed envelope** as an intent before sending it, and its receipt (or refusal) as the ack.
//! Recovery of an unacknowledged intent resends the identical bytes inside the window; outside it
//! (or once OpenAEVC pruned the record) the outcome is found by an authoritative **discovery**
//! query chosen by the caller. A non-idempotent command is never re-sent with a new request id
//! unless discovery proved it was not applied.
use openaevc::protocol::{Command, CommandEnvelope, CommandReceipt, ErrorCode, ProtocolError};
use serde_json::{Value, json};

use crate::journal::Journal;
use crate::{Project, Result};

/// OpenAEVC's replay window (runtime default); identical-envelope retries stay well inside it.
const REPLAY_WINDOW_MS: u64 = 300_000;
const MARGIN_MS: u64 = 30_000;

/// The window Calve relies on (debug builds may shrink it to force the discovery path in tests).
fn window_ms() -> u64 {
    if cfg!(debug_assertions)
        && let Some(ms) = std::env::var("CALVE_REPLAY_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse().ok())
    {
        return ms;
    }
    REPLAY_WINDOW_MS - MARGIN_MS
}

/// The outcome of one journaled command.
pub type Outcome = std::result::Result<CommandReceipt, ProtocolError>;

fn outcome_json(o: &Outcome) -> Value {
    match o {
        Ok(r) => json!({"receipt": r}),
        Err(e) => json!({"error": e}),
    }
}

/// A recorded ack, as an outcome.
pub fn recorded(ack: &Value) -> Option<Outcome> {
    if let Some(r) = ack.get("receipt") {
        return serde_json::from_value(r.clone()).ok().map(Ok);
    }
    ack.get("error")
        .and_then(|e| serde_json::from_value(e.clone()).ok())
        .map(Err)
}

/// How an unacknowledged intent was resolved.
pub enum Resolution {
    /// The identical envelope was resent inside the window.
    Replayed(Box<Outcome>),
    /// Outside the window: the caller must discover the outcome from OpenAEVC state.
    Discover,
}

impl Project {
    /// The current OpenAEVC journal head (events after the recorded checkpoint).
    pub(crate) fn journal_head(&self) -> Result<u64> {
        let mut head = crate::continuity::binding(&self.db)?.map_or(0, |b| b.checkpoint_seq);
        let src = crate::continuity::RuntimeEvents {
            runtime: &self.runtime,
            session: openaevc_sdk::OpenAevcClient::session(&self.client),
        };
        loop {
            let page = crate::continuity::Events::events(&src, head, 1000)?;
            match page.last() {
                Some(e) => head = e.sequence,
                None => return Ok(head),
            }
        }
    }

    /// Journals the signed envelope (`<step>` intent, with the journal head for discovery
    /// scans), sends it, journals the outcome (`<step>` ack) and returns it.
    pub(crate) fn send_journaled(
        &self,
        j: &mut Journal,
        fault_prefix: &str,
        step: &str,
        cmd: Command,
    ) -> Result<Outcome> {
        let env = openaevc_sdk::OpenAevcClient::session(&self.client).envelope(cmd)?;
        let head = self.journal_head()?;
        j.append(
            "intent",
            json!({"step": step, "envelope": env, "head": head}),
        )
        .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
        crate::journal::fault(&format!("{fault_prefix}.{step}.after_intent"));
        let outcome = self.runtime.execute(env);
        crate::journal::fault(&format!("{fault_prefix}.{step}.after_send"));
        j.append(
            "ack",
            json!({"step": step, "outcome": outcome_json(&outcome)}),
        )
        .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
        Ok(outcome)
    }

    /// Resolves an unacknowledged intent: the identical envelope inside the window, otherwise
    /// discovery. A replay that OpenAEVC refuses as outside its window also means discovery.
    pub(crate) fn resolve_intent(&self, intent: &Value) -> Result<Resolution> {
        let env: CommandEnvelope = serde_json::from_value(intent["envelope"].clone())?;
        let issued_ms = (env.issued_at.unix_nanos() / 1_000_000) as u64;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        if now_ms.saturating_sub(issued_ms) > window_ms() {
            return Ok(Resolution::Discover);
        }
        match self.runtime.execute(env) {
            Err(e) if e.code == ErrorCode::ReplayDetected => Ok(Resolution::Discover),
            other => Ok(Resolution::Replayed(Box::new(other))),
        }
    }

    /// Acks a resolved intent in the journal.
    pub(crate) fn ack_resolved(
        j: &mut Journal,
        step: &str,
        outcome: &Outcome,
        how: &str,
    ) -> Result<()> {
        j.append(
            "ack",
            json!({"step": step, "outcome": outcome_json(outcome), "resolved_by": how}),
        )
        .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
        Ok(())
    }

    /// Events after `head` (discovery scans).
    pub(crate) fn events_after(&self, head: u64) -> Result<Vec<openaevc::protocol::Event>> {
        let src = crate::continuity::RuntimeEvents {
            runtime: &self.runtime,
            session: openaevc_sdk::OpenAevcClient::session(&self.client),
        };
        let mut out = vec![];
        let mut after = head;
        loop {
            let page = crate::continuity::Events::events(&src, after, 1000)?;
            match page.last() {
                Some(e) => after = e.sequence,
                None => return Ok(out),
            }
            out.extend(page);
        }
    }
}
