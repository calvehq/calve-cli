//! Index over the OpenAEVC protocol journal (M6, PLAN §55): which events have which kind,
//! time, actor and severity, and which IDs they reference. Maintained incrementally from its own
//! checkpoint, so readers never rescan the journal; it only narrows the candidates. Every
//! caller fetches the candidate events from OpenAEVC and applies its original predicate to
//! them, so results are exactly what a full scan returns (the journal stays the authority).
//!
//! `event_refs` holds each event's subjects and every ID-shaped string value in its body
//! (`exe_…`, `cpk_…`, `ns_…`): a lookup by an ID-shaped reference therefore finds every event
//! whose subjects or body contain it. A reference that is not ID-shaped is never looked up here;
//! its callers fall back to the full scan.
use std::collections::BTreeSet;

use openaevc::protocol::{Event, Query};
use openaevc_sdk::OpenAevcClient as _;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

use crate::{Project, Result, invalid};

pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS event_index (
      seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, ts_ns INTEGER NOT NULL,
      actor TEXT, severity TEXT
    );
    CREATE INDEX IF NOT EXISTS event_index_kind ON event_index(kind, seq);
    CREATE INDEX IF NOT EXISTS event_index_time ON event_index(ts_ns);
    CREATE INDEX IF NOT EXISTS event_index_actor ON event_index(actor, seq);
    CREATE TABLE IF NOT EXISTS event_refs (
      ref TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(ref, seq)
    ) WITHOUT ROWID;";

/// An OpenAEVC-style ID: a 2–4 letter lowercase prefix, `_`, then 20–40 `[a-z0-9]`.
pub(crate) fn id_shaped(s: &str) -> bool {
    let Some((prefix, rest)) = s.split_once('_') else {
        return false;
    };
    (2..=4).contains(&prefix.len())
        && prefix.bytes().all(|b| b.is_ascii_lowercase())
        && (20..=40).contains(&rest.len())
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn collect_refs(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(s) if id_shaped(s) => {
            out.insert(s.clone());
        }
        Value::Array(items) => items.iter().for_each(|v| collect_refs(v, out)),
        Value::Object(fields) => fields.values().for_each(|v| collect_refs(v, out)),
        _ => {}
    }
}

/// Necessary conditions of an activity filter, as SQL over `event_index` (and `event_refs`).
#[derive(Default)]
pub(crate) struct Candidates<'a> {
    pub kind: Option<&'a str>,
    pub kind_prefix: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub since_ns: Option<i128>,
    pub until_ns: Option<i128>,
    /// Every one must be referenced (ID-shaped references only).
    pub refs: Vec<&'a str>,
}

impl Project {
    /// Brings the index up to date with the journal (only events after its checkpoint).
    pub(crate) async fn refresh_event_index(&self) -> Result<()> {
        let checkpoint: u64 = self
            .db
            .query_row(
                "SELECT sequence FROM projection_checkpoints WHERE name='events'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        // Collected first and written after the scan: no transaction stays open across an await
        // (the daemon's requests share this connection on one thread).
        struct Row {
            seq: u64,
            kind: String,
            ts: i64,
            actor: Option<String>,
            severity: Option<String>,
            refs: BTreeSet<String>,
        }
        let mut rows: Vec<Row> = Vec::new();
        self.scan_protocol_events(checkpoint, |event| {
            let mut refs: BTreeSet<String> = event.subjects.iter().cloned().collect();
            collect_refs(&event.body, &mut refs);
            rows.push(Row {
                seq: event.sequence,
                ts: i64::try_from(event.timestamp.unix_nanos()).unwrap_or(i64::MAX),
                actor: event.actor.map(|a| a.to_string()),
                severity: event.body["severity"].as_str().map(str::to_owned),
                kind: event.kind,
                refs,
            });
            Ok(())
        })
        .await?;
        let Some(head) = rows.last().map(|r| r.seq) else {
            return Ok(());
        };
        let tx = self.db.unchecked_transaction()?;
        for r in rows {
            tx.execute(
                "INSERT OR REPLACE INTO event_index VALUES (?1,?2,?3,?4,?5)",
                params![r.seq, r.kind, r.ts, r.actor, r.severity],
            )?;
            for x in r.refs {
                tx.execute(
                    "INSERT OR IGNORE INTO event_refs VALUES (?1,?2)",
                    params![x, r.seq],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO projection_checkpoints VALUES ('events',?1)
             ON CONFLICT(name) DO UPDATE SET sequence=excluded.sequence",
            [head],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The events with these sequence numbers, in sequence order (consecutive runs fetched in
    /// one query each).
    pub(crate) async fn events_by_seq(&self, mut seqs: Vec<u64>) -> Result<Vec<Event>> {
        seqs.sort_unstable();
        seqs.dedup();
        let wanted: BTreeSet<u64> = seqs.iter().copied().collect();
        let mut out = Vec::with_capacity(seqs.len());
        let mut i = 0;
        while i < seqs.len() {
            let start = seqs[i];
            let mut end = start;
            while i + 1 < seqs.len() && seqs[i + 1] == end + 1 && end + 1 - start < 1000 {
                i += 1;
                end += 1;
            }
            i += 1;
            let page = self
                .client
                .query(Query::ListEvents {
                    after: start - 1,
                    limit: Some(u32::try_from(end - start + 1).unwrap_or(1000)),
                    kinds: vec![],
                })
                .await?;
            let page: Vec<Event> = serde_json::from_value(page)?;
            out.extend(page.into_iter().filter(|e| wanted.contains(&e.sequence)));
        }
        if out.len() != wanted.len() {
            return Err(invalid("OpenAEVC journal is missing indexed events"));
        }
        Ok(out)
    }

    /// Every event whose subjects or body contain `id`, in sequence order, or `None` when `id`
    /// is not ID-shaped (callers then scan the journal).
    pub(crate) async fn events_referencing(&self, id: &str) -> Result<Option<Vec<Event>>> {
        if !id_shaped(id) {
            return Ok(None);
        }
        self.refresh_event_index().await?;
        let seqs: Vec<u64> = {
            let mut q = self
                .db
                .prepare("SELECT seq FROM event_refs WHERE ref=?1 ORDER BY seq")?;
            q.query_map([id], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        Ok(Some(self.events_by_seq(seqs).await?))
    }

    /// Every event of exactly this kind, in sequence order.
    pub(crate) async fn events_of_kind(&self, kind: &str) -> Result<Vec<Event>> {
        self.refresh_event_index().await?;
        let seqs: Vec<u64> = {
            let mut q = self
                .db
                .prepare("SELECT seq FROM event_index WHERE kind=?1 ORDER BY seq")?;
            q.query_map([kind], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        self.events_by_seq(seqs).await
    }

    /// Candidate events for an activity filter in (timestamp, sequence) descending order —
    /// the order activity rows are ranked in, so a caller can stop exactly — in pages of
    /// `page`. `before` (the last event's timestamp and sequence) continues after a page.
    pub(crate) async fn candidate_events(
        &self,
        c: &Candidates<'_>,
        before: Option<(i64, u64)>,
        page: u32,
    ) -> Result<Vec<Event>> {
        let mut sql = String::from("SELECT e.seq FROM event_index e WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        if let Some((ts, seq)) = before {
            args.push(ts.into());
            args.push((seq as i64).into());
            sql.push_str(" AND (e.ts_ns < ?1 OR (e.ts_ns = ?1 AND e.seq < ?2))");
        }
        let mut push = |cond: &str, v: rusqlite::types::Value, sql: &mut String| {
            args.push(v);
            sql.push_str(&format!(
                " AND {}",
                cond.replace('?', &format!("?{}", args.len()))
            ));
        };
        if let Some(k) = c.kind {
            push("e.kind = ?", k.to_owned().into(), &mut sql);
        }
        if let Some(p) = c.kind_prefix {
            // `kind.split('.').next() == p`: the kind itself or `p.` followed by anything.
            push(
                "(e.kind = ? OR substr(e.kind, 1, length(?) + 1) = ? || '.')",
                p.to_owned().into(),
                &mut sql,
            );
        }
        if let Some(a) = c.actor {
            push("e.actor = ?", a.to_owned().into(), &mut sql);
        }
        if let Some(s) = c.severity {
            push("e.severity = ?", s.to_owned().into(), &mut sql);
        }
        if let Some(t) = c.since_ns {
            push(
                "e.ts_ns >= ?",
                (i64::try_from(t).unwrap_or(i64::MIN)).into(),
                &mut sql,
            );
        }
        if let Some(t) = c.until_ns {
            push(
                "e.ts_ns <= ?",
                (i64::try_from(t).unwrap_or(i64::MAX)).into(),
                &mut sql,
            );
        }
        for r in &c.refs {
            push(
                "EXISTS (SELECT 1 FROM event_refs x WHERE x.ref = ? AND x.seq = e.seq)",
                (*r).to_owned().into(),
                &mut sql,
            );
        }
        args.push(i64::from(page).into());
        sql.push_str(&format!(
            " ORDER BY e.ts_ns DESC, e.seq DESC LIMIT ?{}",
            args.len()
        ));
        let seqs: Vec<u64> = {
            let mut q = self.db.prepare(&sql)?;
            q.query_map(rusqlite::params_from_iter(args.iter()), |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        let mut events = self.events_by_seq(seqs).await?;
        events.sort_by(|a, b| {
            b.timestamp
                .unix_nanos()
                .cmp(&a.timestamp.unix_nanos())
                .then(b.sequence.cmp(&a.sequence))
        });
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_shape() {
        assert!(id_shaped("exe_agqxvuw4mb3cxmvpsfwtsgoqbe"));
        assert!(id_shaped("ns_agqxvuwlrzz4xmf3nn4szev7am"));
        assert!(!id_shaped("sha256:abc"));
        assert!(!id_shaped("EXE_agqxvuw4mb3cxmvpsfwtsgoqbe"));
        assert!(!id_shaped("exe_short"));
        assert!(!id_shaped("a_agqxvuw4mb3cxmvpsfwtsgoqbe"));
        assert!(!id_shaped("exe_agqx-uw4mb3cxmvpsfwtsgoqbe"));
    }

    #[test]
    fn refs_cover_every_string_value() {
        let mut out = BTreeSet::new();
        let body = serde_json::json!({"a": "exe_agqxvuw4mb3cxmvpsfwtsgoqbe",
            "b": [{"c": "cpk_agqxvuw4mb3cxmvpsfwtsgoqbe"}], "exe_agqxvuw4mb3cxmvpsfwtsgoqbf": 1,
            "d": "not an id"});
        collect_refs(&body, &mut out);
        assert_eq!(
            out.into_iter().collect::<Vec<_>>(),
            [
                "cpk_agqxvuw4mb3cxmvpsfwtsgoqbe",
                "exe_agqxvuw4mb3cxmvpsfwtsgoqbe"
            ]
        );
    }
}
