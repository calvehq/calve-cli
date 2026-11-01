//! What running executions hold. A run takes the Project writer lock only to admit itself and
//! to record its result; while the worker runs, this durable claim says what it is using, so
//! other commands proceed unless they would really collide. OpenAEVC stays the authority on
//! each pack and its generation; a claim only keeps Calve's own working-tree steps apart. A
//! claim whose execution has ended, for example because the daemon died, is dropped on sight.

use rusqlite::{OptionalExtension as _, params};

use crate::config::HarnessMode;
use crate::{Error, Project, Result};

#[derive(Debug, Clone)]
pub(crate) struct Claim {
    pub execution: String,
    pub pack: String,
    pub mode: HarnessMode,
    pub paths: Vec<String>,
}

/// Whether two harness scopes touch: an empty scope is the whole Project.
pub(crate) fn overlaps(a: &[String], b: &[String]) -> bool {
    let within = |outer: &str, inner: &str| {
        let outer = outer.trim_end_matches('/');
        inner == outer
            || inner
                .strip_prefix(outer)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    a.is_empty()
        || b.is_empty()
        || a.iter()
            .any(|x| b.iter().any(|y| within(x, y) || within(y, x)))
}

fn busy(what: &str, claim: &Claim) -> Error {
    Error::Busy(format!(
        "{what} collides with running execution {}; retry when it ends, or cancel it",
        claim.execution
    ))
}

impl Project {
    /// Running executions' claims. Ended ones are finished here, whatever ended them.
    pub(crate) async fn active_claims(&self) -> Result<Vec<Claim>> {
        let rows: Vec<(String, String, String, String)> = self
            .db
            .prepare(
                "SELECT execution_id, pack_id, mode, paths FROM execution_claims
                 WHERE finished_at IS NULL",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut claims = Vec::new();
        for (execution, pack, mode, paths) in rows {
            let state = self.execution(&execution).await?;
            if matches!(
                state["state"].as_str(),
                Some("SUCCEEDED" | "FAILED" | "CANCELLED" | "LOST")
            ) {
                self.finish_claim(&execution)?;
                continue;
            }
            claims.push(Claim {
                execution,
                pack,
                mode: serde_json::from_str(&mode)?,
                paths: serde_json::from_str(&paths)?,
            });
        }
        Ok(claims)
    }

    /// Refuses an execution that would collide with a running one: one run per pack, because
    /// each advances its generation, and no two changing runs on the same paths.
    pub(crate) async fn admit_claim(
        &self,
        pack: &str,
        mode: HarnessMode,
        paths: &[String],
    ) -> Result<()> {
        for claim in self.active_claims().await? {
            if claim.pack == pack {
                return Err(busy("this pack", &claim));
            }
            if mode == HarnessMode::Change
                && claim.mode == HarnessMode::Change
                && overlaps(paths, &claim.paths)
            {
                return Err(busy("this harness's paths", &claim));
            }
        }
        Ok(())
    }

    pub(crate) fn insert_claim(&self, claim: &Claim) -> Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO execution_claims
             (execution_id, pack_id, mode, paths, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                claim.execution,
                claim.pack,
                serde_json::to_string(&claim.mode)?,
                serde_json::to_string(&claim.paths)?,
                crate::now()?
            ],
        )?;
        Ok(())
    }

    pub(crate) fn finish_claim(&self, execution: &str) -> Result<()> {
        self.db.execute(
            "UPDATE execution_claims SET finished_at=?1 WHERE execution_id=?2",
            params![crate::now()?, execution],
        )?;
        // Nothing running: no run can still need the ended ones to explain its tree changes.
        let running: Option<i64> = self
            .db
            .query_row(
                "SELECT 1 FROM execution_claims WHERE finished_at IS NULL LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if running.is_none() {
            self.db.execute("DELETE FROM execution_claims", [])?;
        }
        Ok(())
    }

    /// The change scopes of every other run that overlapped this one in time: their file changes
    /// are theirs, not strays of this run.
    pub(crate) fn other_change_scopes(&self, execution: &str) -> Result<Vec<Vec<String>>> {
        let change = serde_json::to_string(&HarnessMode::Change)?;
        let rows: Vec<String> = self
            .db
            .prepare("SELECT paths FROM execution_claims WHERE execution_id<>?1 AND mode=?2")?
            .query_map(params![execution, change], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        rows.iter().map(|p| Ok(serde_json::from_str(p)?)).collect()
    }

    /// Refuses a command that writes or reads `paths` of the working tree (empty: all of it)
    /// while a run is changing them.
    pub(crate) async fn refuse_if_claimed(&self, what: &str, paths: &[String]) -> Result<()> {
        for claim in self.active_claims().await? {
            if claim.mode == HarnessMode::Change && overlaps(paths, &claim.paths) {
                return Err(busy(what, &claim));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::overlaps;

    fn v(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn scopes_overlap_by_path_component() {
        assert!(overlaps(&v(&[]), &v(&["a"])));
        assert!(overlaps(&v(&["a"]), &v(&["a/b"])));
        assert!(overlaps(&v(&["a/b/"]), &v(&["a"])));
        assert!(overlaps(&v(&["x", "a"]), &v(&["a"])));
        assert!(!overlaps(&v(&["a"]), &v(&["ab"])));
        assert!(!overlaps(&v(&["a"]), &v(&["d"])));
        assert!(!overlaps(&v(&["a/b"]), &v(&["a/c"])));
    }
}
