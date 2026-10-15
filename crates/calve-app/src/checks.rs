//! Language checks on a sealed candidate. Results become candidate-bound evidence that the
//! language's OpenAEVC verifier judges; Calve itself never decides pass/fail.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use openaevc::protocol::{Command, Digest, PackState, Query};
use openaevc_sdk::OpenAevcClient;
use serde_json::{Value, json};

use calve_integration_contract::wire::{CheckPlanOut, DetectOut, PlannedCheck};

use crate::catalog::install::PackageRecord;
use crate::config::EffectiveConfig;
use crate::providers::{resolve_executable, run_command};
use crate::{Error, Project, Result, event};

/// Calve's check-result evidence kind (product namespace), judged by each package's verifier.
pub const CHECK_EVIDENCE: &str = "org.calve.check-result/v1";

const DEFAULT_TIMEOUT_MS: u64 = 30 * 60 * 1000;
const TAIL_BYTES: usize = 8 * 1024;
/// Environment every check keeps; packages add their own names through `check_plan`.
const BASE_ENV: &[&str] = &["PATH", "HOME", "LANG", "TMPDIR"];

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// Removes the scratch tree even when a check panics or errors.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Configured command overrides: `[integrations."<extension id>".checks] name = [argv...]`.
fn overrides(r: &PackageRecord, config: &EffectiveConfig) -> Option<Vec<(String, Vec<String>)>> {
    let table = config.integrations.get(&r.id)?.get("checks")?.as_table()?;
    Some(
        table
            .iter()
            .filter_map(|(name, argv)| {
                let argv: Vec<String> = argv
                    .as_array()?
                    .iter()
                    .filter_map(|a| a.as_str().map(str::to_owned))
                    .collect();
                (!argv.is_empty()).then(|| (name.clone(), argv))
            })
            .collect(),
    )
}

/// A package's check plan comes from its sandboxed CIC module, so it may only name a program
/// on PATH (never a path, which could run candidate content or anything on disk), plain
/// arguments (no absolute paths or `..`), and environment variables that carry no credentials or
/// loader hooks (their values are the user's and end up in recorded output). Configured
/// overrides are the user's own and are not restricted.
fn validate_plan(c: &PlannedCheck) -> Result<()> {
    let bad = |m: String| {
        Err(invalid(format!(
            "ABI_VIOLATION: check_plan {}: {m}",
            c.name
        )))
    };
    let Some(program) = c.argv.first() else {
        return bad("empty argv".into());
    };
    if program.is_empty() || program.starts_with('.') || program.contains(['/', '\\', ':', '\0']) {
        return bad(format!("program {program:?} must be a bare command name"));
    }
    for a in &c.argv[1..] {
        let path_like = a.starts_with(['/', '\\', '~'])
            || a.contains(['\0', ':', '\\'])
            || a.contains("=/")
            || a.split('/').any(|seg| seg == "..");
        if path_like {
            return bad(format!(
                "argument {a:?} must not name paths outside the candidate"
            ));
        }
    }
    const SECRET: [&str; 9] = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "KEY",
        "AUTH",
        "COOKIE",
        "SESSION",
    ];
    for name in &c.env {
        let upper = name.to_ascii_uppercase();
        let shaped = !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !name.as_bytes()[0].is_ascii_digit();
        let hook = upper.starts_with("LD_") || upper.starts_with("DYLD_") || upper == "BASH_ENV";
        if !shaped || hook || SECRET.iter().any(|s| upper.contains(s)) {
            return bad(format!(
                "environment variable {name:?} is not passed to checks"
            ));
        }
    }
    Ok(())
}

impl Project {
    /// Copies the working tree (respecting ignore rules), then overlays the candidate's
    /// snapshots so tools see the candidate content for every captured path.
    fn materialize_candidate(
        &self,
        d: &crate::domains::FileDomain,
        effects: &[openaevc::protocol::AppliedEffect],
    ) -> Result<(Scratch, Vec<String>, Vec<String>)> {
        let scratch =
            Scratch(std::env::temp_dir().join(format!("calve-check-{}", uuid::Uuid::now_v7())));
        fs::create_dir(&scratch.0)?;
        let ws = self.workspace()?;
        let mut files = Vec::new();
        for item in self
            .list_resources_sync(d)?
            .as_array()
            .into_iter()
            .flatten()
        {
            if item["kind"] != "file" {
                continue;
            }
            let path = item["path"].as_str().unwrap_or_default();
            crate::validate_locator(path)?;
            let target = scratch.0.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            ws.copy_out(path, &target)
                .map_err(|e| invalid(format!("{path}: {e}")))?;
            files.push(path.to_owned());
        }
        let mut candidate = crate::resources::FileState::default();
        for effect in effects.iter().filter(|e| d.is_file_effect(e)) {
            crate::validate_locator(&effect.target.locator)?;
            candidate.apply(d, effect)?;
        }
        let mut drift = Vec::new();
        // Deletions and rename sources are removed so tools see the candidate tree.
        for locator in &candidate.removed {
            let target = scratch.0.join(locator);
            if target.exists() {
                drift.push(locator.clone());
                fs::remove_file(&target)?;
            }
            files.retain(|f| f != locator);
        }
        for (locator, content) in &candidate.files {
            let target = scratch.0.join(locator);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            if fs::read(&target).ok().as_deref() != Some(content.as_slice()) {
                drift.push(locator.clone());
            }
            fs::write(&target, content)?;
            if !files.contains(locator) {
                files.push(locator.clone());
            }
        }
        Ok((scratch, files, drift))
    }

    /// Runs language checks against a sealed pack and records each result as evidence.
    pub async fn run_checks(
        &self,
        config: &EffectiveConfig,
        pack_id: &str,
        generation: u64,
        languages: &[String],
        only: &[String],
    ) -> Result<Value> {
        let pack = self.pack(pack_id).await?;
        if pack.generation != generation
            || !matches!(pack.state, PackState::Sealed | PackState::Qualified)
        {
            return Err(invalid(
                "checks need a sealed pack at the requested generation",
            ));
        }
        let candidate: Digest = pack
            .sealed
            .as_ref()
            .ok_or_else(|| invalid("pack has no sealed candidate"))?
            .candidate;
        let d = self.file_domain().await?;
        let (scratch, files, drift) = self.materialize_candidate(&d, &pack.candidate_effects)?;
        // Detection and plans come from each checks package's CIC `detect` / `check_plan`.
        let markers: Vec<String> = fs::read_dir(&scratch.0)?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        let extensions: Vec<String> = files
            .iter()
            .filter_map(|f| Path::new(f).extension()?.to_str().map(str::to_owned))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut plans: Vec<(PackageRecord, String, PlannedCheck)> = Vec::new();
        for (r, decl) in self.check_domains().await? {
            let mut s = crate::domains::open_session(&r)?;
            let wanted: Vec<String> = if languages.is_empty() {
                let out: DetectOut = serde_json::from_value(
                    s.request(
                        "detect",
                        json!({"markers": markers, "extensions": extensions}),
                    )
                    .map_err(crate::domains::cic_error)?,
                )
                .map_err(|e| invalid(format!("ABI_VIOLATION: detect: {e}")))?;
                out.languages
            } else {
                languages.to_vec()
            };
            if wanted.is_empty() {
                continue;
            }
            let plan: CheckPlanOut = serde_json::from_value(
                s.request(
                    "check_plan",
                    json!({"languages": wanted, "markers": markers}),
                )
                .map_err(crate::domains::cic_error)?,
            )
            .map_err(|e| invalid(format!("ABI_VIOLATION: check_plan: {e}")))?;
            for c in plan.checks {
                validate_plan(&c)?;
                if !wanted.contains(&c.language) {
                    return Err(invalid(format!(
                        "ABI_VIOLATION: check_plan returned {} for {wanted:?}",
                        c.language
                    )));
                }
                plans.push((r.clone(), decl.verifier.clone(), c));
            }
        }
        if let Some(missing) = languages
            .iter()
            .find(|l| !plans.iter().any(|(_, _, c)| &c.language == *l))
        {
            return Err(invalid(format!(
                "unknown language {missing}: no enabled checks package plans it"
            )));
        }
        if plans.is_empty() {
            return Err(invalid("no supported language detected; pass --language"));
        }
        let mut report = Vec::new();
        let mut by_language: BTreeMap<
            (String, String),
            (PackageRecord, String, Vec<PlannedCheck>),
        > = BTreeMap::new();
        for (r, verifier, c) in plans {
            by_language
                .entry((r.id.clone(), c.language.clone()))
                .or_insert_with(|| (r, verifier, vec![]))
                .2
                .push(c);
        }
        for ((_, language), (r, verifier, planned)) in by_language {
            let mut evidence = Vec::new();
            let mut results = Vec::new();
            let configured = overrides(&r, config);
            let mut checks: Vec<(String, Vec<String>, PlannedCheck)> = match &configured {
                Some(list) => list
                    .iter()
                    .map(|(n, a)| (n.clone(), a.clone(), planned[0].clone()))
                    .collect(),
                None => planned
                    .iter()
                    .map(|c| (c.name.clone(), c.argv.clone(), c.clone()))
                    .collect(),
            };
            checks.retain(|(name, _, _)| only.is_empty() || only.contains(name));
            for (name, mut argv, plan) in checks {
                let env: BTreeMap<String, String> = BASE_ENV
                    .iter()
                    .map(|s| s.to_string())
                    .chain(plan.env.iter().cloned())
                    .filter_map(|n| std::env::var(&n).ok().map(|v| (n, v)))
                    .collect();
                if configured.is_none() && plan.takes_files {
                    argv.extend(
                        files
                            .iter()
                            .filter(|f| {
                                Path::new(f)
                                    .extension()
                                    .and_then(|e| e.to_str())
                                    .is_some_and(|e| plan.sources.iter().any(|s| s == e))
                            })
                            // `./` keeps a file named like an option from becoming one.
                            .map(|f| format!("./{f}")),
                    );
                }
                let mut result = json!({"language":language,"check":name,"argv":argv,
                    "candidate":candidate,"base":"working-copy","drift":drift});
                match resolve_executable(&argv[0]) {
                    Err(_) => {
                        result["tool_available"] = json!(false);
                        result["exit_code"] = Value::Null;
                    }
                    Ok(program) => {
                        let mut resolved = argv.clone();
                        resolved[0] = program.display().to_string();
                        let root = scratch.0.clone();
                        let run = tokio::task::spawn_blocking(move || {
                            run_command(
                                &resolved,
                                &root,
                                &env,
                                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                                TAIL_BYTES,
                            )
                        })
                        .await
                        .map_err(|error| invalid(format!("check runner failed: {error}")))??;
                        result["tool_available"] = json!(true);
                        result["exit_code"] = json!(run.exit_code);
                        result["timed_out"] = json!(run.timed_out);
                        result["duration_ms"] = json!(run.duration_ms);
                        result["output_tail"] = json!(run.output_tail);
                    }
                }
                let digest = self
                    .register_evidence(
                        pack_id,
                        generation,
                        CHECK_EVIDENCE,
                        "application/json",
                        serde_json::to_vec(&result)?,
                    )
                    .await?;
                evidence.push(digest);
                results.push(
                    json!({"check":name,"tool_available":result["tool_available"],
                    "exit_code":result["exit_code"],"evidence":digest}),
                );
            }
            let verification = if !evidence.is_empty() {
                let receipt = self
                    .client
                    .command(Command::RunVerification {
                        pack: pack.id,
                        generation,
                        verifier: verifier.clone(),
                        config: None,
                        evidence,
                    })
                    .await?;
                let digest = receipt
                    .result
                    .digest
                    .ok_or_else(|| invalid("verification returned no digest"))?;
                let object: Value = self.client.query(Query::GetVerification { digest }).await?;
                json!({"digest":digest,"verifier":verifier,"status":object["envelope"]["body"]["status"],
                    "findings":object["envelope"]["body"]["findings"]})
            } else {
                json!({"status":null,"note":"no check selected"})
            };
            event(&self.db, "checks.ran", pack_id, &language)?;
            report.push(json!({"language":language,"extension":r.id,"checks":results,"verification":verification}));
        }
        Ok(
            json!({"pack":pack.id,"generation":generation,"candidate":candidate,"drift":drift,"languages":report}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(argv: &[&str], env: &[&str]) -> PlannedCheck {
        PlannedCheck {
            language: "toy".into(),
            name: "t".into(),
            argv: argv.iter().map(|s| (*s).into()).collect(),
            takes_files: false,
            env: env.iter().map(|s| (*s).into()).collect(),
            sources: vec![],
        }
    }

    #[test]
    fn plans_name_only_programs_on_path_plain_arguments_and_safe_environment() {
        let ok = [
            plan(
                &["cargo", "clippy", "--", "-D", "warnings"],
                &["CARGO_HOME"],
            ),
            plan(
                &["cmake", "-S", ".", "-B", "build"],
                &["CC", "NODE_OPTIONS"],
            ),
            plan(&["go", "test", "./..."], &["GOFLAGS"]),
        ];
        for p in &ok {
            assert!(validate_plan(p).is_ok(), "{:?}", p.argv);
        }
        let refused = [
            plan(&[], &[]),
            plan(&["/bin/sh", "-c", "x"], &[]),
            plan(&["./cargo"], &[]),
            plan(&["bin/tool"], &[]),
            plan(&["..\\tool.exe"], &[]),
            plan(&["C:tool"], &[]),
            plan(&["cat", "/etc/passwd"], &[]),
            plan(&["cat", "../../.ssh/id_ed25519"], &[]),
            plan(&["cat", "~/.netrc"], &[]),
            plan(&["tool", "--config=/etc/x"], &[]),
            plan(&["tool", "C:\\x"], &[]),
            plan(&["env"], &["GITHUB_TOKEN"]),
            plan(&["env"], &["AWS_SECRET_ACCESS_KEY"]),
            plan(&["env"], &["LD_PRELOAD"]),
            plan(&["env"], &["DYLD_INSERT_LIBRARIES"]),
            plan(&["env"], &["BASH_ENV"]),
            plan(&["env"], &["A-B"]),
            plan(&["env"], &["1X"]),
        ];
        for p in &refused {
            assert!(validate_plan(p).is_err(), "{:?} {:?}", p.argv, p.env);
        }
    }
}
