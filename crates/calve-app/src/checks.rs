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

/// A package's check plan comes from its sandboxed CIC module but runs with the user's
/// permissions, so it runs only once the user approved that exact plan in this Project (see
/// [`approval_digest`]). The program must also be a bare name found on an absolute PATH entry (a
/// path could run candidate content). The argument and environment-name rules below are defence
/// in depth, not the boundary: a denylist cannot confine an arbitrary program. Configured
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The executable a plan's program resolves to on this machine now: its canonical path and
/// sha256, or `None` when it is not installed.
type Executable = Option<(PathBuf, String)>;

fn executable_identity(program: &str) -> Result<Executable> {
    use sha2::{Digest as _, Sha256};
    let Ok(path) = resolve_executable(program) else {
        return Ok(None);
    };
    let mut h = Sha256::new();
    std::io::copy(&mut fs::File::open(&path)?, &mut h)?;
    Ok(Some((path, hex(&h.finalize()))))
}

/// SHA-256 of everything an approval covers: the exact plan (every field), the package that
/// produced it (id, version, target, every file digest) and the executable it resolves to
/// (canonical path and content digest). A changed plan, package, PATH resolution or executable
/// is a different digest and needs a new approval.
fn approval_digest(r: &PackageRecord, c: &PlannedCheck, exe: &Executable) -> Result<String> {
    let package =
        json!({"id": r.id, "version": r.version, "target": r.target, "digests": r.digests});
    covered_digest(&package, c, exe)
}

fn covered_digest(package: &Value, c: &PlannedCheck, exe: &Executable) -> Result<String> {
    use sha2::{Digest as _, Sha256};
    let covered = json!({
        "plan": c,
        "package": package,
        "executable": exe.as_ref().map(|(p, d)| json!({"path": p.to_string_lossy(), "sha256": d})),
    });
    let canonical = calve_integration_contract::jcs::to_vec(&covered)
        .map_err(|_| invalid("check plan is not canonical JSON"))?;
    Ok(hex(&Sha256::digest(canonical)))
}

impl Project {
    /// Copies the working tree (respecting ignore rules), then overlays the candidate's
    /// snapshots so tools see the candidate content for every captured path.
    async fn materialize_candidate(
        &self,
        d: &crate::domains::FileDomain,
        effects: &[openaevc::protocol::AppliedEffect],
    ) -> Result<(Scratch, Vec<String>, Vec<String>)> {
        let scratch =
            Scratch(std::env::temp_dir().join(format!("calve-check-{}", uuid::Uuid::now_v7())));
        // The copy can hold files the user keeps private; other local users must not read it.
        crate::journal::private_dir(&scratch.0)?;
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
            let content = self.content_bytes(locator, content).await?;
            let target = scratch.0.join(locator);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            if fs::read(&target).ok().as_deref() != Some(content.as_slice()) {
                drift.push(locator.clone());
            }
            fs::write(&target, &content)?;
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
        approve: &[String],
    ) -> Result<Value> {
        let pack = self.pack(pack_id).await?;
        if pack.generation != generation
            || !matches!(pack.state, PackState::Sealed | PackState::Qualified)
        {
            return Err(crate::coded(
                "STALE_VIEW",
                "checks need a sealed pack at the requested generation",
            ));
        }
        let candidate: Digest = pack
            .sealed
            .as_ref()
            .ok_or_else(|| invalid("pack has no sealed candidate"))?
            .candidate;
        let d = self.file_domain().await?;
        let (scratch, files, drift) = self
            .materialize_candidate(&d, &pack.candidate_effects)
            .await?;
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
        let mut plans: Vec<(PackageRecord, String, PlannedCheck, Executable)> = Vec::new();
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
                let exe = executable_identity(&c.argv[0])?;
                plans.push((r.clone(), decl.verifier.clone(), c, exe));
            }
        }
        if let Some(missing) = languages
            .iter()
            .find(|l| !plans.iter().any(|(_, _, c, _)| &c.language == *l))
        {
            return Err(invalid(format!(
                "unknown language {missing}: no enabled checks package plans it"
            )));
        }
        if plans.is_empty() {
            return Err(invalid("no supported language detected; pass --language"));
        }
        // A package's own plan runs only when approved (configured overrides replace it).
        let mut unapproved = Vec::new();
        for (r, _, c, exe) in &plans {
            if overrides(r, config).is_some() || !(only.is_empty() || only.contains(&c.name)) {
                continue;
            }
            let digest = approval_digest(r, c, exe)?;
            if self.check_plan_approved(r, &digest)? {
                continue;
            }
            // Only a plan the user saw can be approved: the digest names its exact content.
            if approve.contains(&digest) {
                self.approve_check_plan(r, &digest)?;
                continue;
            }
            let files = if c.takes_files {
                format!(
                    ", followed by every candidate file with extension {:?}",
                    c.sources
                )
            } else {
                String::new()
            };
            let executable = match exe {
                Some((path, sha)) => format!("{} (sha256:{sha})", path.display()),
                None => "nothing (not installed; approving records that)".into(),
            };
            unapproved.push(format!(
                "{digest}  {}@{}: runs {:?} as {executable}{files}, passing environment variables {:?}; plan {}",
                r.id,
                r.version,
                c.argv,
                c.env,
                String::from_utf8_lossy(
                    &calve_integration_contract::jcs::to_vec(&serde_json::to_value(c)?)
                        .map_err(|_| invalid("check plan is not canonical JSON"))?
                )
            ));
        }
        if !unapproved.is_empty() {
            return Err(invalid(format!(
                "CHECK_PLAN_UNAPPROVED: these check plans run with your user permissions and are not confined. Review each, then approve it with --approve-plan <digest> (or configure [integrations.\"<id>\".checks]):\n  {}",
                unapproved.join("\n  ")
            )));
        }
        let mut report = Vec::new();
        type Planned = (PackageRecord, String, Vec<(PlannedCheck, Executable)>);
        let mut by_language: BTreeMap<(String, String), Planned> = BTreeMap::new();
        for (r, verifier, c, exe) in plans {
            by_language
                .entry((r.id.clone(), c.language.clone()))
                .or_insert_with(|| (r, verifier, vec![]))
                .2
                .push((c, exe));
        }
        for ((_, language), (r, verifier, planned)) in by_language {
            let mut evidence = Vec::new();
            let mut results = Vec::new();
            let configured = overrides(&r, config);
            // The approved executable of a package plan; `None` for the user's own overrides.
            let mut checks: Vec<(String, Vec<String>, PlannedCheck, Option<Executable>)> =
                match &configured {
                    Some(list) => list
                        .iter()
                        .map(|(n, a)| (n.clone(), a.clone(), planned[0].0.clone(), None))
                        .collect(),
                    None => planned
                        .iter()
                        .map(|(c, exe)| {
                            (c.name.clone(), c.argv.clone(), c.clone(), Some(exe.clone()))
                        })
                        .collect(),
                };
            checks.retain(|(name, _, _, _)| only.is_empty() || only.contains(name));
            for (name, mut argv, plan, approved) in checks {
                let mut env: BTreeMap<String, String> = BASE_ENV
                    .iter()
                    .map(|s| s.to_string())
                    .chain(plan.env.iter().cloned())
                    // A variable a provider uses as a secret stays out, whatever its name.
                    .filter(|n| {
                        let secret = format!("env:{n}");
                        !config
                            .providers
                            .values()
                            .any(|p| p.secrets.values().any(|s| *s == secret))
                    })
                    .filter_map(|n| std::env::var(&n).ok().map(|v| (n, v)))
                    .collect();
                // Names the Project whose control state the supervisor hides from this check.
                env.insert("CALVE_PROJECT_ROOT".into(), self.root.display().to_string());
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
                let program = match approved {
                    // Re-resolved and re-hashed right before the spawn: only the approved
                    // executable runs. ponytail: a replacement between this hash and exec is
                    // not caught (no exec-by-handle); M5 confinement bounds what it could do.
                    Some(exe) => match (exe, executable_identity(&argv[0])?) {
                        (None, None) => None,
                        (Some(a), Some(now)) if a == now => Some(now.0),
                        _ => {
                            return Err(invalid(format!(
                                "CHECK_PLAN_CHANGED: {:?} no longer resolves to the approved executable; run the checks again to review the new plan",
                                argv[0]
                            )));
                        }
                    },
                    None => resolve_executable(&argv[0]).ok(),
                };
                match program {
                    None => {
                        result["tool_available"] = json!(false);
                        result["exit_code"] = Value::Null;
                    }
                    Some(program) => {
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
    fn approval_covers_the_plan_the_package_and_the_executable() {
        let a = plan(&["cargo", "test"], &[]);
        let pkg = json!({"id": "org.x.rust", "version": "1.0.0", "digests": {"native": "aa"}});
        let exe: Executable = Some((PathBuf::from("/usr/bin/cargo"), "11".repeat(32)));
        let base = covered_digest(&pkg, &a, &exe).unwrap();
        assert_eq!(
            base,
            covered_digest(&pkg, &a.clone(), &exe.clone()).unwrap()
        );
        let mut b = a.clone();
        b.env.push("CARGO_HOME".into());
        let mut b2 = a.clone();
        b2.takes_files = true;
        let mut b3 = a.clone();
        b3.sources.push("rs".into());
        let mut other_pkg = pkg.clone();
        other_pkg["digests"]["native"] = json!("bb");
        let changed = [
            covered_digest(&pkg, &b, &exe),
            covered_digest(&pkg, &b2, &exe),
            covered_digest(&pkg, &b3, &exe),
            covered_digest(&other_pkg, &a, &exe),
            // Same content, another PATH resolution.
            covered_digest(
                &pkg,
                &a,
                &Some((PathBuf::from("/tmp/cargo"), "11".repeat(32))),
            ),
            // Same path, replaced executable.
            covered_digest(
                &pkg,
                &a,
                &Some((PathBuf::from("/usr/bin/cargo"), "22".repeat(32))),
            ),
            covered_digest(&pkg, &a, &None),
        ];
        for (i, d) in changed.into_iter().enumerate() {
            assert_ne!(d.unwrap(), base, "change {i} kept the approval");
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
