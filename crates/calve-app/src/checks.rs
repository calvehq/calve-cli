//! Language checks on a sealed candidate. Results become candidate-bound evidence that the
//! language's OpenAEVC verifier judges; Calve itself never decides pass/fail.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use openaevc_protocol::{Command, Digest, PackState, Query};
use openaevc_sdk::OpenAevcClient;
use serde_json::{Value, json};

use crate::config::EffectiveConfig;
use crate::domain::{self, CHECK_EVIDENCE, Language};
use crate::providers::{resolve_executable, run_command};
use crate::{Error, Project, Result, event};

const DEFAULT_TIMEOUT_MS: u64 = 30 * 60 * 1000;
const TAIL_BYTES: usize = 8 * 1024;

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

/// Configured command overrides: `[integrations."org.calve.<lang>".checks] name = [argv...]`.
fn checks_for(
    language: &Language,
    config: &EffectiveConfig,
    root: &Path,
) -> Vec<(String, Vec<String>)> {
    let overrides = config
        .integrations
        .get(&language.extension_id())
        .and_then(|value| value.get("checks"))
        .and_then(|value| value.as_table());
    if let Some(table) = overrides {
        return table
            .iter()
            .filter_map(|(name, argv)| {
                let argv: Vec<String> = argv
                    .as_array()?
                    .iter()
                    .filter_map(|arg| arg.as_str().map(str::to_owned))
                    .collect();
                (!argv.is_empty()).then(|| (name.clone(), argv))
            })
            .collect();
    }
    // Gradle projects without a Maven pom use Gradle; CMake-only trees configure then build.
    if language.key == "java" && !root.join("pom.xml").exists() {
        return vec![(
            "test".into(),
            vec!["gradle".into(), "test".into(), "-q".into()],
        )];
    }
    if language.key == "c-cpp"
        && !root.join("Makefile").exists()
        && root.join("CMakeLists.txt").exists()
    {
        return vec![(
            "build".into(),
            vec![
                "sh".into(),
                "-c".into(),
                "cmake -S . -B build && cmake --build build".into(),
            ],
        )];
    }
    language
        .checks
        .iter()
        .map(|check| {
            (
                check.name.to_owned(),
                check.argv.iter().map(|arg| (*arg).to_owned()).collect(),
            )
        })
        .collect()
}

impl Project {
    /// Copies the working tree (respecting ignore rules), then overlays the candidate's
    /// snapshots so tools see the candidate content for every captured path.
    fn materialize_candidate(
        &self,
        effects: &[openaevc_protocol::AppliedEffect],
    ) -> Result<(Scratch, Vec<String>, Vec<String>)> {
        let scratch =
            Scratch(std::env::temp_dir().join(format!("calve-check-{}", uuid::Uuid::now_v7())));
        fs::create_dir(&scratch.0)?;
        let mut files = Vec::new();
        for item in self.list_resources()?.as_array().into_iter().flatten() {
            if item["kind"] != "file" {
                continue;
            }
            let path = item["path"].as_str().unwrap_or_default();
            let target = scratch.0.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(self.root.join(path), &target)?;
            files.push(path.to_owned());
        }
        let mut candidate = crate::resources::FileState::default();
        for effect in effects
            .iter()
            .filter(|e| crate::resources::is_file_effect(&e.kind))
        {
            crate::validate_locator(&effect.target.locator)?;
            candidate.apply(effect)?;
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
        let (scratch, files, drift) = self.materialize_candidate(&pack.candidate_effects)?;
        let selected: Vec<&Language> = if languages.is_empty() {
            domain::detect(&scratch.0, &files)
        } else {
            languages
                .iter()
                .map(|key| {
                    domain::language(key).ok_or_else(|| invalid(format!("unknown language {key}")))
                })
                .collect::<Result<_>>()?
        };
        if selected.is_empty() {
            return Err(invalid("no supported language detected; pass --language"));
        }
        let active = self.list_extensions().await?;
        let mut report = Vec::new();
        for language in selected {
            let mut evidence = Vec::new();
            let mut results = Vec::new();
            let env: BTreeMap<String, String> = domain::allowed_env(language)
                .into_iter()
                .filter_map(|name| {
                    std::env::var(name)
                        .ok()
                        .map(|value| (name.to_owned(), value))
                })
                .collect();
            for (name, mut argv) in checks_for(language, config, &scratch.0) {
                if !only.is_empty() && !only.contains(&name) {
                    continue;
                }
                if language
                    .checks
                    .iter()
                    .any(|check| check.name == name && check.takes_files())
                {
                    argv.extend(
                        files
                            .iter()
                            .filter(|file| {
                                Path::new(file)
                                    .extension()
                                    .and_then(|ext| ext.to_str())
                                    .is_some_and(|ext| language.sources.contains(&ext))
                            })
                            .cloned(),
                    );
                }
                let mut result = json!({"language":language.key,"check":name,"argv":argv,
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
                        let env = env.clone();
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
            let enabled = active
                .as_array()
                .into_iter()
                .flatten()
                .any(|entry| entry["id"] == language.extension_id() && entry["active"] == true);
            let verification = if enabled && !evidence.is_empty() {
                let receipt = self
                    .client
                    .command(Command::RunVerification {
                        pack: pack.id,
                        generation,
                        verifier: language.verifier(),
                        config: None,
                        evidence,
                    })
                    .await?;
                let digest = receipt
                    .result
                    .digest
                    .ok_or_else(|| invalid("verification returned no digest"))?;
                let object: Value = self.client.query(Query::GetVerification { digest }).await?;
                json!({"digest":digest,"status":object["envelope"]["body"]["status"],
                    "findings":object["envelope"]["body"]["findings"]})
            } else {
                json!({"status":null,"note":format!("enable {} to verify these results", language.extension_id())})
            };
            event(&self.db, "checks.ran", pack_id, language.key)?;
            report.push(
                json!({"language":language.key,"checks":results,"verification":verification}),
            );
        }
        Ok(
            json!({"pack":pack.id,"generation":generation,"candidate":candidate,"drift":drift,"languages":report}),
        )
    }
}
