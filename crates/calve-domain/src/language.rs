//! First-party language domains. Each language ships as its own OpenAEVC extension binary
//! (`calve_ext_<lang>`) whose verifier judges candidate-bound check evidence; Calve's check
//! runner produces that evidence by running the language's commands on the sealed candidate.

use std::path::Path;

use serde_json::{Value, json};

pub const CHECK_EVIDENCE: &str = "org.calve.check-result/v1";

pub struct Check {
    pub name: &'static str,
    pub argv: &'static [&'static str],
}

impl Check {
    /// Tools such as shellcheck take the files to inspect as arguments.
    pub fn takes_files(&self) -> bool {
        self.argv == ["shellcheck"]
    }
}

pub struct Language {
    pub key: &'static str,
    pub display: &'static str,
    /// Any of these at the Project root marks the language as present.
    pub markers: &'static [&'static str],
    /// File extensions classified as this language's sources.
    pub sources: &'static [&'static str],
    pub checks: &'static [Check],
    /// Generated or dependency directories excluded from resource scans.
    pub ignore: &'static [&'static str],
    /// Environment the tools commonly need; everything else is cleared.
    pub env: &'static [&'static str],
}

impl Language {
    pub fn extension_id(&self) -> String {
        format!("org.calve.{}", self.key)
    }

    pub fn verifier(&self) -> String {
        format!("org.calve.{}.checks", self.key)
    }

    pub fn detected(&self, root: &Path) -> bool {
        self.markers.iter().any(|marker| root.join(marker).exists())
    }
}

const BASE_ENV: &[&str] = &["PATH", "HOME", "LANG", "TMPDIR"];

pub const LANGUAGES: &[Language] = &[
    Language {
        key: "rust",
        display: "Rust",
        markers: &["Cargo.toml"],
        sources: &["rs"],
        checks: &[
            Check {
                name: "check",
                argv: &["cargo", "check", "--all-targets"],
            },
            Check {
                name: "test",
                argv: &["cargo", "test"],
            },
            Check {
                name: "clippy",
                argv: &["cargo", "clippy", "--all-targets", "--", "-D", "warnings"],
            },
            Check {
                name: "fmt",
                argv: &["cargo", "fmt", "--check"],
            },
        ],
        ignore: &["target/"],
        env: &["CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"],
    },
    Language {
        key: "go",
        display: "Go",
        markers: &["go.mod", "go.work"],
        sources: &["go"],
        checks: &[
            Check {
                name: "test",
                argv: &["go", "test", "./..."],
            },
            Check {
                name: "vet",
                argv: &["go", "vet", "./..."],
            },
            Check {
                name: "fmt",
                argv: &["gofmt", "-l", "."],
            },
        ],
        ignore: &["vendor/"],
        env: &["GOPATH", "GOCACHE", "GOMODCACHE", "GOFLAGS", "GOPROXY"],
    },
    Language {
        key: "python",
        display: "Python",
        markers: &["pyproject.toml", "setup.py", "requirements.txt"],
        sources: &["py"],
        checks: &[Check {
            name: "test",
            argv: &["python3", "-m", "pytest", "-q"],
        }],
        ignore: &[
            ".venv/",
            "venv/",
            "__pycache__/",
            ".pytest_cache/",
            ".mypy_cache/",
        ],
        env: &["VIRTUAL_ENV", "PYTHONPATH"],
    },
    Language {
        key: "javascript-typescript",
        display: "JavaScript/TypeScript",
        markers: &["package.json"],
        sources: &["js", "mjs", "cjs", "jsx", "ts", "tsx"],
        checks: &[Check {
            name: "test",
            argv: &["npm", "test", "--silent"],
        }],
        ignore: &["node_modules/", "dist/", ".next/", "coverage/"],
        env: &["NODE_OPTIONS", "npm_config_cache"],
    },
    Language {
        key: "java",
        display: "Java",
        markers: &["pom.xml", "build.gradle", "build.gradle.kts"],
        sources: &["java", "kt"],
        checks: &[Check {
            name: "test",
            argv: &["mvn", "-q", "test"],
        }],
        ignore: &["target/", "build/", ".gradle/"],
        env: &["JAVA_HOME", "MAVEN_OPTS", "GRADLE_USER_HOME"],
    },
    Language {
        key: "c-cpp",
        display: "C/C++",
        markers: &["CMakeLists.txt", "Makefile", "meson.build"],
        sources: &["c", "h", "cc", "cpp", "hpp", "cxx"],
        checks: &[Check {
            name: "build",
            argv: &["make"],
        }],
        ignore: &["build/", "cmake-build-debug/", "cmake-build-release/"],
        env: &["CC", "CXX", "CFLAGS", "CXXFLAGS"],
    },
    Language {
        key: "shell",
        display: "Shell",
        markers: &[],
        sources: &["sh", "bash"],
        checks: &[Check {
            name: "shellcheck",
            argv: &["shellcheck"],
        }],
        ignore: &[],
        env: &[],
    },
    Language {
        key: "hcl",
        display: "HCL",
        markers: &[],
        sources: &["hcl", "tf", "tfvars"],
        checks: &[Check {
            name: "fmt",
            argv: &["terraform", "fmt", "-check", "-recursive"],
        }],
        ignore: &[".terraform/"],
        env: &["TF_CLI_CONFIG_FILE"],
    },
];

pub fn language(key: &str) -> Option<&'static Language> {
    LANGUAGES.iter().find(|language| language.key == key)
}

pub fn allowed_env(language: &Language) -> Vec<&'static str> {
    BASE_ENV.iter().chain(language.env).copied().collect()
}

/// Languages present at the root, either by marker file or by source files in `files`.
pub fn detect(root: &Path, files: &[String]) -> Vec<&'static Language> {
    LANGUAGES
        .iter()
        .filter(|language| {
            language.detected(root)
                || files.iter().any(|file| {
                    Path::new(file)
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| language.sources.contains(&ext))
                })
        })
        .collect()
}

/// The judgement shared by every language verifier: all checks passed, any check failed, or
/// the outcome is unknown because a tool was unavailable (never reported as a pass).
pub fn judge(language: &str, evidence: &[Value]) -> (&'static str, Vec<(String, String)>) {
    let mut findings = Vec::new();
    let mut failed = false;
    let mut unavailable = false;
    let mut seen = 0;
    for item in evidence.iter().filter(|item| item["language"] == language) {
        seen += 1;
        let check = item["check"].as_str().unwrap_or("check");
        if item["tool_available"] == false {
            unavailable = true;
            findings.push((
                format!("org.calve.{language}.tool_unavailable"),
                format!(
                    "{check}: {} is not installed",
                    item["argv"][0].as_str().unwrap_or("tool")
                ),
            ));
        } else if item["exit_code"] != 0 {
            failed = true;
            findings.push((
                format!("org.calve.{language}.check_failed"),
                format!("{check} exited with {}", item["exit_code"]),
            ));
        }
    }
    let status = if failed {
        "fail"
    } else if unavailable || seen == 0 {
        "inconclusive"
    } else {
        "pass"
    };
    (status, findings)
}

/// Declarative Calve integration metadata (§33): labels only, never behaviour.
pub fn integration_metadata(language: &Language) -> Value {
    json!({"display_name":language.display,"categories":["language"],
        "depends_on":["org.calve.software"],
        "recommended_verification":[language.verifier()],
        "checks":language.checks.iter().map(|check| json!({"name":check.name,"argv":check.argv})).collect::<Vec<_>>(),
        "ignore_defaults":language.ignore,"source_extensions":language.sources})
}

/// Serves one language as an OpenAEVC extension; each `calve_ext_<lang>` binary calls this.
pub fn serve_language(key: &str) -> std::process::ExitCode {
    use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
    use openaevc::extension::wire::{Operation, VerifyOutput, WireError};
    use openaevc::protocol::{
        Entrypoint, ExtensionManifest, Finding, SUPPORTED_CONTRACT, SUPPORTED_PROTOCOL,
        VerificationStatus,
    };

    struct Server(&'static Language);

    impl Extension for Server {
        fn manifest(&self) -> ExtensionManifest {
            ExtensionManifest {
                id: self.0.extension_id(),
                version: env!("CARGO_PKG_VERSION").into(),
                protocol: SUPPORTED_PROTOCOL,
                contract: SUPPORTED_CONTRACT,
                publisher: None,
                artifact_digest: self_artifact_digest(),
                resource_kinds: vec![],
                effect_kinds: vec![],
                verifier_kinds: vec![self.0.verifier()],
                evaluator_kinds: vec![],
                composition_validators: vec![],
                host_capabilities: vec![],
                schemas: Default::default(),
                execution_modes: vec!["subprocess".into()],
                entrypoint: Entrypoint {
                    command: format!("calve_ext_{}", self.0.key.replace('-', "_")),
                    args: vec![],
                },
            }
        }

        fn handle(
            &mut self,
            operation: Operation,
            _: &mut HostContext<'_>,
        ) -> Result<Value, WireError> {
            match operation {
                Operation::Verify {
                    kind,
                    candidate,
                    evidence,
                    ..
                } if kind == self.0.verifier() => {
                    let mut results = Vec::new();
                    for input in evidence.iter().filter(|input| input.kind == CHECK_EVIDENCE) {
                        let value: Value = serde_json::from_slice(&input.data)
                            .map_err(|e| WireError::new("invalid_evidence", e.to_string()))?;
                        // Evidence names the candidate it ran against; a mismatch is not accepted.
                        if value["candidate"] != json!(candidate) {
                            return Err(WireError::new(
                                "invalid_evidence",
                                "check evidence is bound to another candidate",
                            ));
                        }
                        results.push(value);
                    }
                    let (status, findings) = judge(self.0.key, &results);
                    serde_json::to_value(VerifyOutput {
                        status: match status {
                            "pass" => VerificationStatus::Pass,
                            "fail" => VerificationStatus::Fail,
                            _ => VerificationStatus::Inconclusive,
                        },
                        findings: findings
                            .into_iter()
                            .map(|(code, message)| Finding {
                                code,
                                message,
                                resource: None,
                            })
                            .collect(),
                        facts: Default::default(),
                    })
                    .map_err(|e| WireError::new("encode", e.to_string()))
                }
                other => Err(WireError::new(
                    "unsupported",
                    format!("{} is not supported", other.name()),
                )),
            }
        }
    }

    match language(key) {
        Some(language) => serve(Server(language)),
        None => std::process::ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tool_is_never_a_pass() {
        let ok = json!({"language":"rust","check":"test","tool_available":true,"exit_code":0,"argv":["cargo"]});
        let missing = json!({"language":"rust","check":"clippy","tool_available":false,"exit_code":null,"argv":["cargo"]});
        let failed = json!({"language":"rust","check":"fmt","tool_available":true,"exit_code":1,"argv":["cargo"]});
        assert_eq!(judge("rust", std::slice::from_ref(&ok)).0, "pass");
        assert_eq!(
            judge("rust", &[ok.clone(), missing.clone()]).0,
            "inconclusive"
        );
        assert_eq!(judge("rust", &[ok, missing, failed]).0, "fail");
        assert_eq!(judge("rust", &[]).0, "inconclusive");
    }
}
