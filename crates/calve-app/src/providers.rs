//! Provider profiles, harness definitions and the hardened process runner.
//!
//! OpenAEVC owns execution identity, admission and provenance; this module only launches the
//! worker, streams its output into observations and turns its file changes into effects.
//!
//! Stdio agent contract (`kind = "stdio-agent"`, version 1), one JSON object per line:
//! * Calve -> agent, first line: `{"type":"context","version":1,...}` (see [`WorkerContext`]).
//! * agent -> Calve: `{"type":"log","text":"..."}`,
//!   `{"type":"propose","path":"rel/path","content_base64":"..."}`,
//!   `{"type":"done","status":"succeeded"|"failed","reason":"..."}`.
//!   `content_base64` is RFC 4648 base64; standard (padded) and URL-safe forms are accepted.
//!   Anything else is recorded as a protocol error and fails the execution.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as Process, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use openaevc::crypto::sha256;
use openaevc::protocol::{
    Command, EffectProposal, ExecutionId, ExecutionRequest, PackState, ProviderDescriptor,
    ResourceRef, ResourceSelector, WorkUnitId, WorkerInfo, b64,
};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde::Serialize;
use serde_json::{Value, json};

use crate::config::{
    ConfigPaths, EffectiveConfig, HarnessDefinition, HarnessMode, ProviderKind, ProviderProfile,
    Scope,
};
use crate::{Error, Project, Result, event};

const DEFAULT_TIMEOUT_MS: u64 = 30 * 60 * 1000;
const DEFAULT_MAX_OUTPUT: u64 = 1024 * 1024;
const LOG_CHUNK: usize = 16 * 1024;
/// The built-in capture harness (`pack capture`); its protocol ids derive from the enabled
/// file extension (`<extension>.capture`, `<extension>.local`).
const CAPTURE_HARNESS: &str = "capture";

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// Built-in harness that records file snapshots chosen by the user (`pack capture`).
fn builtin_harnesses() -> Value {
    json!([{"id":CAPTURE_HARNESS,"builtin":true,"provider":"<file extension>.local",
        "mode":"change","description":"Capture the files named on the command line through the file extension"}])
}

/// Resolves an executable name against PATH, or checks an explicit path.
pub fn resolve_executable(name: &str) -> Result<PathBuf> {
    let candidate = Path::new(name);
    let found = if candidate.components().count() > 1 || candidate.is_absolute() {
        candidate.is_file().then(|| candidate.to_path_buf())
    } else {
        // Only absolute PATH entries: an empty or relative entry would resolve against the
        // working directory, which may hold candidate content.
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .filter(|dir| dir.is_absolute())
                .map(|dir| dir.join(name))
                .find(|path| path.is_file())
        })
    };
    let path = found.ok_or_else(|| invalid(format!("executable {name:?} not found")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&path)?.permissions().mode() & 0o111 == 0 {
            return Err(invalid(format!("{} is not executable", path.display())));
        }
    }
    Ok(std::fs::canonicalize(path)?)
}

/// Resolves a secret reference at launch time. The value never leaves the child environment.
fn resolve_secret(reference: &str) -> Result<String> {
    if let Some(name) = reference.strip_prefix("env:") {
        return std::env::var(name)
            .map_err(|_| invalid(format!("secret reference {reference} is not set")));
    }
    if let Some(name) = reference.strip_prefix("keyring:") {
        return keyring_lookup(name);
    }
    Err(invalid(format!("unsupported secret reference {reference}")))
}

/// Reads `name` (service `calve`) from the OS credential store through the platform tool,
/// or through `CALVE_KEYRING_COMMAND <name>` when set.
fn keyring_lookup(name: &str) -> Result<String> {
    let (program, args, hint): (String, Vec<String>, String) = match std::env::var(
        "CALVE_KEYRING_COMMAND",
    ) {
        Ok(program) => (
            program,
            vec![name.to_owned()],
            "check CALVE_KEYRING_COMMAND".into(),
        ),
        Err(_) if cfg!(target_os = "macos") => (
            "security".into(),
            ["find-generic-password", "-s", "calve", "-a", name, "-w"]
                .map(str::to_owned)
                .to_vec(),
            format!("store it with: security add-generic-password -s calve -a {name} -w"),
        ),
        Err(_) if cfg!(target_os = "linux") => (
            "secret-tool".into(),
            ["lookup", "service", "calve", "account", name]
                .map(str::to_owned)
                .to_vec(),
            format!(
                "store it with: secret-tool store --label='calve {name}' service calve account {name}"
            ),
        ),
        Err(_) => {
            return Err(invalid(
                "this platform has no supported credential store; use an env: reference",
            ));
        }
    };
    let output = Process::new(resolve_executable(&program)?)
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| invalid(format!("credential store unavailable: {error}")))?;
    let value = String::from_utf8(output.stdout).unwrap_or_default();
    let value = value.trim_end_matches(['\n', '\r']).to_owned();
    if !output.status.success() || value.is_empty() {
        return Err(invalid(format!("keyring:{name} was not found; {hint}")));
    }
    Ok(value)
}

#[derive(Debug, Serialize)]
pub struct WorkerContext {
    #[serde(rename = "type")]
    kind: &'static str,
    version: u32,
    project_id: String,
    namespace_id: String,
    pack: String,
    generation: u64,
    execution: String,
    work_unit: String,
    harness: String,
    mode: HarnessMode,
    paths: Vec<String>,
    task: Option<String>,
    intent: Option<String>,
    active_baseline: Option<String>,
}

struct Launch {
    argv: Vec<String>,
    env: BTreeMap<String, String>,
    timeout: Duration,
    max_output: u64,
}

fn launch_plan(
    provider_id: &str,
    profile: &ProviderProfile,
    harness: &HarnessDefinition,
) -> Result<Launch> {
    let mut argv = Vec::new();
    if let Some(executable) = &profile.executable {
        argv.push(resolve_executable(executable)?.display().to_string());
        argv.extend(profile.args.iter().cloned());
        argv.extend(harness.command.iter().cloned());
    } else {
        let (program, rest) = harness.command.split_first().ok_or_else(|| {
            invalid(format!(
                "provider {provider_id} has no executable and the harness no command"
            ))
        })?;
        argv.push(resolve_executable(program)?.display().to_string());
        argv.extend(rest.iter().cloned());
    }
    let mut env = BTreeMap::new();
    for name in &profile.env {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.clone(), value);
        }
    }
    for (name, reference) in &profile.secrets {
        env.insert(name.clone(), resolve_secret(reference)?);
    }
    let timeout = harness
        .timeout_ms
        .or(profile.timeout_ms)
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    Ok(Launch {
        argv,
        env,
        timeout: Duration::from_millis(timeout),
        max_output: profile.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT),
    })
}

enum Line {
    Out(String),
    Err(String),
}

fn spawn(launch: &Launch, cwd: &Path, context: &BTreeMap<String, String>) -> Result<Child> {
    let mut command = Process::new(&launch.argv[0]);
    command
        .args(&launch.argv[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(&launch.env)
        .envs(context)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    Ok(command.spawn()?)
}

/// Kills the worker's whole process group so grandchildren do not outlive the execution.
fn terminate(child: &mut Child) {
    #[cfg(unix)]
    {
        // ponytail: kill(1) instead of libc because unsafe code is forbidden.
        let _ = Process::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn pump(stream: impl Read + Send + 'static, tx: mpsc::Sender<Line>, err: bool) {
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            if tx
                .send(if err {
                    Line::Err(line)
                } else {
                    Line::Out(line)
                })
                .is_err()
            {
                break;
            }
        }
    });
}

struct Outcome {
    status: &'static str,
    reason: Option<String>,
    exit_code: Option<i32>,
    logs: Vec<(String, String)>,
    proposals: Vec<(String, Vec<u8>)>,
    truncated: bool,
}

/// Runs the worker to completion, enforcing timeout, output limit and cancellation.
fn run_worker(
    launch: &Launch,
    kind: ProviderKind,
    cwd: &Path,
    env: &BTreeMap<String, String>,
    context: &WorkerContext,
    cancelled: &dyn Fn() -> bool,
) -> Result<Outcome> {
    let mut child = spawn(launch, cwd, env)?;
    let mut stdin = child.stdin.take();
    if kind == ProviderKind::StdioAgent {
        if let Some(input) = stdin.as_mut() {
            writeln!(input, "{}", serde_json::to_string(context)?)?;
            input.flush()?;
        }
    } else {
        drop(stdin.take());
    }
    let (tx, rx) = mpsc::channel();
    pump(
        child.stdout.take().expect("piped stdout"),
        tx.clone(),
        false,
    );
    pump(child.stderr.take().expect("piped stderr"), tx, true);
    let deadline = Instant::now() + launch.timeout;
    let mut outcome = Outcome {
        status: "failed",
        reason: None,
        exit_code: None,
        logs: Vec::new(),
        proposals: Vec::new(),
        truncated: false,
    };
    let mut used = 0u64;
    let mut agent_done: Option<(&'static str, Option<String>)> = None;
    let mut record = |stream: &str, text: String, outcome: &mut Outcome| {
        used += text.len() as u64 + 1;
        if used > launch.max_output {
            outcome.truncated = true;
        } else {
            outcome.logs.push((stream.to_owned(), text));
        }
    };
    let mut last_poll = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Line::Err(text)) => record("stderr", text, &mut outcome),
            Ok(Line::Out(text)) if kind == ProviderKind::StdioAgent => {
                match serde_json::from_str::<Value>(&text) {
                    Ok(frame) => match frame["type"].as_str() {
                        Some("log") => record(
                            "agent",
                            frame["text"].as_str().unwrap_or_default().to_owned(),
                            &mut outcome,
                        ),
                        Some("propose") => {
                            let path = frame["path"].as_str().unwrap_or_default().to_owned();
                            let content = frame["content_base64"].as_str().and_then(decode_base64);
                            match content {
                                Some(content) => outcome.proposals.push((path, content)),
                                None => {
                                    agent_done = Some((
                                        "failed",
                                        Some("agent sent an invalid proposal".into()),
                                    ));
                                }
                            }
                        }
                        Some("done") => {
                            agent_done = Some(match frame["status"].as_str() {
                                Some("succeeded") => ("succeeded", None),
                                _ => (
                                    "failed",
                                    Some(
                                        frame["reason"]
                                            .as_str()
                                            .unwrap_or("agent reported failure")
                                            .to_owned(),
                                    ),
                                ),
                            });
                            drop(stdin.take());
                        }
                        _ => {
                            agent_done = Some((
                                "failed",
                                Some(format!(
                                    "unknown agent frame: {}",
                                    crate::truncate(&text, 200)
                                )),
                            ));
                        }
                    },
                    Err(_) => {
                        agent_done = Some(("failed", Some("agent wrote a non-JSON line".into())));
                    }
                }
                if agent_done
                    .as_ref()
                    .is_some_and(|(status, _)| *status == "failed")
                {
                    terminate(&mut child);
                    break;
                }
            }
            Ok(Line::Out(text)) => record("stdout", text, &mut outcome),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Both pipes closed; wait for the exit status below.
                let status = child.wait()?;
                outcome.exit_code = status.code();
                break;
            }
        }
        if Instant::now() > deadline {
            terminate(&mut child);
            outcome.reason = Some(format!("timed out after {} ms", launch.timeout.as_millis()));
            return Ok(outcome);
        }
        if last_poll.elapsed() > Duration::from_millis(500) {
            last_poll = Instant::now();
            if cancelled() {
                terminate(&mut child);
                outcome.status = "cancelled";
                outcome.reason = Some("execution was cancelled".into());
                return Ok(outcome);
            }
        }
    }
    if outcome.exit_code.is_none()
        && let Ok(Some(status)) = child.try_wait()
    {
        outcome.exit_code = status.code();
    }
    match kind {
        ProviderKind::LocalProcess => {
            if outcome.exit_code == Some(0) {
                outcome.status = "succeeded";
            } else {
                outcome.reason = Some(match outcome.exit_code {
                    Some(code) => format!("worker exited with status {code}"),
                    None => "worker was terminated by a signal".into(),
                });
            }
        }
        ProviderKind::StdioAgent => match agent_done {
            Some((status, reason)) => {
                outcome.status = status;
                outcome.reason = reason;
            }
            None => outcome.reason = Some("agent exited without a done frame".into()),
        },
    }
    Ok(outcome)
}

/// Result of one bounded command run.
pub struct CommandRun {
    pub exit_code: Option<i32>,
    pub output_tail: String,
    pub timed_out: bool,
    pub duration_ms: u128,
}

/// Runs argv (argv[0] already resolved) with a cleared environment, keeping the output tail.
pub fn run_command(
    argv: &[String],
    cwd: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    tail_bytes: usize,
) -> Result<CommandRun> {
    let launch = Launch {
        argv: argv.to_vec(),
        env: env.clone(),
        timeout,
        max_output: u64::MAX,
    };
    let started = Instant::now();
    let mut child = spawn(&launch, cwd, &BTreeMap::new())?;
    drop(child.stdin.take());
    let (tx, rx) = mpsc::channel();
    pump(
        child.stdout.take().expect("piped stdout"),
        tx.clone(),
        false,
    );
    pump(child.stderr.take().expect("piped stderr"), tx, true);
    let mut tail = std::collections::VecDeque::new();
    let mut size = 0usize;
    let deadline = started + timeout;
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Line::Out(line) | Line::Err(line)) => {
                size += line.len() + 1;
                tail.push_back(line);
                while size > tail_bytes && tail.len() > 1 {
                    size -= tail.pop_front().map_or(0, |line| line.len() + 1);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if Instant::now() > deadline {
            terminate(&mut child);
            return Ok(CommandRun {
                exit_code: None,
                output_tail: Vec::from(tail).join("\n"),
                timed_out: true,
                duration_ms: started.elapsed().as_millis(),
            });
        }
    }
    let status = child.wait()?;
    Ok(CommandRun {
        exit_code: status.code(),
        output_tail: Vec::from(tail).join("\n"),
        timed_out: false,
        duration_ms: started.elapsed().as_millis(),
    })
}

/// Agents usually emit standard padded base64; OpenAEVC's own form is URL-safe unpadded.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    STANDARD
        .decode(text)
        .or_else(|_| URL_SAFE_NO_PAD.decode(text))
        .ok()
}

fn in_scope(paths: &[String], locator: &str) -> bool {
    paths.is_empty()
        || paths.iter().any(|prefix| {
            locator == prefix
                || locator
                    .strip_prefix(prefix.trim_end_matches('/'))
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

impl Project {
    fn provider_allowed(&self, id: &str, profile: &ProviderProfile) -> Result<()> {
        if !profile.enabled {
            return Err(invalid(format!("provider {id} is disabled")));
        }
        if !profile.projects.is_empty() && !profile.projects.contains(&self.identity.project_id) {
            return Err(invalid(format!(
                "provider {id} is not allowed in this Project"
            )));
        }
        Ok(())
    }

    async fn file_digests(&self, paths: &[String]) -> Result<BTreeMap<String, String>> {
        let mut map = BTreeMap::new();
        for item in self
            .list_resources()
            .await?
            .as_array()
            .into_iter()
            .flatten()
        {
            let path = item["path"].as_str().unwrap_or_default();
            if item["kind"] == "file" && in_scope(paths, path) {
                map.insert(path.to_owned(), item["digest"].to_string());
            }
        }
        Ok(map)
    }

    /// Starts an OpenAEVC execution for a configured harness and supervises the worker.
    pub async fn start_harness_execution(
        &self,
        config: &EffectiveConfig,
        pack_id: &str,
        expected_generation: u64,
        harness_id: &str,
        task: Option<&str>,
        retry: Option<(WorkUnitId, ExecutionId)>,
    ) -> Result<Value> {
        let harness = config
            .harnesses
            .get(harness_id)
            .ok_or_else(|| invalid(format!("harness {harness_id} is not configured")))?;
        let profile = config
            .providers
            .get(&harness.provider)
            .ok_or_else(|| invalid(format!("provider {} is not configured", harness.provider)))?;
        self.provider_allowed(&harness.provider, profile)?;
        let launch = launch_plan(&harness.provider, profile, harness)?;
        let pack = self.pack(pack_id).await?;
        if pack.state != PackState::Open || pack.generation != expected_generation {
            return Err(invalid(format!(
                "pack must be OPEN at generation {expected_generation}"
            )));
        }
        if harness.mode == HarnessMode::Change && !pack.candidate_effects.is_empty() {
            return Err(invalid(
                "pack already has effects from another execution; OpenAEVC only promotes effects from the current generation, so run change harnesses in a new pack",
            ));
        }
        if let Some(task) = task {
            self.task(task)?;
        }
        // Change harnesses write the file domain's resources with its declared kinds.
        let domain = if harness.mode == HarnessMode::Change {
            Some(self.file_domain().await?)
        } else {
            None
        };
        let provider = format!("org.calve.provider.{}", harness.provider);
        // OpenAEVC names are namespaced; configured IDs stay short for users.
        let protocol_harness = format!("org.calve.harness.{harness_id}");
        self.client
            .command(Command::RegisterProvider {
                provider: ProviderDescriptor {
                    id: provider.clone(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    worker_kinds: vec![protocol_harness.clone()],
                    harnesses: vec![protocol_harness.clone()],
                    required_actions: domain.iter().map(|d| d.decl.write_action.clone()).collect(),
                    cancellation: true,
                    resumable: false,
                    heartbeat: true,
                    limits: BTreeMap::new(),
                    provenance_fields: vec![],
                    principal: self.identity.created_by,
                },
            })
            .await?;
        let work_unit = match retry {
            Some((work_unit, _)) => work_unit,
            None => {
                self.client
                    .add_work_unit(pack.id, pack.generation, &protocol_harness)
                    .await?
            }
        };
        let generation = self.pack(pack_id).await?.generation;
        let (allowed_resources, allowed_effects) = if let Some(d) = &domain {
            let selectors = if harness.paths.is_empty() {
                vec![ResourceSelector {
                    kind: d.decl.resource_kind.clone(),
                    locator_prefix: None,
                }]
            } else {
                harness
                    .paths
                    .iter()
                    .map(|prefix| ResourceSelector {
                        kind: d.decl.resource_kind.clone(),
                        locator_prefix: Some(prefix.clone()),
                    })
                    .collect()
            };
            (selectors, vec![d.decl.put.clone()])
        } else {
            (vec![], vec![])
        };
        let (execution, lease) = self
            .client
            .start_execution(ExecutionRequest {
                pack: pack.id,
                expected_generation: generation,
                work_unit,
                provider: provider.clone(),
                harness: protocol_harness.clone(),
                worker: Some(WorkerInfo {
                    id: format!("local:{}", std::process::id()),
                    kind: protocol_harness.clone(),
                    attributes: BTreeMap::new(),
                }),
                allowed_resources,
                allowed_effects,
                context: vec![],
                timeout_ms: u64::try_from(launch.timeout.as_millis()).unwrap_or(u64::MAX),
                budget: BTreeMap::new(),
                max_attempts: 3,
                idempotency_key: uuid::Uuid::now_v7().to_string(),
                retry_of: retry.map(|(_, previous)| previous),
            })
            .await?;
        if let Some(task) = task {
            // Linking is product metadata; the execution record stays authoritative.
            self.db.execute(
                "INSERT OR IGNORE INTO task_links(task_id,kind,object_id,created_at) VALUES (?1,'execution',?2,?3)",
                rusqlite::params![task, execution.to_string(), crate::now()?],
            )?;
        }
        let intent: Option<String> = self
            .db
            .query_row(
                "SELECT intent_id FROM pack_metadata WHERE id=?1",
                [pack.id.to_string()],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        let context = WorkerContext {
            kind: "context",
            version: 1,
            project_id: self.identity.project_id.clone(),
            namespace_id: self.identity.namespace_id.to_string(),
            pack: pack.id.to_string(),
            generation,
            execution: execution.to_string(),
            work_unit: work_unit.to_string(),
            harness: harness_id.into(),
            mode: harness.mode,
            paths: harness.paths.clone(),
            task: task.map(str::to_owned),
            intent,
            active_baseline: self.active_baseline()?,
        };
        let mut env = BTreeMap::from([
            (
                "CALVE_PROJECT_ROOT".to_owned(),
                self.root.display().to_string(),
            ),
            ("CALVE_PACK".to_owned(), context.pack.clone()),
            ("CALVE_GENERATION".to_owned(), generation.to_string()),
            ("CALVE_EXECUTION".to_owned(), context.execution.clone()),
            ("CALVE_HARNESS".to_owned(), harness_id.to_owned()),
        ]);
        if let Some(task) = task {
            env.insert("CALVE_TASK".into(), task.into());
        }
        self.client.heartbeat(&lease).await?;
        // Whole-Project snapshot so writes outside the harness scope are detected, not ignored.
        let before = self.file_digests(&[]).await?;
        // The worker runs on a blocking thread; cancellation is checked from its own runtime.
        let client = self.client.clone();
        let handle = tokio::runtime::Handle::current();
        let execution_id = execution;
        // Polled every 500 ms: renews the lease at the runtime's heartbeat interval so a worker is never
        // mistaken for a lost one, and notices cancellation.
        let worker_lease = lease.clone();
        let every = u32::try_from(lease.heartbeat_interval_ms / 500)
            .unwrap_or(u32::MAX)
            .max(1);
        let polls = std::cell::Cell::new(0u32);
        let cancelled = move || {
            polls.set(polls.get() + 1);
            if polls.get().is_multiple_of(every) {
                let _ = handle.block_on(client.heartbeat(&worker_lease));
            }
            handle
                .block_on(client.query(openaevc::protocol::Query::GetExecution {
                    execution: execution_id,
                }))
                .is_ok_and(|value| value["state"] == "CANCELLED")
        };
        let root = self.root.clone();
        let kind = profile.kind;
        let outcome = tokio::task::spawn_blocking(move || {
            run_worker(&launch, kind, &root, &env, &context, &cancelled)
        })
        .await
        .map_err(|error| invalid(format!("worker supervisor failed: {error}")))??;
        for chunk in outcome.logs.chunks(64) {
            let text: Vec<Value> = chunk
                .iter()
                .map(|(stream, line)| json!({"stream":stream,"text":crate::truncate(line, LOG_CHUNK)}))
                .collect();
            self.client.heartbeat(&lease).await.ok();
            self.client
                .command(Command::AppendObservation {
                    execution,
                    lease: lease.id,
                    kind: "org.calve.harness.log".into(),
                    payload: Some(json!({"lines":text})),
                    blob: None,
                    related_resources: vec![],
                    related_effects: vec![],
                })
                .await?;
        }
        if outcome.status == "cancelled" {
            event(
                &self.db,
                "execution.cancelled",
                &execution.to_string(),
                harness_id,
            )?;
            return Ok(json!({"execution":execution,"state":"CANCELLED","reason":outcome.reason}));
        }
        let mut proposals = outcome.proposals;
        let after = self.file_digests(&[]).await?;
        let mut changed: Vec<&String> = after
            .iter()
            .filter(|(path, digest)| before.get(*path) != Some(*digest))
            .map(|(path, _)| path)
            .collect();
        changed.extend(before.keys().filter(|path| !after.contains_key(*path)));
        let stray: Vec<&&String> = changed
            .iter()
            .filter(|path| harness.mode == HarnessMode::Check || !in_scope(&harness.paths, path))
            .collect();
        if outcome.status == "succeeded"
            && harness.mode == HarnessMode::Change
            && profile.kind == ProviderKind::LocalProcess
        {
            for path in &changed {
                if in_scope(&harness.paths, path) && after.contains_key(*path) {
                    let content = crate::workspace_io::Workspace::open(&self.root)
                        .and_then(|w| w.read(path, crate::resources::MAX_CAPTURE_BYTES))
                        .map_err(|e| invalid(e.to_string()))?;
                    proposals.push(((*path).clone(), content));
                }
            }
        }
        let mut failure = (outcome.status != "succeeded").then(|| {
            outcome
                .reason
                .clone()
                .unwrap_or_else(|| "worker failed".into())
        });
        if outcome.truncated {
            failure.get_or_insert_with(|| "worker output exceeded the configured limit".into());
        }
        if harness.mode == HarnessMode::Check && !proposals.is_empty() {
            failure = Some("check harness proposed changes".into());
        }
        if let Some(path) = stray.first() {
            failure = Some(format!(
                "worker changed {path} outside the harness scope; the change was not recorded"
            ));
        }
        let mut effects = Vec::new();
        if failure.is_none() {
            for (path, content) in &proposals {
                if !in_scope(&harness.paths, path) {
                    failure = Some(format!("worker proposed {path} outside the harness scope"));
                    break;
                }
                // Same path rules as capture; agent proposals are validated before submission.
                let check = crate::validate_locator(path);
                if let Err(error) = check {
                    failure = Some(error.to_string());
                    break;
                }
                let digest = sha256(content);
                let Some(d) = &domain else { break };
                let effect = EffectProposal {
                    kind: d.decl.put.clone(),
                    target: ResourceRef {
                        kind: d.decl.resource_kind.clone(),
                        locator: path.clone(),
                        version: None,
                        extension: d.extension.clone(),
                    },
                    payload: json!({"digest":digest,"size":content.len(),"content":b64::encode(content)}),
                    preconditions: vec![],
                    outputs: vec![],
                };
                self.client.heartbeat(&lease).await?;
                match self.client.submit_effect(&lease, effect).await {
                    Ok(true) => effects.push(json!({"path":path,"digest":digest})),
                    Ok(false) => {
                        failure = Some(format!("the file extension rejected {path}"));
                        break;
                    }
                    Err(error) => {
                        failure = Some(error.message.clone());
                        break;
                    }
                }
            }
        }
        let state = match &failure {
            None => {
                self.client.heartbeat(&lease).await?;
                self.client.complete_execution(&lease).await?;
                "SUCCEEDED"
            }
            Some(reason) => {
                self.client
                    .command(Command::FailExecution {
                        execution,
                        lease: lease.id,
                        reason: reason.clone(),
                    })
                    .await?;
                "FAILED"
            }
        };
        event(
            &self.db,
            "execution.finished",
            &execution.to_string(),
            state,
        )?;
        crate::observe::record(
            "execution",
            json!({"execution":execution,"harness":harness_id,"provider":provider,"state":state,
                "exit_code":outcome.exit_code,"effects":effects.len(),"reason":failure}),
        );
        Ok(
            json!({"execution":execution,"work_unit":work_unit,"state":state,"harness":harness_id,
            "provider":provider,"exit_code":outcome.exit_code,"reason":failure,"effects":effects,
            "log_lines":outcome.logs.len(),"output_truncated":outcome.truncated}),
        )
    }
}

/// Provider/harness views and profile edits. They need config, not a Project runtime.
pub fn list_providers(config: &EffectiveConfig) -> Value {
    json!(
        config
            .providers
            .iter()
            .map(
                |(id, profile)| json!({"id":id,"name":profile.name,"kind":profile.kind,
            "enabled":profile.enabled,"default_harness":profile.default_harness,
            "source":config.provider_sources.get(id)})
            )
            .collect::<Vec<_>>()
    )
}

pub fn show_provider(config: &EffectiveConfig, id: &str) -> Result<Value> {
    let profile = config
        .providers
        .get(id)
        .ok_or_else(|| invalid(format!("provider {id} is not configured")))?;
    let harnesses: Vec<&String> = config
        .harnesses
        .iter()
        .filter(|(_, harness)| harness.provider == id)
        .map(|(id, _)| id)
        .collect();
    Ok(
        json!({"id":id,"profile":profile,"harnesses":harnesses,"source":config.provider_sources.get(id)}),
    )
}

/// Health check without launching the worker: executable, secrets and harness references.
pub fn test_provider(config: &EffectiveConfig, id: &str) -> Result<Value> {
    let profile = config
        .providers
        .get(id)
        .ok_or_else(|| invalid(format!("provider {id} is not configured")))?;
    let mut problems = Vec::new();
    let executable = match &profile.executable {
        Some(name) => match resolve_executable(name) {
            Ok(path) => Some(path),
            Err(error) => {
                problems.push(error.to_string());
                None
            }
        },
        None => None,
    };
    for (name, reference) in &profile.secrets {
        if resolve_secret(reference).is_err() {
            problems.push(format!("secret {name} ({reference}) is unavailable"));
        }
    }
    if let Some(harness) = &profile.default_harness
        && !config.harnesses.contains_key(harness)
    {
        problems.push(format!("default harness {harness} is not configured"));
    }
    if !profile.enabled {
        problems.push("provider is disabled".into());
    }
    Ok(json!({"id":id,"healthy":problems.is_empty(),"executable":executable,"problems":problems}))
}

pub fn list_harnesses(config: &EffectiveConfig) -> Value {
    let mut items = builtin_harnesses().as_array().cloned().unwrap_or_default();
    items.extend(config.harnesses.iter().map(|(id, harness)| {
        json!({"id":id,"builtin":false,"provider":harness.provider,"mode":harness.mode,
            "description":harness.description})
    }));
    json!(items)
}

pub fn show_harness(config: &EffectiveConfig, id: &str) -> Result<Value> {
    if id == CAPTURE_HARNESS {
        return Ok(builtin_harnesses()[0].clone());
    }
    let harness = config
        .harnesses
        .get(id)
        .ok_or_else(|| invalid(format!("harness {id} is not configured")))?;
    Ok(json!({"id":id,"builtin":false,"definition":harness}))
}

pub fn test_harness(config: &EffectiveConfig, id: &str) -> Result<Value> {
    if id == CAPTURE_HARNESS {
        return Ok(json!({"id":id,"healthy":true,"problems":[]}));
    }
    let harness = config
        .harnesses
        .get(id)
        .ok_or_else(|| invalid(format!("harness {id} is not configured")))?;
    let mut problems = Vec::new();
    let mut argv = None;
    match config.providers.get(&harness.provider) {
        None => problems.push(format!("provider {} is not configured", harness.provider)),
        Some(profile) => {
            if !profile.enabled {
                problems.push(format!("provider {} is disabled", harness.provider));
            }
            match launch_plan(&harness.provider, profile, harness) {
                Ok(plan) => argv = Some(plan.argv),
                Err(error) => problems.push(error.to_string()),
            }
        }
    }
    Ok(json!({"id":id,"healthy":problems.is_empty(),"argv":argv,"problems":problems}))
}

/// Edits go to the scope that already defines the profile, or `scope` for new profiles.
pub fn put_provider(
    paths: &ConfigPaths,
    scope: Option<Scope>,
    id: &str,
    profile: ProviderProfile,
) -> Result<Value> {
    let scope = match scope {
        Some(scope) => scope,
        None => paths.provider_scope(id).unwrap_or(Scope::Global),
    };
    paths.put_provider(scope, id, profile)?;
    Ok(json!({"id":id,"scope":scope.to_string()}))
}

#[cfg(test)]
mod tests {
    use super::in_scope;

    #[test]
    fn scope_matches_whole_path_segments() {
        assert!(in_scope(&[], "any/file"));
        assert!(in_scope(&["src".into()], "src/lib.rs"));
        assert!(in_scope(&["src/".into()], "src/lib.rs"));
        assert!(!in_scope(&["src".into()], "srcx/lib.rs"));
        assert!(in_scope(&["README.md".into()], "README.md"));
    }

    #[test]
    fn agent_content_accepts_both_base64_forms() {
        assert_eq!(super::decode_base64("aGk=").as_deref(), Some(&b"hi"[..]));
        assert_eq!(super::decode_base64("aGk").as_deref(), Some(&b"hi"[..]));
        assert_eq!(super::decode_base64("!!"), None);
    }
}
