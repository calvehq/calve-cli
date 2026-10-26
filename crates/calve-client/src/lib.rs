//! One client for the Calve API with two backends: the local daemon over IPC, or the same
//! application use cases embedded in-process (PLAN §11.3). Callers never pick the backend.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use calve_api::{Action, DaemonCommand, Outcome, Request, RequestScope, Response};
use serde_json::{Value, json};

pub use calve_app::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Daemon,
    Embedded,
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Always run in-process.
    pub direct: bool,
    /// Explicit daemon endpoint; when set, failing to reach it is an error.
    pub endpoint: Option<PathBuf>,
    /// Never start `calved` implicitly.
    pub no_daemon_start: bool,
}

pub struct Client {
    options: Options,
}

/// The daemon socket (§12.2): in the platform runtime directory when there is one
/// (`$XDG_RUNTIME_DIR/calve/<data root digest>/daemon.sock`, so each data root has its own
/// daemon), otherwise in the data directory. The pid file sits beside the socket.
pub fn default_endpoint() -> Result<PathBuf> {
    Ok(calve_app::registry::runtime_dir()?.join("daemon.sock"))
}

/// The daemon pid file beside the socket it serves.
fn daemon_file(endpoint: &Path, name: &str) -> PathBuf {
    endpoint.with_file_name(name)
}

/// The daemon log: `<data>/logs/daemon.log` (runtime directories are not for logs).
fn daemon_log() -> Result<PathBuf> {
    Ok(calve_app::registry::default_data_root()?.join("logs/daemon.log"))
}

fn ipc_error(error: calve_ipc::Error) -> Error {
    match error {
        calve_ipc::Error::Io(error) => Error::Message(format!(
            "DAEMON_UNAVAILABLE: the daemon could not be reached: {error}"
        )),
        calve_ipc::Error::Busy(message) => Error::Busy(message),
        other => Error::Message(other.to_string()),
    }
}

/// Lets concurrent in-process requests on this thread share one runtime per Project, as the
/// daemon does. Interactive embedded clients (the console) call this once.
pub fn share_embedded_projects() {
    calve_app::app::enable_project_cache();
}

/// Serves the API on `endpoint` with this build's application handler.
pub async fn serve(endpoint: &Path) -> Result<()> {
    // Requests run on this thread's local task set; share one runtime per Project here.
    calve_app::app::enable_project_cache();
    // Groups left by a daemon that died (macOS has no parent-death signal): reap them first.
    let _ = calve_app::supervise::reap();
    calve_ipc::serve(
        endpoint,
        calve_ipc::ServerInfo {
            product_version: env!("CARGO_PKG_VERSION").into(),
            openaevc_revision: calve_app::compatibility::OPENAEVC_REVISION.into(),
        },
        calve_app::app::execute,
    )
    .await
    .map_err(ipc_error)
}

/// Returns the daemon's version report when a compatible daemon answers.
pub async fn daemon_alive(endpoint: &Path) -> Option<Value> {
    let probe = Request::local(
        RequestScope {
            project: None,
            workspace: None,
            config_file: None,
            actor: None,
        },
        Action::Version,
    );
    match calve_ipc::request(endpoint, probe).await.ok()?.outcome {
        Outcome::Ok { value } => Some(value),
        Outcome::Error { .. } => None,
    }
}

impl Client {
    pub fn new(options: Options) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn endpoint(&self) -> Result<PathBuf> {
        match &self.options.endpoint {
            Some(endpoint) => Ok(endpoint.clone()),
            None => default_endpoint(),
        }
    }

    /// Sends one request. Supervised work (executions) starts `calved` first so the worker
    /// outlives this process, unless the caller opted out (PLAN §11.4).
    pub async fn send(&self, request: Request) -> Result<(Response, Backend)> {
        if self.options.direct {
            return Ok((calve_app::app::execute(request).await, Backend::Embedded));
        }
        let endpoint = self.endpoint()?;
        let supervised = matches!(
            request.action,
            Action::Execution {
                command: calve_api::ExecutionCommand::Start { .. }
                    | calve_api::ExecutionCommand::Retry { .. }
            }
        );
        if supervised
            && !self.options.no_daemon_start
            && daemon_alive(&endpoint).await.is_none()
            && let Err(error) = self.daemon(DaemonCommand::Start).await
        {
            eprintln!("calve: could not start calved ({error}); running in this process");
        }
        if endpoint.exists() || self.options.endpoint.is_some() {
            match calve_ipc::request(&endpoint, request.clone()).await {
                Ok(response) => return Ok((response, Backend::Daemon)),
                Err(calve_ipc::Error::Io(error))
                    if self.options.endpoint.is_none()
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                        ) => {}
                Err(error) => return Err(ipc_error(error)),
            }
        }
        Ok((calve_app::app::execute(request).await, Backend::Embedded))
    }

    /// Sends a request and unwraps the outcome into a value or a product error.
    pub async fn call(&self, scope: RequestScope, action: Action) -> Result<Value> {
        let (response, _) = self.send(Request::local(scope, action)).await?;
        match response.outcome {
            Outcome::Ok { value } => Ok(value),
            Outcome::Error { error } => {
                Err(Error::Message(format!("{}: {}", error.code, error.message)))
            }
        }
    }

    /// Daemon lifecycle; these never travel over the daemon API.
    pub async fn daemon(&self, command: DaemonCommand) -> Result<Value> {
        let endpoint = self.endpoint()?;
        match command {
            DaemonCommand::Serve => {
                serve(&endpoint).await?;
                Ok(json!({"stopped":true}))
            }
            DaemonCommand::Status => Ok(match daemon_alive(&endpoint).await {
                Some(version) => json!({"running":true,"endpoint":endpoint,"version":version}),
                None => json!({"running":false,"endpoint":endpoint}),
            }),
            DaemonCommand::Start => {
                if let Some(version) = daemon_alive(&endpoint).await {
                    return Ok(json!({"running":true,"already_running":true,"version":version}));
                }
                let log_path = daemon_log()?;
                if let Some(parent) = log_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let log = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)?;
                let exe = std::env::current_exe()?.with_file_name(if cfg!(windows) {
                    "calved.exe"
                } else {
                    "calved"
                });
                let mut child = std::process::Command::new(exe)
                    .arg("--endpoint")
                    .arg(&endpoint)
                    .stdin(std::process::Stdio::null())
                    .stdout(log.try_clone()?)
                    .stderr(log)
                    .spawn()?;
                for _ in 0..100 {
                    if let Some(version) = daemon_alive(&endpoint).await {
                        return Ok(json!({"running":true,"pid":child.id(),"version":version}));
                    }
                    if let Some(status) = child.try_wait()? {
                        return Err(Error::Message(format!(
                            "DAEMON_UNAVAILABLE: calved exited with {status}; see {}",
                            log_path.display()
                        )));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(Error::Message(
                    "DAEMON_UNAVAILABLE: calved did not become ready within 5 s".into(),
                ))
            }
            DaemonCommand::Stop => {
                if daemon_alive(&endpoint).await.is_none() {
                    return Ok(json!({"running":false}));
                }
                let pid = std::fs::read_to_string(daemon_file(&endpoint, "daemon.pid"))?;
                let pid = pid.trim();
                // ponytail: shells out to kill(1) because unsafe (libc) is forbidden; unix only.
                let status = std::process::Command::new("kill")
                    .args(["-TERM", pid])
                    .status()?;
                if !status.success() {
                    return Err(Error::Message(format!("could not signal calved pid {pid}")));
                }
                for _ in 0..200 {
                    if !endpoint.exists() {
                        return Ok(json!({"running":false,"stopped_pid":pid}));
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(Error::Message("calved did not stop within 10 s".into()))
            }
            DaemonCommand::Restart => {
                Box::pin(self.daemon(DaemonCommand::Stop)).await?;
                Box::pin(self.daemon(DaemonCommand::Start)).await
            }
            DaemonCommand::Logs { lines } => {
                let text = match std::fs::read_to_string(daemon_log()?) {
                    Ok(text) => text,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => return Err(error.into()),
                };
                let all: Vec<&str> = text.lines().collect();
                Ok(Value::String(
                    all[all.len().saturating_sub(lines)..].join("\n"),
                ))
            }
        }
    }
}
