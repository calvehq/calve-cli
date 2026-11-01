//! Local framed transport for the versioned Calve API: framing, peer checks, handshake,
//! request correlation and replay protection. It knows nothing about how requests are served;
//! the daemon passes the application's handler in.
#![forbid(unsafe_code)]

use std::future::Future;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::rc::Rc;

use calve_api::{self as app, Request, Response};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("{0}")]
    Busy(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Identity the daemon reports in its handshake.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub product_version: String,
    pub openaevc_revision: String,
}

const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Default)]
struct ReplayCache {
    entries: std::collections::HashMap<uuid::Uuid, (Vec<u8>, Response)>,
    order: std::collections::VecDeque<uuid::Uuid>,
    in_flight: std::collections::HashSet<uuid::Uuid>,
}

impl ReplayCache {
    fn insert(&mut self, id: uuid::Uuid, body: Vec<u8>, response: Response) {
        self.entries.insert(id, (body, response));
        self.order.push_back(id);
        if self.order.len() > 1024
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
enum Frame {
    Hello(Hello),
    HelloAck(HelloAck),
    Request(Box<Request>),
    Response(Box<Response>),
    /// Asks the daemon to stop; it acks, finishes in-flight requests, then exits. The peer is
    /// checked like any other client (same user only).
    Shutdown,
    ShutdownAck {
        pid: u32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    api_version: u16,
    product_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HelloAck {
    api_version: u16,
    product_version: String,
    openaevc_revision: String,
    accepted: bool,
    message: Option<String>,
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let size = reader.read_u32().await? as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(Error::Message("invalid IPC frame length".into()));
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    let body = serde_json::to_vec(frame)?;
    if body.len() > MAX_FRAME {
        return Err(Error::Message("IPC frame exceeds 8 MiB".into()));
    }
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Opens the local transport to the daemon: the Unix socket, or on Windows the daemon's named
/// pipe after checking the server runs as this user from the installed `calved.exe`.
#[cfg(unix)]
async fn connect(endpoint: &Path) -> Result<tokio::net::UnixStream> {
    Ok(tokio::net::UnixStream::connect(endpoint).await?)
}

#[cfg(windows)]
async fn connect(endpoint: &Path) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let client = loop {
        match calve_win_sec::pipe_connect(endpoint) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    let daemon = std::env::current_exe()?.with_file_name("calved.exe");
    calve_win_sec::verify_pipe_server(&client, &daemon).map_err(|e| {
        Error::Message(format!(
            "DAEMON_INCOMPATIBLE: refusing the daemon pipe: {e}"
        ))
    })?;
    Ok(client)
}

async fn hello<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    write_frame(
        stream,
        &Frame::Hello(Hello {
            api_version: app::API_VERSION,
            product_version: env!("CARGO_PKG_VERSION").into(),
        }),
    )
    .await?;
    let ack = match read_frame(stream).await? {
        Frame::HelloAck(ack) => ack,
        _ => {
            return Err(Error::Message(
                "DAEMON_INCOMPATIBLE: invalid daemon handshake".into(),
            ));
        }
    };
    // A release pins one OpenAEVC revision, so an older daemon is a different runtime too.
    if ack.accepted && ack.product_version != env!("CARGO_PKG_VERSION") {
        return Err(Error::Message(format!(
            "DAEMON_INCOMPATIBLE: the daemon is Calve {} (OpenAEVC {}) and this client {}; run `calve daemon restart`",
            ack.product_version,
            ack.openaevc_revision,
            env!("CARGO_PKG_VERSION")
        )));
    }
    if !ack.accepted || ack.api_version != app::API_VERSION {
        return Err(Error::Message(format!(
            "DAEMON_INCOMPATIBLE: {}",
            ack.message
                .unwrap_or_else(|| "incompatible daemon API".into())
        )));
    }
    Ok(())
}

pub async fn request(endpoint: &Path, payload: Request) -> Result<Response> {
    let mut stream = connect(endpoint).await?;
    hello(&mut stream).await?;
    write_frame(&mut stream, &Frame::Request(Box::new(payload))).await?;
    match read_frame(&mut stream).await? {
        Frame::Response(response) => Ok(*response),
        _ => Err(Error::Message(
            "DAEMON_INCOMPATIBLE: invalid daemon response".into(),
        )),
    }
}

/// Asks the daemon to stop (every platform; no signal or `kill`); returns its pid.
pub async fn shutdown(endpoint: &Path) -> Result<u32> {
    let mut stream = connect(endpoint).await?;
    hello(&mut stream).await?;
    write_frame(&mut stream, &Frame::Shutdown).await?;
    match read_frame(&mut stream).await? {
        Frame::ShutdownAck { pid } => Ok(pid),
        _ => Err(Error::Message(
            "DAEMON_INCOMPATIBLE: invalid shutdown reply".into(),
        )),
    }
}

#[cfg(unix)]
pub async fn serve<H, F>(endpoint: &Path, info: ServerInfo, handler: H) -> Result<()>
where
    H: Fn(Request) -> F + Clone + 'static,
    F: Future<Output = Response> + 'static,
{
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::sync::Arc;
    use tokio::net::UnixListener;
    use tokio::sync::{Mutex, Semaphore};

    let parent = endpoint
        .parent()
        .ok_or_else(|| Error::Message("socket has no parent".into()))?;
    let created = !parent.exists();
    if created {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let directory = fs::symlink_metadata(parent)?;
    if !directory.file_type().is_dir() || directory.permissions().mode() & 0o077 != 0 {
        return Err(Error::Message(
            "daemon socket directory must be private".into(),
        ));
    }
    let lock_path = parent.join("daemon.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    if directory.uid() != lock.metadata()?.uid() {
        return Err(Error::Message(
            "daemon socket directory is owned by another user".into(),
        ));
    }
    lock.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => Error::Busy("daemon is already running".into()),
        std::fs::TryLockError::Error(error) => Error::Io(error),
    })?;
    if let Ok(metadata) = fs::symlink_metadata(endpoint) {
        if !metadata.file_type().is_socket() {
            return Err(Error::Message(
                "daemon endpoint exists and is not a socket".into(),
            ));
        }
        fs::remove_file(endpoint)?;
    }
    let listener = UnixListener::bind(endpoint)?;
    fs::write(parent.join("daemon.pid"), std::process::id().to_string())?;
    fs::set_permissions(endpoint, fs::Permissions::from_mode(0o600))?;
    let owner = fs::metadata(endpoint)?.uid();
    let _endpoint_guard = EndpointGuard(endpoint.to_path_buf());
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let writer = Arc::new(Mutex::new(ReplayCache::default()));
            let slots = Arc::new(Semaphore::new(64));
            let stop = Rc::new(tokio::sync::Notify::new());
            let mut tasks = tokio::task::JoinSet::new();
            let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            loop {
                let permit = tokio::select! {
                    result = slots.clone().acquire_owned() => result.map_err(|_| Error::Message("daemon shutting down".into()))?,
                    result = tokio::signal::ctrl_c() => { result?; break; }
                    _ = terminate.recv() => break,
                    _ = stop.notified() => break,
                };
                tokio::select! {
                    result = listener.accept() => {
                        let (stream, _) = result?;
                        let writer = writer.clone();
                        let handler = handler.clone();
                        let info = info.clone();
                        let stop = stop.clone();
                        tasks.spawn_local(async move {
                            let _permit = permit;
                            let peer = stream.peer_cred().map(|c| c.uid());
                            if peer.ok() != Some(owner) {
                                eprintln!("calved: client: IPC peer is not the daemon owner");
                                return;
                            }
                            if let Err(error) = handle_client(stream, writer, &info, handler, stop).await {
                                eprintln!("calved: client: {error}");
                            }
                        });
                    }
                    result = tokio::signal::ctrl_c() => {
                        result?;
                        break;
                    }
                    _ = terminate.recv() => break,
                    _ = stop.notified() => break,
                }
            }
            drop(listener);
            while tokio::time::timeout(std::time::Duration::from_secs(5), tasks.join_next())
                .await
                .ok()
                .flatten()
                .is_some()
            {}
            tasks.abort_all();
            Ok::<(), Error>(())
        })
        .await?;
    drop(lock);
    Ok(())
}

#[cfg(unix)]
struct EndpointGuard(PathBuf);

#[cfg(unix)]
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// One authenticated connection (the transport checked the peer is our user).
async fn handle_client<S, H, F>(
    mut stream: S,
    writer: std::sync::Arc<tokio::sync::Mutex<ReplayCache>>,
    info: &ServerInfo,
    handler: H,
    stop: Rc<tokio::sync::Notify>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    let hello = match read_frame(&mut stream).await? {
        Frame::Hello(hello) => hello,
        _ => return Err(Error::Message("expected IPC hello".into())),
    };
    let accepted = hello.api_version == app::API_VERSION;
    write_frame(
        &mut stream,
        &Frame::HelloAck(HelloAck {
            api_version: app::API_VERSION,
            product_version: info.product_version.clone(),
            openaevc_revision: info.openaevc_revision.clone(),
            accepted,
            message: (!accepted).then(|| format!("unsupported API version {}", hello.api_version)),
        }),
    )
    .await?;
    if !accepted {
        return Ok(());
    }
    loop {
        let request = match read_frame(&mut stream).await {
            Ok(Frame::Request(request)) => *request,
            Ok(Frame::Shutdown) => {
                write_frame(
                    &mut stream,
                    &Frame::ShutdownAck {
                        pid: std::process::id(),
                    },
                )
                .await?;
                stop.notify_one();
                return Ok(());
            }
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Ok(_) => return Err(Error::Message("expected IPC request".into())),
            Err(error) => return Err(error),
        };
        let body = serde_json::to_vec(&request)?;
        let fault = |code: &str, message: &str, retryable: bool| Response {
            api_version: app::API_VERSION,
            request_id: request.request_id,
            correlation_id: request.correlation_id,
            outcome: app::Outcome::Error {
                error: app::Fault {
                    code: code.into(),
                    message: message.into(),
                    retryable,
                    detail: None,
                },
            },
        };
        // The cache lock covers lookup and insert only, never the request itself, so a long
        // execution does not block other clients.
        let replay = {
            let mut cache = writer.lock().await;
            match cache.entries.get(&request.request_id) {
                Some((original, previous)) if original == &body => Some(previous.clone()),
                Some(_) => Some(fault(
                    "REQUEST_ID_REUSED",
                    "request ID was reused for a different request",
                    false,
                )),
                None if cache.in_flight.contains(&request.request_id) => Some(fault(
                    "REQUEST_IN_PROGRESS",
                    "this request is still running",
                    true,
                )),
                None => {
                    cache.in_flight.insert(request.request_id);
                    None
                }
            }
        };
        let response = match replay {
            Some(response) => response,
            None => {
                let id = request.request_id;
                let response = handler(request).await;
                let mut cache = writer.lock().await;
                cache.in_flight.remove(&id);
                if !matches!(&response.outcome, app::Outcome::Error { error } if error.retryable) {
                    cache.insert(id, body, response.clone());
                }
                response
            }
        };
        write_frame(&mut stream, &Frame::Response(Box::new(response))).await?;
    }
}

#[cfg(windows)]
pub async fn serve<H, F>(endpoint: &Path, info: ServerInfo, handler: H) -> Result<()>
where
    H: Fn(Request) -> F + Clone + 'static,
    F: Future<Output = Response> + 'static,
{
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // FILE_FLAG_FIRST_PIPE_INSTANCE: a second daemon (or another user's squatter) cannot
    // create the first instance.
    let mut server = calve_win_sec::pipe_server(endpoint, true).map_err(|e| {
        if matches!(e.raw_os_error(), Some(5) | Some(231)) {
            Error::Busy("daemon is already running".into())
        } else {
            Error::Io(e)
        }
    })?;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let writer = Arc::new(Mutex::new(ReplayCache::default()));
            let stop = Rc::new(tokio::sync::Notify::new());
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = server.connect() => {
                        result?;
                        let connected = server;
                        server = calve_win_sec::pipe_server(endpoint, false)?;
                        if let Err(e) = calve_win_sec::verify_pipe_client(&connected) {
                            eprintln!("calved: client refused: {e}");
                            continue;
                        }
                        let (writer, handler, info, stop) = (writer.clone(), handler.clone(), info.clone(), stop.clone());
                        tasks.spawn_local(async move {
                            if let Err(error) = handle_client(connected, writer, &info, handler, stop).await {
                                eprintln!("calved: client: {error}");
                            }
                        });
                    }
                    result = tokio::signal::ctrl_c() => {
                        result?;
                        break;
                    }
                    _ = stop.notified() => break,
                }
            }
            while tokio::time::timeout(std::time::Duration::from_secs(5), tasks.join_next())
                .await
                .ok()
                .flatten()
                .is_some()
            {}
            tasks.abort_all();
            Ok::<(), Error>(())
        })
        .await
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    /// A frame survives the wire, and an oversized length is refused before anything is read.
    #[tokio::test]
    async fn frame_round_trip_and_size_limit() {
        for text in ["", "a", "é\u{10ffff}", &"x".repeat(70_000)] {
            let (mut a, mut b) = tokio::io::duplex(1 << 20);
            let hello = Frame::ShutdownAck {
                pid: text.len() as u32,
            };
            write_frame(&mut a, &hello).await.unwrap();
            assert!(matches!(
                read_frame(&mut b).await.unwrap(),
                Frame::ShutdownAck { pid } if pid == text.len() as u32
            ));
        }
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(read_frame(&mut b).await.is_err());
    }
}
