//! Local framed transport for the versioned Calve API: framing, peer checks, handshake,
//! request correlation and replay protection. It knows nothing about how requests are served;
//! the daemon passes the application's handler in.
#![forbid(unsafe_code)]

use std::future::Future;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

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

#[cfg(unix)]
#[derive(Default)]
struct ReplayCache {
    entries: std::collections::HashMap<uuid::Uuid, (Vec<u8>, Response)>,
    order: std::collections::VecDeque<uuid::Uuid>,
    in_flight: std::collections::HashSet<uuid::Uuid>,
}

#[cfg(unix)]
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

#[cfg(unix)]
pub async fn request(endpoint: &Path, payload: Request) -> Result<Response> {
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(endpoint).await?;
    write_frame(
        &mut stream,
        &Frame::Hello(Hello {
            api_version: app::API_VERSION,
            product_version: env!("CARGO_PKG_VERSION").into(),
        }),
    )
    .await?;
    let ack = match read_frame(&mut stream).await? {
        Frame::HelloAck(ack) => ack,
        _ => return Err(Error::Message("invalid daemon handshake".into())),
    };
    if !ack.accepted || ack.api_version != app::API_VERSION {
        return Err(Error::Message(
            ack.message
                .unwrap_or_else(|| "incompatible daemon API".into()),
        ));
    }
    write_frame(&mut stream, &Frame::Request(Box::new(payload))).await?;
    match read_frame(&mut stream).await? {
        Frame::Response(response) => Ok(*response),
        _ => Err(Error::Message("invalid daemon response".into())),
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
            let mut tasks = tokio::task::JoinSet::new();
            let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            loop {
                let permit = tokio::select! {
                    result = slots.clone().acquire_owned() => result.map_err(|_| Error::Message("daemon shutting down".into()))?,
                    result = tokio::signal::ctrl_c() => { result?; break; }
                    _ = terminate.recv() => break,
                };
                tokio::select! {
                    result = listener.accept() => {
                        let (stream, _) = result?;
                        let writer = writer.clone();
                        let handler = handler.clone();
                        let info = info.clone();
                        tasks.spawn_local(async move {
                            let _permit = permit;
                            if let Err(error) = handle_client(stream, owner, writer, &info, handler).await {
                                eprintln!("calved: client: {error}");
                            }
                        });
                    }
                    result = tokio::signal::ctrl_c() => {
                        result?;
                        break;
                    }
                    _ = terminate.recv() => break,
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

#[cfg(unix)]
async fn handle_client<H, F>(
    mut stream: tokio::net::UnixStream,
    owner: u32,
    writer: std::sync::Arc<tokio::sync::Mutex<ReplayCache>>,
    info: &ServerInfo,
    handler: H,
) -> Result<()>
where
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    if stream.peer_cred()?.uid() != owner {
        return Err(Error::Message("IPC peer is not the daemon owner".into()));
    }
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

#[cfg(not(unix))]
pub async fn request(_endpoint: &Path, _payload: Request) -> Result<Response> {
    Err(Error::Message(
        "local IPC is not yet supported on this platform".into(),
    ))
}

#[cfg(not(unix))]
pub async fn serve<H, F>(_endpoint: &Path, _info: ServerInfo, _handler: H) -> Result<()>
where
    H: Fn(Request) -> F + Clone + 'static,
    F: Future<Output = Response> + 'static,
{
    Err(Error::Message(
        "local IPC is not yet supported on this platform".into(),
    ))
}
