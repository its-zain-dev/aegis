use crate::traits::ControlHandler;
use aegis_core::{AegisError, IpcConfig, IpcRequest, IpcResponse, Result};
use std::fmt;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone)]
pub enum IpcEndpoint {
    #[cfg(unix)]
    Unix(PathBuf),
    Tcp(String),
}

impl IpcEndpoint {
    pub fn from_config(cfg: &IpcConfig) -> Self {
        if let Some(addr) = &cfg.tcp_addr {
            return Self::Tcp(addr.clone());
        }
        #[cfg(unix)]
        {
            Self::Unix(cfg.resolved_unix_path())
        }
        #[cfg(not(unix))]
        {
            Self::Tcp(cfg.resolved_tcp_addr())
        }
    }
}

impl fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(unix)]
            IpcEndpoint::Unix(p) => write!(f, "unix://{}", p.display()),
            IpcEndpoint::Tcp(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

/// Live local control & telemetry IPC server.
/// Runs alongside both `--stdio` and `--http` modes so `aegis tui` and `aegis status` attach seamlessly.
pub struct IpcServer {
    endpoint: IpcEndpoint,
    handle: JoinHandle<()>,
}

impl IpcServer {
    pub async fn spawn(endpoint: IpcEndpoint, control: Arc<dyn ControlHandler>) -> Result<Self> {
        let handle = match &endpoint {
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                if path.exists() {
                    let _ = std::fs::remove_file(path);
                }
                let listener = UnixListener::bind(path).map_err(|e| {
                    AegisError::Ipc(format!(
                        "failed to bind Unix IPC socket '{}': {e}",
                        path.display()
                    ))
                })?;
                info!(socket = %path.display(), "Aegis IPC server listening");
                tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((stream, _)) => {
                                let ctrl = Arc::clone(&control);
                                tokio::spawn(async move {
                                    let (read_half, write_half) = stream.into_split();
                                    handle_ipc_connection(
                                        BufReader::new(read_half),
                                        write_half,
                                        ctrl,
                                    )
                                    .await;
                                });
                            }
                            Err(e) => {
                                debug!(error = %e, "IPC unix accept error");
                                break;
                            }
                        }
                    }
                })
            }
            IpcEndpoint::Tcp(addr) => {
                let listener = TcpListener::bind(addr).await.map_err(|e| {
                    AegisError::Ipc(format!("failed to bind TCP IPC on '{addr}': {e}"))
                })?;
                info!(%addr, "Aegis TCP IPC server listening");
                tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((stream, _)) => {
                                let ctrl = Arc::clone(&control);
                                tokio::spawn(async move {
                                    let (read_half, write_half) = stream.into_split();
                                    handle_ipc_connection(
                                        BufReader::new(read_half),
                                        write_half,
                                        ctrl,
                                    )
                                    .await;
                                });
                            }
                            Err(e) => {
                                debug!(error = %e, "IPC tcp accept error");
                                break;
                            }
                        }
                    }
                })
            }
        };

        Ok(Self { endpoint, handle })
    }

    pub fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.handle.abort();
        #[cfg(unix)]
        if let IpcEndpoint::Unix(path) = &self.endpoint {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn handle_ipc_connection<R, W>(mut reader: R, mut writer: W, control: Arc<dyn ControlHandler>)
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut line = String::new();
    let mut subscribed = false;
    let mut events_rx = control.subscribe_events();

    loop {
        if subscribed {
            line.clear();
            tokio::select! {
                read_res = reader.read_line(&mut line) => {
                    match read_res {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            if !process_ipc_line(&line, &mut writer, &control, &mut subscribed).await {
                                break;
                            }
                        }
                    }
                }
                ev_res = events_rx.recv() => {
                    match ev_res {
                        Ok(ev) => {
                            if write_ipc_response(&mut writer, &IpcResponse::Event(ev)).await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        } else {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if !process_ipc_line(&line, &mut writer, &control, &mut subscribed).await {
                        break;
                    }
                }
            }
        }
    }
}

async fn process_ipc_line<W: AsyncWrite + Unpin>(
    line: &str,
    writer: &mut W,
    control: &Arc<dyn ControlHandler>,
    subscribed: &mut bool,
) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }

    let req: IpcRequest = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            return write_ipc_response(
                writer,
                &IpcResponse::Error {
                    message: format!("invalid IPC request: {e}"),
                },
            )
            .await
            .is_ok();
        }
    };

    match req {
        IpcRequest::Ping => write_ipc_response(writer, &IpcResponse::Pong).await.is_ok(),
        IpcRequest::GetStats => {
            let stats = control.stats().await;
            write_ipc_response(writer, &IpcResponse::Stats(stats))
                .await
                .is_ok()
        }
        IpcRequest::GetServers => {
            let servers = control.servers().await;
            write_ipc_response(writer, &IpcResponse::Servers(servers))
                .await
                .is_ok()
        }
        IpcRequest::Reload => {
            let resp = match control.reload().await {
                Ok(msg) => IpcResponse::Ack { message: msg },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            };
            write_ipc_response(writer, &resp).await.is_ok()
        }
        IpcRequest::ClearCache => {
            let resp = match control.clear_cache().await {
                Ok(n) => IpcResponse::Ack {
                    message: format!("cleared {n} cached entries"),
                },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            };
            write_ipc_response(writer, &resp).await.is_ok()
        }
        IpcRequest::Subscribe => {
            *subscribed = true;
            let stats = control.stats().await;
            let servers = control.servers().await;
            if write_ipc_response(writer, &IpcResponse::Stats(stats))
                .await
                .is_err()
            {
                return false;
            }
            write_ipc_response(writer, &IpcResponse::Servers(servers))
                .await
                .is_ok()
        }
    }
}

async fn write_ipc_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &IpcResponse,
) -> std::io::Result<()> {
    let json = serde_json::to_string(resp).unwrap_or_else(|_| "{}".to_string());
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

enum IpcReader {
    #[cfg(unix)]
    Unix(BufReader<tokio::net::unix::OwnedReadHalf>),
    Tcp(BufReader<tokio::net::tcp::OwnedReadHalf>),
}

enum IpcWriter {
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedWriteHalf),
    Tcp(tokio::net::tcp::OwnedWriteHalf),
}

/// Cross-platform client for talking to a live Aegis gateway over Unix socket or loopback TCP.
pub struct IpcClient {
    reader: IpcReader,
    writer: IpcWriter,
}

impl IpcClient {
    pub async fn connect(endpoint: &IpcEndpoint) -> Result<Self> {
        match endpoint {
            #[cfg(unix)]
            IpcEndpoint::Unix(path) => {
                let stream = UnixStream::connect(path).await.map_err(|e| {
                    AegisError::Ipc(format!(
                        "could not connect to Aegis IPC at '{}': {e}",
                        path.display()
                    ))
                })?;
                let (r, w) = stream.into_split();
                Ok(Self {
                    reader: IpcReader::Unix(BufReader::new(r)),
                    writer: IpcWriter::Unix(w),
                })
            }
            IpcEndpoint::Tcp(addr) => {
                let stream = TcpStream::connect(addr).await.map_err(|e| {
                    AegisError::Ipc(format!("could not connect to Aegis IPC at '{addr}': {e}"))
                })?;
                let (r, w) = stream.into_split();
                Ok(Self {
                    reader: IpcReader::Tcp(BufReader::new(r)),
                    writer: IpcWriter::Tcp(w),
                })
            }
        }
    }

    pub async fn send(&mut self, req: &IpcRequest) -> Result<()> {
        let line = serde_json::to_string(req)?;
        match &mut self.writer {
            #[cfg(unix)]
            IpcWriter::Unix(w) => {
                w.write_all(line.as_bytes()).await?;
                w.write_all(b"\n").await?;
                w.flush().await?;
            }
            IpcWriter::Tcp(w) => {
                w.write_all(line.as_bytes()).await?;
                w.write_all(b"\n").await?;
                w.flush().await?;
            }
        }
        Ok(())
    }

    pub async fn next_response(&mut self) -> Result<Option<IpcResponse>> {
        let mut line = String::new();
        let n = match &mut self.reader {
            #[cfg(unix)]
            IpcReader::Unix(r) => r.read_line(&mut line).await?,
            IpcReader::Tcp(r) => r.read_line(&mut line).await?,
        };
        if n == 0 {
            return Ok(None);
        }
        let resp: IpcResponse = serde_json::from_str(line.trim())?;
        Ok(Some(resp))
    }

    pub async fn request(&mut self, req: &IpcRequest) -> Result<IpcResponse> {
        self.send(req).await?;
        self.next_response()
            .await?
            .ok_or_else(|| AegisError::Ipc("IPC connection closed before response".into()))
    }
}
