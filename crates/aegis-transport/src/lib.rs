pub mod http;
pub mod ipc;
pub mod sse;
pub mod stdio;
pub mod traits;

pub use http::{build_http_router, serve_http_downstream, StreamableHttpUpstream};
pub use ipc::{IpcClient, IpcEndpoint, IpcServer};
pub use sse::LegacySseUpstream;
pub use stdio::{serve_stdio_downstream, StdioUpstream};
pub use traits::{initialize_upstream, ControlHandler, McpHandler, UpstreamTransport};
