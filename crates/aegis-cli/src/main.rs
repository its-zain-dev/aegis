mod replay_server;

use aegis_core::{AegisConfig, IpcRequest, IpcResponse, PolicyConfig, RedactionConfig};
use aegis_mux::Gateway;
use aegis_policy::{PolicyDecision, PolicyEngine};
use aegis_redact::SecretRedactor;
use aegis_store::{export_jsonl, export_otel, ReplayEngine, ToolCache, TraceWal};
use aegis_transport::{
    serve_http_downstream, serve_stdio_downstream, ControlHandler, IpcClient, IpcEndpoint,
    IpcServer, McpHandler,
};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use replay_server::ReplayMcpServer;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const EXAMPLE_CONFIG: &str = include_str!("../../../aegis.example.toml");

#[derive(Parser, Debug)]
#[command(
    name = "aegis",
    version,
    about = "Single-binary Rust AI Agent Gateway & MCP Firewall"
)]
struct Cli {
    /// Path to aegis.toml configuration file
    #[arg(short, long, global = true, env = "AEGIS_CONFIG", default_value = "aegis.toml")]
    config: PathBuf,

    /// Log verbosity filter (e.g. info, debug, warn) — always written to stderr
    #[arg(long, global = true, env = "AEGIS_LOG", default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the Aegis MCP Gateway in Stdio or Streamable HTTP mode
    Serve {
        /// Expose MCP over stdin/stdout (default if --http is not specified)
        #[arg(long, conflicts_with = "http")]
        stdio: bool,

        /// Expose MCP over Streamable HTTP (e.g. 127.0.0.1:7420)
        #[arg(long, value_name = "ADDR")]
        http: Option<SocketAddr>,

        /// Named policy profile from [profiles.<name>]
        #[arg(short, long)]
        profile: Option<String>,

        /// Disable the local live IPC control server
        #[arg(long)]
        no_ipc: bool,

        /// Override Unix IPC socket path
        #[arg(long)]
        ipc_path: Option<PathBuf>,

        /// Override TCP IPC address (e.g. 127.0.0.1:17420)
        #[arg(long)]
        ipc_tcp: Option<String>,
    },

    /// Open the live interactive TUI dashboard (or inspect an offline .wal file)
    Tui {
        /// Inspect an offline binary WAL trace file instead of connecting live
        #[arg(long)]
        wal: Option<PathBuf>,

        /// Override Unix IPC socket path
        #[arg(long)]
        ipc_path: Option<PathBuf>,

        /// Override TCP IPC address
        #[arg(long)]
        ipc_tcp: Option<String>,
    },

    /// Query live gateway status and upstream health over IPC
    Status {
        /// Print machine-readable JSON output
        #[arg(long)]
        json: bool,

        /// Override Unix IPC socket path
        #[arg(long)]
        ipc_path: Option<PathBuf>,

        /// Override TCP IPC address
        #[arg(long)]
        ipc_tcp: Option<String>,
    },

    /// Trigger a live upstream reload on a running gateway over IPC
    Reload {
        #[arg(long)]
        ipc_path: Option<PathBuf>,
        #[arg(long)]
        ipc_tcp: Option<String>,
    },

    /// Clear the BLAKE3 content-addressed tool cache (live via IPC or offline on disk)
    ClearCache {
        /// Clear the disk cache directly without contacting a running gateway
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        ipc_path: Option<PathBuf>,
        #[arg(long)]
        ipc_tcp: Option<String>,
    },

    /// Validate aegis.toml and optionally test a tool name against policy & cache rules
    Check {
        /// Policy profile to evaluate
        #[arg(short, long)]
        profile: Option<String>,

        /// Evaluate a specific namespaced tool (e.g. github__delete_repo)
        #[arg(long)]
        test_tool: Option<String>,
    },

    /// Test secret & PII redaction rules on stdin, a file, or inline text
    TestRedact {
        /// Inline text to redact
        #[arg(long)]
        text: Option<String>,

        /// File path to redact (defaults to stdin if neither --text nor --file is set)
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Deterministically replay a binary WAL trace (policy/redaction diff or offline mock server)
    Replay {
        /// Path to the .wal trace file
        wal: PathBuf,

        /// Replay mode: diff or serve-stdio
        #[arg(long, value_enum, default_value_t = ReplayMode::Diff)]
        mode: ReplayMode,

        /// Optional policy profile to test during replay
        #[arg(short, long)]
        profile: Option<String>,

        /// Emit JSON report in diff mode
        #[arg(long)]
        json: bool,
    },

    /// Export a binary WAL trace file to JSONL or OpenTelemetry OTLP JSON
    Export {
        /// Path to the .wal trace file
        wal: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = ExportFormat::Jsonl)]
        format: ExportFormat,

        /// Destination file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Service name for OpenTelemetry resourceSpans
        #[arg(long, default_value = "aegis-gateway")]
        service_name: String,
    },

    /// Generate an annotated starter aegis.toml configuration file
    Init {
        /// Destination file path
        #[arg(short, long, default_value = "aegis.toml")]
        output: PathBuf,

        /// Overwrite existing file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ReplayMode {
    Diff,
    ServeStdio,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ExportFormat {
    Jsonl,
    Otel,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Never initialize stderr logging during interactive TUI rendering
    if !matches!(cli.command, Commands::Tui { .. }) {
        let filter = EnvFilter::try_new(&cli.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .with_target(false)
            .init();
    }

    match cli.command {
        Commands::Serve {
            stdio: _,
            http,
            profile,
            no_ipc,
            ipc_path,
            ipc_tcp,
        } => {
            let mut cfg = AegisConfig::from_file(&cli.config)
                .with_context(|| format!("failed to load config '{}'", cli.config.display()))?;
            if let Some(p) = ipc_path {
                cfg.ipc.path = Some(p);
            }
            if let Some(addr) = ipc_tcp {
                cfg.ipc.tcp_addr = Some(addr);
            }

            let mode = match http {
                Some(addr) => format!("http://{addr}/mcp"),
                None => "stdio".to_string(),
            };

            let gateway = Arc::new(Gateway::new(cfg.clone(), profile.as_deref(), mode)?);
            gateway.startup().await;

            // Start local IPC control server unless disabled
            let _ipc_guard = if !no_ipc && cfg.ipc.enabled {
                let endpoint = IpcEndpoint::from_config(&cfg.ipc);
                let control: Arc<dyn ControlHandler> = gateway.clone();
                match IpcServer::spawn(endpoint.clone(), control).await {
                    Ok(srv) => Some(srv),
                    Err(e) => {
                        warn!(endpoint = %endpoint, error = %e, "could not start IPC server; continuing without IPC");
                        None
                    }
                }
            } else {
                None
            };

            let mcp_handler: Arc<dyn McpHandler> = gateway.clone();
            let result = if let Some(addr) = http {
                let (shutdown_tx, shutdown_rx) = watch::channel(false);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = shutdown_tx.send(true);
                });
                let control: Arc<dyn ControlHandler> = gateway.clone();
                serve_http_downstream(addr, mcp_handler, Some(control), shutdown_rx)
                    .await
                    .map_err(Into::into)
            } else {
                info!(
                    config = %cli.config.display(),
                    profile = ?profile,
                    "Aegis MCP Gateway running in Stdio mode"
                );
                serve_stdio_downstream(mcp_handler).await.map_err(Into::into)
            };

            gateway.shutdown().await;
            result
        }

        Commands::Tui {
            wal,
            ipc_path,
            ipc_tcp,
        } => {
            if let Some(wal_path) = wal {
                aegis_tui::run_wal_tui(&wal_path)?;
                return Ok(());
            }
            let endpoint = resolve_ipc_endpoint(&cli.config, ipc_path, ipc_tcp);
            aegis_tui::run_live_tui(endpoint).await?;
            Ok(())
        }

        Commands::Status {
            json: as_json,
            ipc_path,
            ipc_tcp,
        } => {
            let endpoint = resolve_ipc_endpoint(&cli.config, ipc_path, ipc_tcp);
            let mut client = IpcClient::connect(&endpoint).await?;
            let stats = match client.request(&IpcRequest::GetStats).await? {
                IpcResponse::Stats(s) => s,
                other => return Err(anyhow!("unexpected IPC response: {other:?}")),
            };
            let servers = match client.request(&IpcRequest::GetServers).await? {
                IpcResponse::Servers(s) => s,
                other => return Err(anyhow!("unexpected IPC response: {other:?}")),
            };

            if as_json {
                let out = serde_json::json!({
                    "endpoint": endpoint.to_string(),
                    "stats": stats,
                    "servers": servers,
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Aegis Gateway Status ({endpoint})");
                println!("  Mode             : {}", stats.mode);
                println!("  Uptime           : {}s", stats.uptime_secs);
                println!(
                    "  Calls            : {} total ({} allowed, {} blocked, {} errors)",
                    stats.total_calls, stats.allowed_calls, stats.denied_calls, stats.error_calls
                );
                println!(
                    "  BLAKE3 Cache     : {} hits / {} misses",
                    stats.cache_hits, stats.cache_misses
                );
                println!("  Secrets Redacted : {}", stats.total_redactions);
                println!(
                    "  Latency          : avg {:.2}ms | p95 {}ms",
                    stats.avg_latency_ms, stats.p95_latency_ms
                );
                println!("  Upstreams ({}):", servers.len());
                for s in servers {
                    println!(
                        "    - {:<16} [{}] {:<10} tools={} calls={} errs={} restarts={}",
                        s.name,
                        s.transport,
                        s.state,
                        s.tool_count,
                        s.total_calls,
                        s.error_count,
                        s.restart_count
                    );
                }
            }
            Ok(())
        }

        Commands::Reload { ipc_path, ipc_tcp } => {
            let endpoint = resolve_ipc_endpoint(&cli.config, ipc_path, ipc_tcp);
            let mut client = IpcClient::connect(&endpoint).await?;
            match client.request(&IpcRequest::Reload).await? {
                IpcResponse::Ack { message } => {
                    println!("{message}");
                    Ok(())
                }
                IpcResponse::Error { message } => Err(anyhow!(message)),
                other => Err(anyhow!("unexpected IPC response: {other:?}")),
            }
        }

        Commands::ClearCache {
            offline,
            ipc_path,
            ipc_tcp,
        } => {
            if offline {
                let cfg = AegisConfig::from_file(&cli.config)?;
                let cache = ToolCache::from_config(&cfg.cache)?;
                let removed = cache.clear()?;
                println!("Cleared {removed} cached entries from {}", cfg.cache.resolved_dir().display());
                return Ok(());
            }
            let endpoint = resolve_ipc_endpoint(&cli.config, ipc_path, ipc_tcp);
            let mut client = IpcClient::connect(&endpoint).await?;
            match client.request(&IpcRequest::ClearCache).await? {
                IpcResponse::Ack { message } => {
                    println!("{message}");
                    Ok(())
                }
                IpcResponse::Error { message } => Err(anyhow!(message)),
                other => Err(anyhow!("unexpected IPC response: {other:?}")),
            }
        }

        Commands::Check { profile, test_tool } => {
            let cfg = AegisConfig::from_file(&cli.config)
                .with_context(|| format!("invalid config '{}'", cli.config.display()))?;
            let policy = PolicyEngine::from_config(&cfg, profile.as_deref())?;
            let _redactor = SecretRedactor::from_config(&cfg.redaction)?;
            let cache = ToolCache::from_config(&cfg.cache)?;

            println!("Config OK: {}", cli.config.display());
            println!(
                "  Gateway   : {} (separator '{}', timeout {}s)",
                cfg.gateway.name, cfg.gateway.namespace_separator, cfg.gateway.request_timeout_secs
            );
            println!(
                "  Profile   : {}",
                profile.as_deref().unwrap_or("<default>")
            );
            println!(
                "  Servers   : {} configured ({} enabled)",
                cfg.servers.len(),
                cfg.servers.values().filter(|s| s.enabled).count()
            );
            println!(
                "  Redaction : enabled={} outputs={} inputs={} entropy={} pii={}",
                cfg.redaction.enabled,
                cfg.redaction.redact_outputs,
                cfg.redaction.redact_inputs,
                cfg.redaction.enable_entropy,
                cfg.redaction.enable_pii
            );
            println!(
                "  Cache     : enabled={} ttl={}s dir={}",
                cfg.cache.enabled,
                cfg.cache.default_ttl_secs,
                cfg.cache.resolved_dir().display()
            );
            println!(
                "  WAL Trace : enabled={} compress={} path={}",
                cfg.trace.enabled,
                cfg.trace.compress,
                cfg.trace.resolved_path().display()
            );

            if let Some(tool) = test_tool {
                let (server, raw_tool) = tool
                    .split_once(&cfg.gateway.namespace_separator)
                    .unwrap_or(("unknown", tool.as_str()));
                let decision = policy.evaluate(server, raw_tool, &tool);
                let cacheable = cache.is_cacheable(server, raw_tool, &tool);
                println!("\nTool Check: {tool}");
                match decision {
                    PolicyDecision::Allow { matched_rule } => {
                        println!("  Policy    : ALLOW ({matched_rule})");
                    }
                    PolicyDecision::Deny {
                        matched_rule,
                        reason,
                    } => {
                        println!("  Policy    : DENY ({matched_rule}) — {reason}");
                    }
                }
                println!("  Cacheable : {cacheable}");
            }
            Ok(())
        }

        Commands::TestRedact { text, file } => {
            let redaction_cfg = if cli.config.exists() {
                AegisConfig::from_file(&cli.config)?.redaction
            } else {
                RedactionConfig::default()
            };
            let redactor = SecretRedactor::from_config(&redaction_cfg)?;

            let input = if let Some(t) = text {
                t
            } else if let Some(path) = file {
                fs::read_to_string(&path)
                    .with_context(|| format!("failed to read '{}'", path.display()))?
            } else {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                buf
            };

            let (redacted, report) = redactor.redact_str(&input);
            println!("{redacted}");
            eprintln!(
                "--- Aegis Redaction Summary: {} item(s) masked ({:?}) ---",
                report.total_redactions, report.by_category
            );
            Ok(())
        }

        Commands::Replay {
            wal,
            mode,
            profile,
            json: as_json,
        } => {
            let (engine, wal_stats) = ReplayEngine::from_wal(&wal)?;
            let (policy, redactor, sep) = if cli.config.exists() {
                let cfg = AegisConfig::from_file(&cli.config)?;
                (
                    PolicyEngine::from_config(&cfg, profile.as_deref())?,
                    SecretRedactor::from_config(&cfg.redaction)?,
                    cfg.gateway.namespace_separator,
                )
            } else {
                (
                    PolicyEngine::from_policy(&PolicyConfig::default()),
                    SecretRedactor::from_config(&RedactionConfig::default())?,
                    "__".to_string(),
                )
            };

            match mode {
                ReplayMode::Diff => {
                    let report = engine.diff(&policy, &redactor);
                    if as_json {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    } else {
                        println!(
                            "Aegis Replay Diff ({} — {} records loaded, {} skipped)",
                            wal.display(),
                            wal_stats.records_read,
                            wal_stats.corrupted_frames_skipped
                        );
                        println!("  Total records         : {}", report.total_records);
                        println!("  Unchanged             : {}", report.unchanged);
                        println!("  Newly DENIED          : {}", report.now_denied);
                        println!("  Newly ALLOWED         : {}", report.now_allowed);
                        println!("  Additional Redactions : {}", report.additional_redactions);
                        if !report.diffs.is_empty() {
                            println!("\nDifferences:");
                            for d in &report.diffs {
                                println!(
                                    "  - {} | prev={} -> new={} ({}) | extra_redactions={}",
                                    d.namespaced_tool,
                                    d.previous_outcome,
                                    if d.new_policy_allowed { "ALLOW" } else { "DENY" },
                                    d.matched_rule,
                                    d.new_redactions
                                );
                            }
                        }
                    }
                    Ok(())
                }
                ReplayMode::ServeStdio => {
                    info!(
                        wal = %wal.display(),
                        records = wal_stats.records_read,
                        "serving deterministic offline MCP replay over stdio"
                    );
                    let srv: Arc<dyn McpHandler> =
                        Arc::new(ReplayMcpServer::new(engine, policy, redactor, sep));
                    serve_stdio_downstream(srv).await?;
                    Ok(())
                }
            }
        }

        Commands::Export {
            wal,
            format,
            output,
            service_name,
        } => {
            let (records, wal_stats) = TraceWal::read_all(&wal)?;
            let mut writer: Box<dyn Write> = match &output {
                Some(path) => Box::new(fs::File::create(path)?),
                None => Box::new(io::stdout().lock()),
            };

            let count = match format {
                ExportFormat::Jsonl => export_jsonl(&records, &mut writer)?,
                ExportFormat::Otel => export_otel(&records, &service_name, &mut writer)?,
            };

            eprintln!(
                "Exported {count} record(s) from {} (corrupted skipped: {})",
                wal.display(),
                wal_stats.corrupted_frames_skipped
            );
            Ok(())
        }

        Commands::Init { output, force } => {
            if output.exists() && !force {
                return Err(anyhow!(
                    "'{}' already exists (pass --force to overwrite)",
                    output.display()
                ));
            }
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&output, EXAMPLE_CONFIG)?;
            println!("Wrote starter configuration to {}", output.display());
            Ok(())
        }
    }
}

fn resolve_ipc_endpoint(
    config_path: &Path,
    ipc_path: Option<PathBuf>,
    ipc_tcp: Option<String>,
) -> IpcEndpoint {
    if let Some(addr) = ipc_tcp {
        return IpcEndpoint::Tcp(addr);
    }
    #[cfg(unix)]
    if let Some(path) = ipc_path {
        return IpcEndpoint::Unix(path);
    }
    #[cfg(not(unix))]
    let _ = ipc_path;

    let ipc_cfg = if config_path.exists() {
        AegisConfig::from_file(config_path)
            .map(|c| c.ipc)
            .unwrap_or_default()
    } else {
        Default::default()
    };
    IpcEndpoint::from_config(&ipc_cfg)
}
