# Aegis — Single-Binary Rust AI Agent Gateway & MCP Firewall

[![Version](https://img.shields.io/badge/version-0.9.0-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green.svg)](#license)
[![Pure Rust](https://img.shields.io/badge/pure--rust-zero%20C%20deps-orange.svg)](#architecture)

**Aegis** is a high-performance, cross-platform, single-binary **MCP Gateway & Firewall** written in 100% pure Rust. It connects AI coding assistants (like **Antigravity CLI**, Claude Code, Cursor, and custom agents) to **multiple MCP servers simultaneously** behind one unified endpoint—while enforcing tool-level firewall policies, masking leaked secrets/PII before they leave your device, caching idempotent tool calls with BLAKE3, recording crash-safe binary traces, and streaming live telemetry to a terminal dashboard (`aegis tui`).

Designed from day one to compile and run cleanly everywhere: **Linux**, **macOS**, **Windows**, and **Termux on Android (`aarch64`)** with **zero C library dependencies** (no OpenSSL, no `libsqlite3`, no `zstd-sys`).

---

## Key Features

- **Universal MCP Multiplexer & Protocol Bridge**
  - Downstream: **Stdio** (`aegis serve --stdio`) and **Streamable HTTP 2025-03-26** (`aegis serve --http 127.0.0.1:7420`, with `/mcp`, `/health`, and Prometheus `/metrics`).
  - Upstreams: **Stdio** child processes, **Streamable HTTP (2025-03-26)**, and a built-in **Legacy HTTP+SSE (2024-11-05) bridge** so modern MCP clients like Antigravity CLI can talk to older SSE servers seamlessly.
  - Collision-free tool & prompt namespacing (`github__list_issues`, `filesystem__read_file`) with eager or lazy startup and automatic crash recovery.
- **Zero-Overhead Tool-Level Firewall (`aegis-policy`)**
  - Linear-time, ReDoS-immune glob allowlists/denylists (`*`, `?`) per server and globally, plus named policy **profiles** (`--profile readonly`, `--profile dev`).
  - Explicit deny always overrides allow; optionally hides denied tools from `tools/list` to keep agent context clean and small.
- **High-Speed Secret & PII Redaction (`aegis-redact`)**
  - Two-stage one-way masking (`[REDACTED:<category>]`): Aho-Corasick multi-pattern prefilter + curated regexes (GitHub PATs, OpenAI/Anthropic/AWS/Google/Slack/Stripe/GitLab/npm/HF tokens, JWTs, PEM private keys, Bearer headers, DB URLs with credentials, generic assignments, optional Luhn credit cards & emails) + Shannon-entropy detector for unlabeled random secrets.
- **Pure-Rust BLAKE3 Cache & Crash-Safe Binary WAL (`aegis-store`)**
  - Canonical JSON + **BLAKE3** content-addressed disk cache (`lz4_flex` + MessagePack) with TTL & LRU eviction.
  - Append-only CRC32-framed binary Write-Ahead Log (`AEGSWAL\x01`) with automatic torn-tail recovery.
  - **Deterministic Replay (`aegis replay`)**: diff historical traces against stricter firewall/redaction configs, or run an offline deterministic mock MCP server (`--mode serve-stdio`) for zero-cost CI testing.
  - **Export (`aegis export`)**: convert binary traces to `jsonl` or **OpenTelemetry OTLP JSON** (`otel`).
- **Live Terminal Dashboard (`aegis tui`)**
  - Attaches over local IPC (Unix domain socket on Linux/macOS/Termux; loopback TCP on Windows) to **either** `--stdio` or `--http` gateways without ever interfering with stdio JSON-RPC streams.
  - Live tool call feed & payload inspector, upstream health & hot-reload (`r`), security/redaction breakdown, and BLAKE3 cache controls (`c`).

---

## Architecture

```
                Antigravity CLI / Claude / Cursor / Custom Agents
                          │                           │
                  Stdio (--stdio)           Streamable HTTP (--http)
                          └─────────────┬─────────────┘
                                        ▼
        ┌──────────────────────────────────────────────────────────────┐
        │                       aegis-mux Gateway                      │
        │  [1] Namespace Router  ──▶  [2] Policy Firewall (globs)      │
        │  [3] Input Redactor    ──▶  [4] BLAKE3 Disk Cache (TTL/LRU)  │
        │  [5] Upstream Pool     ──▶  [6] Output Secret/PII Redactor   │
        │  [7] CRC32 Binary WAL  ──▶  [8] Live IPC Telemetry Bus       │
        └──────────┬────────────────────┬────────────────────┬─────────┘
                   │                    │                    │
                   ▼                    ▼                    ▼
         Stdio MCP Servers   Streamable HTTP (2025)   Legacy SSE (2024)
         (filesystem, git)    (GitHub, remote APIs)    (bridged seamlessly)
                                        │
                            Local IPC (Unix / TCP)
                                        ▼
                            aegis tui  /  aegis status
```

### Workspace Layout

| Crate | Purpose |
|---|---|
| `aegis-core` | JSON-RPC 2.0 & MCP protocol types, TOML config loader, telemetry & IPC models |
| `aegis-policy` | ReDoS-immune glob matcher and tool-level allowlist/denylist firewall engine |
| `aegis-redact` | Aho-Corasick + regex + Shannon-entropy secret & PII redactor |
| `aegis-store` | CRC32+LZ4+MessagePack WAL, BLAKE3 disk cache, replay engine, JSONL/OTLP export |
| `aegis-transport` | Stdio, Streamable HTTP (Axum + Reqwest/Rustls), Legacy SSE bridge, Unix/TCP IPC |
| `aegis-mux` | Upstream lifecycle pool, crash recovery, request pipeline, rolling latency metrics |
| `aegis-tui` | Multi-tab `ratatui` live dashboard & offline WAL trace viewer |
| `aegis-cli` | Single `aegis` binary exposing all subcommands |

---

## Quickstart

### 1. Build from Source

```bash
git clone https://github.com/its-zain-dev/aegis.git
cd aegis
cargo build --release
# Binary is at ./target/release/aegis
```

### 2. Initialize & Validate Config

```bash
aegis init --output aegis.toml
aegis check --config aegis.toml --test-tool github__delete_repo
```

### 3. Connect Antigravity CLI to Aegis

#### Option A: Zero-daemon Stdio Mode (`~/.gemini/config/mcp_config.json`)

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/absolute/path/to/aegis",
      "args": ["serve", "--stdio", "--config", "/absolute/path/to/aegis.toml"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

#### Option B: Shared Background Daemon (Streamable HTTP)

Start Aegis once (shared across multiple agent sessions with a warm BLAKE3 cache):

```bash
aegis serve --http 127.0.0.1:7420 --config aegis.toml
```

Point Antigravity CLI at Aegis in `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "aegis": {
      "url": "http://127.0.0.1:7420/mcp"
    }
  }
}
```

### 4. Attach the Live TUI Dashboard

While Aegis is running (in **either** `--stdio` or `--http` mode!), open another terminal:

```bash
aegis tui
```

---

## CLI Reference

```bash
aegis serve --stdio [--config aegis.toml] [--profile readonly]
aegis serve --http 127.0.0.1:7420 [--config aegis.toml] [--profile dev]
aegis tui [--wal path/to/aegis.wal]
aegis status [--json]
aegis reload
aegis clear-cache [--offline]
aegis check --config aegis.toml [--profile readonly] [--test-tool github__list_issues]
aegis test-redact --text "token=ghp_..."
aegis replay aegis.wal --mode diff --config aegis.toml --profile readonly
aegis replay aegis.wal --mode serve-stdio
aegis export aegis.wal --format otel --output trace.otel.json
aegis export aegis.wal --format jsonl
```

---

## License

Dual-licensed under **MIT** ([LICENSE-MIT](LICENSE-MIT)) or **Apache-2.0** ([LICENSE-APACHE](LICENSE-APACHE)), at your option.
