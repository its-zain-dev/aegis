use aegis_core::{
    AegisError, CallOutcome, GatewayStats, IpcRequest, IpcResponse, Result, ServerHealth,
    ServerState, TelemetryEvent, ToolCallEvent,
};
use aegis_store::TraceWal;
use aegis_transport::{IpcClient, IpcEndpoint};
use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;

const MAX_FEED_EVENTS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Feed = 0,
    Upstreams = 1,
    Security = 2,
    CachePerf = 3,
}

impl Tab {
    fn titles() -> Vec<&'static str> {
        vec![
            "1: Live Feed",
            "2: Upstreams",
            "3: Security",
            "4: Cache & Perf",
        ]
    }

    fn next(self) -> Self {
        match self {
            Tab::Feed => Tab::Upstreams,
            Tab::Upstreams => Tab::Security,
            Tab::Security => Tab::CachePerf,
            Tab::CachePerf => Tab::Feed,
        }
    }

    fn prev(self) -> Self {
        match self {
            Tab::Feed => Tab::CachePerf,
            Tab::Upstreams => Tab::Feed,
            Tab::Security => Tab::Upstreams,
            Tab::CachePerf => Tab::Security,
        }
    }
}

struct AppState {
    source_label: String,
    is_live: bool,
    connected: bool,
    active_tab: Tab,
    stats: GatewayStats,
    servers: Vec<ServerHealth>,
    events: VecDeque<ToolCallEvent>,
    selected_idx: usize,
    filter_mode: bool,
    filter_query: String,
    status_notice: String,
}

impl AppState {
    fn new(source_label: String, is_live: bool) -> Self {
        Self {
            source_label,
            is_live,
            connected: is_live,
            active_tab: Tab::Feed,
            stats: GatewayStats {
                started_at: Utc::now(),
                mode: if is_live { "live".into() } else { "wal".into() },
                uptime_secs: 0,
                total_calls: 0,
                allowed_calls: 0,
                denied_calls: 0,
                error_calls: 0,
                cache_hits: 0,
                cache_misses: 0,
                total_redactions: 0,
                redactions_by_category: BTreeMap::new(),
                avg_latency_ms: 0.0,
                p95_latency_ms: 0,
                active_servers: 0,
                total_tools: 0,
            },
            servers: Vec::new(),
            events: VecDeque::with_capacity(MAX_FEED_EVENTS),
            selected_idx: 0,
            filter_mode: false,
            filter_query: String::new(),
            status_notice: "Ready. Press q to quit, Tab/1-4 to switch views.".into(),
        }
    }

    fn push_event(&mut self, ev: ToolCallEvent) {
        if self.events.len() >= MAX_FEED_EVENTS {
            self.events.pop_back();
        }
        self.events.push_front(ev);
    }

    fn filtered_events(&self) -> Vec<&ToolCallEvent> {
        let q = self.filter_query.to_ascii_lowercase();
        self.events
            .iter()
            .filter(|e| {
                if q.is_empty() {
                    return true;
                }
                e.namespaced_tool.to_ascii_lowercase().contains(&q)
                    || e.server.to_ascii_lowercase().contains(&q)
                    || e.outcome.to_string().to_ascii_lowercase().contains(&q)
            })
            .collect()
    }

    fn blocked_events(&self) -> Vec<&ToolCallEvent> {
        self.events
            .iter()
            .filter(|e| e.outcome == CallOutcome::Denied || e.redaction_count > 0)
            .collect()
    }

    fn apply_ipc_response(&mut self, resp: IpcResponse) {
        match resp {
            IpcResponse::Stats(s) => self.stats = s,
            IpcResponse::Servers(list) => self.servers = list,
            IpcResponse::Ack { message } => self.status_notice = format!("OK: {message}"),
            IpcResponse::Error { message } => self.status_notice = format!("ERR: {message}"),
            IpcResponse::Pong => {}
            IpcResponse::Event(ev) => match ev {
                TelemetryEvent::ToolCall(tc) => self.push_event(tc),
                TelemetryEvent::Stats(s) => self.stats = s,
                TelemetryEvent::ServerStatus(h) => {
                    if let Some(existing) = self.servers.iter_mut().find(|s| s.name == h.name) {
                        *existing = h;
                    } else {
                        self.servers.push(h);
                        self.servers.sort_by(|a, b| a.name.cmp(&b.name));
                    }
                }
                TelemetryEvent::Notice { level, message } => {
                    self.status_notice = format!("[{level}] {message}");
                }
            },
        }
    }
}

/// Launches the live TUI attached to a running Aegis gateway over IPC.
pub async fn run_live_tui(endpoint: IpcEndpoint) -> Result<()> {
    let mut client = IpcClient::connect(&endpoint).await?;
    client.send(&IpcRequest::Subscribe).await?;

    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Option<IpcResponse>>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<IpcRequest>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(cmd) = out_rx.recv() => {
                    if client.send(&cmd).await.is_err() {
                        let _ = in_tx.send(None);
                        break;
                    }
                }
                resp = client.next_response() => {
                    match resp {
                        Ok(Some(msg)) => {
                            if in_tx.send(Some(msg)).is_err() {
                                break;
                            }
                        }
                        Ok(None) | Err(_) => {
                            let _ = in_tx.send(None);
                            break;
                        }
                    }
                }
            }
        }
    });

    let mut app = AppState::new(endpoint.to_string(), true);
    run_tui_loop(&mut app, Some(&mut in_rx), Some(&out_tx))
}

/// Launches an offline TUI inspecting a recorded `.wal` trace file.
pub fn run_wal_tui(wal_path: &Path) -> Result<()> {
    let (records, wal_stats) = TraceWal::read_all(wal_path)?;
    let mut app = AppState::new(wal_path.display().to_string(), false);

    let mut latencies = Vec::with_capacity(records.len());
    for rec in records {
        app.stats.total_calls += 1;
        match rec.outcome {
            CallOutcome::Allowed => {
                app.stats.allowed_calls += 1;
                app.stats.cache_misses += 1;
            }
            CallOutcome::Cached => {
                app.stats.allowed_calls += 1;
                app.stats.cache_hits += 1;
            }
            CallOutcome::Denied => app.stats.denied_calls += 1,
            CallOutcome::Error => app.stats.error_calls += 1,
        }
        app.stats.total_redactions += rec.redaction_count;
        for (k, v) in &rec.redaction_categories {
            *app.stats
                .redactions_by_category
                .entry(k.clone())
                .or_insert(0) += *v;
        }
        latencies.push(rec.duration_ms);

        app.push_event(ToolCallEvent {
            id: rec.id,
            timestamp: rec.timestamp,
            server: rec.server,
            tool: rec.tool,
            namespaced_tool: rec.namespaced_tool,
            outcome: rec.outcome,
            duration_ms: rec.duration_ms,
            cache_hit: rec.cache_hit,
            redaction_count: rec.redaction_count,
            redaction_categories: rec.redaction_categories,
            error_message: rec.error_message,
            args_preview: rec.arguments.map(|v| v.to_string()),
            result_preview: rec
                .result
                .and_then(|r| serde_json::to_string(&r.content).ok()),
        });
    }

    if !latencies.is_empty() {
        let sum: u64 = latencies.iter().sum();
        app.stats.avg_latency_ms = sum as f64 / latencies.len() as f64;
        latencies.sort_unstable();
        let idx = ((latencies.len() as f64 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(latencies.len() - 1);
        app.stats.p95_latency_ms = latencies[idx];
    }

    app.status_notice = format!(
        "Loaded {} records from WAL (skipped: {}, truncated_tail: {})",
        wal_stats.records_read, wal_stats.corrupted_frames_skipped, wal_stats.truncated_tail
    );

    run_tui_loop(&mut app, None, None)
}

fn run_tui_loop(
    app: &mut AppState,
    mut in_rx: Option<&mut mpsc::UnboundedReceiver<Option<IpcResponse>>>,
    out_tx: Option<&mpsc::UnboundedSender<IpcRequest>>,
) -> Result<()> {
    enable_raw_mode().map_err(|e| AegisError::Io(io::Error::other(e)))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = loop {
        // Drain all queued IPC messages without blocking UI frames
        if let Some(rx) = in_rx.as_deref_mut() {
            while let Ok(item) = rx.try_recv() {
                match item {
                    Some(resp) => app.apply_ipc_response(resp),
                    None => {
                        app.connected = false;
                        app.status_notice =
                            "Disconnected from Aegis gateway IPC. Press q to exit.".into();
                    }
                }
            }
        }

        if let Err(e) = terminal.draw(|f| draw_ui(f, app)) {
            break Err(AegisError::Io(e));
        }

        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if app.filter_mode {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => app.filter_mode = false,
                        KeyCode::Backspace => {
                            app.filter_query.pop();
                            app.selected_idx = 0;
                        }
                        KeyCode::Char(c) => {
                            app.filter_query.push(c);
                            app.selected_idx = 0;
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => break Ok(()),
                    KeyCode::Tab => app.active_tab = app.active_tab.next(),
                    KeyCode::BackTab => app.active_tab = app.active_tab.prev(),
                    KeyCode::Char('1') => app.active_tab = Tab::Feed,
                    KeyCode::Char('2') => app.active_tab = Tab::Upstreams,
                    KeyCode::Char('3') => app.active_tab = Tab::Security,
                    KeyCode::Char('4') => app.active_tab = Tab::CachePerf,
                    KeyCode::Char('/') => {
                        app.filter_mode = true;
                        app.active_tab = Tab::Feed;
                    }
                    KeyCode::Esc => {
                        app.filter_query.clear();
                        app.selected_idx = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let len = app.filtered_events().len();
                        if len > 0 && app.selected_idx + 1 < len {
                            app.selected_idx += 1;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.selected_idx = app.selected_idx.saturating_sub(1);
                    }
                    KeyCode::Char('r') => {
                        if let Some(tx) = out_tx {
                            let _ = tx.send(IpcRequest::Reload);
                            app.status_notice = "Sent reload command to gateway...".into();
                        }
                    }
                    KeyCode::Char('c') => {
                        if let Some(tx) = out_tx {
                            let _ = tx.send(IpcRequest::ClearCache);
                            app.status_notice = "Sent clear-cache command to gateway...".into();
                        }
                    }
                    _ => {}
                }
            }
        }
    };

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    res
}

fn draw_ui(frame: &mut Frame<'_>, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // KPI Header
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Main Content
            Constraint::Length(2), // Footer / Notice
        ])
        .split(frame.area());

    draw_header(frame, chunks[0], app);
    draw_tabs(frame, chunks[1], app);

    match app.active_tab {
        Tab::Feed => draw_feed_tab(frame, chunks[2], app),
        Tab::Upstreams => draw_upstreams_tab(frame, chunks[2], app),
        Tab::Security => draw_security_tab(frame, chunks[2], app),
        Tab::CachePerf => draw_cache_perf_tab(frame, chunks[2], app),
    }

    draw_footer(frame, chunks[3], app);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let status_span = if !app.is_live {
        Span::styled(" OFFLINE WAL ", Style::default().fg(Color::Black).bg(Color::Cyan))
    } else if app.connected {
        Span::styled(" LIVE ", Style::default().fg(Color::Black).bg(Color::Green))
    } else {
        Span::styled(" DISCONNECTED ", Style::default().fg(Color::White).bg(Color::Red))
    };

    let s = &app.stats;
    let cache_total = s.cache_hits + s.cache_misses;
    let hit_pct = if cache_total > 0 {
        (s.cache_hits as f64 / cache_total as f64) * 100.0
    } else {
        0.0
    };

    let line = Line::from(vec![
        Span::styled(
            " AEGIS v0.9 ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        status_span,
        Span::raw(format!(
            "  Calls: {}  |  Blocked: {}  |  Redacted: {}  |  Cache Hit: {:.0}%  |  p95: {}ms  |  Servers: {}  |  Tools: {}",
            s.total_calls,
            s.denied_calls,
            s.total_redactions,
            hit_pct,
            s.p95_latency_ms,
            s.active_servers,
            s.total_tools
        )),
    ]);

    let p = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Source: {} ", app.source_label)),
    );
    frame.render_widget(p, area);
}

fn draw_tabs(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let titles: Vec<Line<'_>> = Tab::titles()
        .into_iter()
        .map(|t| Line::from(Span::raw(t)))
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.active_tab as usize)
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, area);
}

fn draw_feed_tab(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    let filtered = app.filtered_events();
    let selected = app.selected_idx.min(filtered.len().saturating_sub(1));

    let rows: Vec<Row<'_>> = filtered
        .iter()
        .enumerate()
        .map(|(idx, ev)| {
            let outcome_style = match ev.outcome {
                CallOutcome::Allowed => Style::default().fg(Color::Green),
                CallOutcome::Cached => Style::default().fg(Color::Cyan),
                CallOutcome::Denied => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                CallOutcome::Error => Style::default().fg(Color::Yellow),
            };
            let row_style = if idx == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(ev.timestamp.format("%H:%M:%S").to_string()),
                Cell::from(ev.outcome.to_string()).style(outcome_style),
                Cell::from(ev.server.clone()),
                Cell::from(ev.tool.clone()),
                Cell::from(format!("{}ms", ev.duration_ms)),
                Cell::from(if ev.redaction_count > 0 {
                    format!("{} masked", ev.redaction_count)
                } else {
                    "-".into()
                }),
            ])
            .style(row_style)
        })
        .collect();

    let title = if app.filter_mode {
        format!(" Tool Calls [filter: {}_] ", app.filter_query)
    } else if !app.filter_query.is_empty() {
        format!(" Tool Calls [filter: '{}' (Esc to clear)] ", app.filter_query)
    } else {
        " Tool Calls (j/k navigate, / filter) ".to_string()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(14),
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec![
            "Time", "Status", "Server", "Tool", "Latency", "Redacted",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, split[0]);

    // Inspector pane for selected call
    let detail_text = if let Some(ev) = filtered.get(selected) {
        let mut lines = vec![
            Line::from(format!(
                "Call: {}  |  Outcome: {}  |  Duration: {}ms  |  Cache Hit: {}",
                ev.namespaced_tool, ev.outcome, ev.duration_ms, ev.cache_hit
            )),
            Line::from(format!(
                "Args: {}",
                ev.args_preview.as_deref().unwrap_or("<none>")
            )),
        ];
        if let Some(err) = &ev.error_message {
            lines.push(Line::from(Span::styled(
                format!("Error/Reason: {err}"),
                Style::default().fg(Color::Red),
            )));
        }
        if let Some(res) = &ev.result_preview {
            lines.push(Line::from(format!("Result: {res}")));
        }
        if !ev.redaction_categories.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("Redactions: {:?}", ev.redaction_categories),
                Style::default().fg(Color::Magenta),
            )));
        }
        lines
    } else {
        vec![Line::from(
            "Waiting for MCP tool calls... Connect Antigravity CLI or any MCP client to Aegis.",
        )]
    };

    let inspector = Paragraph::new(detail_text)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(" Inspector "));
    frame.render_widget(inspector, split[1]);
}

fn draw_upstreams_tab(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let rows: Vec<Row<'_>> = app
        .servers
        .iter()
        .map(|srv| {
            let state_style = match srv.state {
                ServerState::Ready => Style::default().fg(Color::Green),
                ServerState::Degraded => Style::default().fg(Color::Red),
                ServerState::Connecting => Style::default().fg(Color::Yellow),
                _ => Style::default().fg(Color::Gray),
            };
            Row::new(vec![
                Cell::from(srv.name.clone()),
                Cell::from(srv.transport.to_string()),
                Cell::from(srv.state.to_string()).style(state_style),
                Cell::from(srv.tool_count.to_string()),
                Cell::from(srv.total_calls.to_string()),
                Cell::from(srv.error_count.to_string()),
                Cell::from(srv.restart_count.to_string()),
                Cell::from(srv.last_error.clone().unwrap_or_else(|| "-".into())),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec![
            "Server",
            "Transport",
            "State",
            "Tools",
            "Calls",
            "Errors",
            "Restarts",
            "Last Error",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Upstream MCP Servers (press 'r' to reload) "),
    );
    frame.render_widget(table, area);
}

fn draw_security_tab(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    let sec_events = app.blocked_events();
    let rows: Vec<Row<'_>> = sec_events
        .iter()
        .map(|ev| {
            let action = if ev.outcome == CallOutcome::Denied {
                "BLOCKED".to_string()
            } else {
                format!("REDACTED ({})", ev.redaction_count)
            };
            let style = if ev.outcome == CallOutcome::Denied {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Magenta)
            };
            Row::new(vec![
                Cell::from(ev.timestamp.format("%H:%M:%S").to_string()),
                Cell::from(action).style(style),
                Cell::from(ev.namespaced_tool.clone()),
                Cell::from(
                    ev.error_message
                        .clone()
                        .unwrap_or_else(|| format!("{:?}", ev.redaction_categories)),
                ),
            ])
        })
        .collect();

    let left = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(15),
            Constraint::Length(24),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["Time", "Action", "Tool", "Details"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Blocked & Redacted Events "),
    );
    frame.render_widget(left, split[0]);

    let cat_rows: Vec<Row<'_>> = app
        .stats
        .redactions_by_category
        .iter()
        .map(|(cat, count)| Row::new(vec![Cell::from(cat.clone()), Cell::from(count.to_string())]))
        .collect();

    let right = Table::new(cat_rows, [Constraint::Min(16), Constraint::Length(10)])
        .header(
            Row::new(vec!["Secret Category", "Masked"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Redaction Breakdown "),
        );
    frame.render_widget(right, split[1]);
}

fn draw_cache_perf_tab(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let s = &app.stats;
    let total_cache_ops = s.cache_hits + s.cache_misses;
    let ratio = if total_cache_ops > 0 {
        (s.cache_hits as f64 / total_cache_ops as f64) * 100.0
    } else {
        0.0
    };

    let lines = vec![
        Line::from(format!("Gateway Mode      : {}", s.mode)),
        Line::from(format!("Uptime            : {}s", s.uptime_secs)),
        Line::from(format!("Total Tool Calls  : {}", s.total_calls)),
        Line::from(format!("  Allowed/Cached  : {}", s.allowed_calls)),
        Line::from(format!("  Policy Blocked  : {}", s.denied_calls)),
        Line::from(format!("  Upstream Errors : {}", s.error_calls)),
        Line::from(""),
        Line::from(format!("BLAKE3 Cache Hits : {}", s.cache_hits)),
        Line::from(format!("BLAKE3 Cache Miss : {}", s.cache_misses)),
        Line::from(format!("Cache Hit Ratio   : {:.1}%", ratio)),
        Line::from(""),
        Line::from(format!("Avg Latency       : {:.2} ms", s.avg_latency_ms)),
        Line::from(format!("P95 Latency       : {} ms", s.p95_latency_ms)),
        Line::from(""),
        Line::from("Tip: Press 'c' to flush the BLAKE3 disk cache, 'r' to reload upstreams."),
    ];

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" BLAKE3 Cache & Latency Telemetry "),
    );
    frame.render_widget(p, area);
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let text = Line::from(vec![
        Span::styled(
            " [q] Quit  [Tab/1-4] Views  [j/k] Select  [/] Filter  [r] Reload  [c] Clear Cache ",
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  |  "),
        Span::styled(&app.status_notice, Style::default().fg(Color::Cyan)),
    ]);
    frame.render_widget(Paragraph::new(text), area);
}
