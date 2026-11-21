use aegis_core::{CallOutcome, GatewayStats};
use aegis_redact::RedactionReport;
use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

const MAX_LATENCY_SAMPLES: usize = 1024;

#[derive(Default)]
struct Counters {
    total_calls: u64,
    allowed_calls: u64,
    denied_calls: u64,
    error_calls: u64,
    cache_hits: u64,
    cache_misses: u64,
    total_redactions: u64,
    redactions_by_category: BTreeMap<String, u64>,
    latencies: VecDeque<u64>,
}

pub struct MetricsTracker {
    started_at: DateTime<Utc>,
    mode: String,
    inner: Mutex<Counters>,
}

impl MetricsTracker {
    pub fn new(mode: impl Into<String>) -> Self {
        Self {
            started_at: Utc::now(),
            mode: mode.into(),
            inner: Mutex::new(Counters::default()),
        }
    }

    pub fn record_call(
        &self,
        outcome: CallOutcome,
        duration_ms: u64,
        cache_checked: bool,
        cache_hit: bool,
        redactions: &RedactionReport,
    ) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        g.total_calls += 1;
        match outcome {
            CallOutcome::Allowed | CallOutcome::Cached => g.allowed_calls += 1,
            CallOutcome::Denied => g.denied_calls += 1,
            CallOutcome::Error => g.error_calls += 1,
        }
        if cache_checked {
            if cache_hit {
                g.cache_hits += 1;
            } else {
                g.cache_misses += 1;
            }
        }
        if redactions.total_redactions > 0 {
            g.total_redactions += redactions.total_redactions;
            for (cat, count) in &redactions.by_category {
                *g.redactions_by_category.entry(cat.clone()).or_insert(0) += *count;
            }
        }
        if g.latencies.len() >= MAX_LATENCY_SAMPLES {
            g.latencies.pop_front();
        }
        g.latencies.push_back(duration_ms);
    }

    pub fn snapshot(&self, active_servers: usize, total_tools: usize) -> GatewayStats {
        let now = Utc::now();
        let uptime_secs = now
            .signed_duration_since(self.started_at)
            .num_seconds()
            .max(0) as u64;

        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (avg_latency_ms, p95_latency_ms) = compute_latency_stats(&g.latencies);

        GatewayStats {
            started_at: self.started_at,
            mode: self.mode.clone(),
            uptime_secs,
            total_calls: g.total_calls,
            allowed_calls: g.allowed_calls,
            denied_calls: g.denied_calls,
            error_calls: g.error_calls,
            cache_hits: g.cache_hits,
            cache_misses: g.cache_misses,
            total_redactions: g.total_redactions,
            redactions_by_category: g.redactions_by_category.clone(),
            avg_latency_ms,
            p95_latency_ms,
            active_servers,
            total_tools,
        }
    }
}

fn compute_latency_stats(samples: &VecDeque<u64>) -> (f64, u64) {
    if samples.is_empty() {
        return (0.0, 0);
    }
    let sum: u64 = samples.iter().sum();
    let avg = sum as f64 / samples.len() as f64;

    let mut sorted: Vec<u64> = samples.iter().copied().collect();
    sorted.sort_unstable();
    let p95_idx = ((sorted.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    (avg, sorted[p95_idx])
}
