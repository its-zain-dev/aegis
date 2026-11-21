use crate::canonical::cache_key;
use aegis_core::{AegisError, CacheConfig, CallToolResult, Result};
use aegis_policy::{compile_globs, matches_any, GlobPattern};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedBlob {
    created_at: DateTime<Utc>,
    ttl_secs: u64,
    server: String,
    tool: String,
    result: CallToolResult,
}

#[derive(Debug, Clone)]
struct IndexEntry {
    created_at: DateTime<Utc>,
    ttl_secs: u64,
    last_accessed: DateTime<Utc>,
}

/// Pure-Rust BLAKE3 content-addressed disk cache for idempotent MCP tool calls.
pub struct ToolCache {
    enabled: bool,
    dir: PathBuf,
    default_ttl_secs: u64,
    max_entries: usize,
    allow: Vec<GlobPattern>,
    deny: Vec<GlobPattern>,
    index: RwLock<HashMap<String, IndexEntry>>,
}

impl ToolCache {
    pub fn from_config(config: &CacheConfig) -> Result<Self> {
        let dir = config.resolved_dir();
        if config.enabled {
            fs::create_dir_all(&dir)?;
        }

        let mut index_map = HashMap::new();
        if config.enabled {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) != Some("aegc") {
                        continue;
                    }
                    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if let Ok(blob) = read_blob(&path) {
                        if !is_expired(blob.created_at, blob.ttl_secs) {
                            index_map.insert(
                                stem.to_string(),
                                IndexEntry {
                                    created_at: blob.created_at,
                                    ttl_secs: blob.ttl_secs,
                                    last_accessed: blob.created_at,
                                },
                            );
                        } else {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
            }
        }

        Ok(Self {
            enabled: config.enabled,
            dir,
            default_ttl_secs: config.default_ttl_secs,
            max_entries: config.max_entries.max(1),
            allow: compile_globs(&config.allow),
            deny: compile_globs(&config.deny),
            index: RwLock::new(index_map),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_cacheable(&self, _server: &str, raw_tool: &str, namespaced_tool: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if matches_any(&self.deny, namespaced_tool).is_some()
            || matches_any(&self.deny, raw_tool).is_some()
        {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        matches_any(&self.allow, namespaced_tool).is_some()
            || matches_any(&self.allow, raw_tool).is_some()
    }

    pub fn get(
        &self,
        server: &str,
        raw_tool: &str,
        namespaced_tool: &str,
        arguments: Option<&Value>,
    ) -> Option<CallToolResult> {
        if !self.is_cacheable(server, raw_tool, namespaced_tool) {
            return None;
        }
        let key = cache_key(server, raw_tool, arguments);

        let meta = {
            let guard = self.index.read().ok()?;
            guard.get(&key).cloned()
        }?;

        let path = self.entry_path(&key);
        if is_expired(meta.created_at, meta.ttl_secs) {
            if let Ok(mut guard) = self.index.write() {
                guard.remove(&key);
            }
            let _ = fs::remove_file(&path);
            return None;
        }

        match read_blob(&path) {
            Ok(blob) => {
                if is_expired(blob.created_at, blob.ttl_secs) {
                    if let Ok(mut guard) = self.index.write() {
                        guard.remove(&key);
                    }
                    let _ = fs::remove_file(&path);
                    return None;
                }
                if let Ok(mut guard) = self.index.write() {
                    if let Some(e) = guard.get_mut(&key) {
                        e.last_accessed = Utc::now();
                    }
                }
                Some(blob.result)
            }
            Err(_) => {
                if let Ok(mut guard) = self.index.write() {
                    guard.remove(&key);
                }
                None
            }
        }
    }

    pub fn put(
        &self,
        server: &str,
        raw_tool: &str,
        namespaced_tool: &str,
        arguments: Option<&Value>,
        result: &CallToolResult,
    ) -> Result<()> {
        if !self.is_cacheable(server, raw_tool, namespaced_tool) {
            return Ok(());
        }
        // Never cache error tool responses
        if result.is_error == Some(true) {
            return Ok(());
        }

        let key = cache_key(server, raw_tool, arguments);
        let now = Utc::now();
        let blob = CachedBlob {
            created_at: now,
            ttl_secs: self.default_ttl_secs,
            server: server.to_string(),
            tool: raw_tool.to_string(),
            result: result.clone(),
        };

        let encoded = rmp_serde::to_vec_named(&blob)
            .map_err(|e| AegisError::Storage(format!("cache encode failed: {e}")))?;
        let compressed = lz4_flex::compress_prepend_size(&encoded);

        let path = self.entry_path(&key);
        let tmp_path = self.dir.join(format!("{key}.tmp"));
        fs::write(&tmp_path, compressed)?;
        fs::rename(&tmp_path, &path)?;

        let mut guard = self
            .index
            .write()
            .map_err(|_| AegisError::Storage("cache lock poisoned".into()))?;
        guard.insert(
            key,
            IndexEntry {
                created_at: now,
                ttl_secs: self.default_ttl_secs,
                last_accessed: now,
            },
        );

        // Evict least-recently-used entries if over capacity
        if guard.len() > self.max_entries {
            let overflow = guard.len() - self.max_entries;
            let mut entries: Vec<(String, DateTime<Utc>)> = guard
                .iter()
                .map(|(k, v)| (k.clone(), v.last_accessed))
                .collect();
            entries.sort_by_key(|(_, ts)| *ts);
            for (old_key, _) in entries.into_iter().take(overflow) {
                guard.remove(&old_key);
                let _ = fs::remove_file(self.entry_path(&old_key));
            }
        }

        Ok(())
    }

    pub fn clear(&self) -> Result<usize> {
        let mut removed = 0usize;
        if let Ok(mut guard) = self.index.write() {
            removed = guard.len();
            guard.clear();
        }
        if self.dir.exists() {
            for entry in fs::read_dir(&self.dir)?.flatten() {
                let path = entry.path();
                if matches!(
                    path.extension().and_then(|e| e.to_str()),
                    Some("aegc") | Some("tmp")
                ) {
                    let _ = fs::remove_file(path);
                }
            }
        }
        Ok(removed)
    }

    pub fn entry_count(&self) -> usize {
        self.index.read().map(|g| g.len()).unwrap_or(0)
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.aegc"))
    }
}

fn read_blob(path: &Path) -> Result<CachedBlob> {
    let data = fs::read(path)?;
    let decompressed = lz4_flex::decompress_size_prepended(&data)
        .map_err(|e| AegisError::Storage(format!("cache lz4 decompress error: {e}")))?;
    rmp_serde::from_slice(&decompressed)
        .map_err(|e| AegisError::Storage(format!("cache msgpack decode error: {e}")))
}

fn is_expired(created_at: DateTime<Utc>, ttl_secs: u64) -> bool {
    if ttl_secs == 0 {
        return false;
    }
    let age = Utc::now().signed_duration_since(created_at).num_seconds();
    age >= ttl_secs as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn caches_and_reloads_from_disk() {
        let dir = tempdir().unwrap();
        let cfg = CacheConfig {
            enabled: true,
            dir: Some(dir.path().to_path_buf()),
            default_ttl_secs: 60,
            max_entries: 16,
            allow: vec!["*__list_*".to_string()],
            deny: vec!["*__list_secrets".to_string()],
        };

        let cache = ToolCache::from_config(&cfg).unwrap();
        let args1 = json!({"b": 2, "a": 1});
        let args2 = json!({"a": 1, "b": 2});
        let result = CallToolResult::text("cached payload");

        cache
            .put("github", "list_issues", "github__list_issues", Some(&args1), &result)
            .unwrap();

        // Different key order still hits BLAKE3 cache
        let hit = cache
            .get("github", "list_issues", "github__list_issues", Some(&args2))
            .unwrap();
        assert_eq!(hit.content, result.content);

        // Denied tool is not cached
        assert!(!cache.is_cacheable("github", "list_secrets", "github__list_secrets"));

        // Reload cache from disk
        let cache2 = ToolCache::from_config(&cfg).unwrap();
        assert_eq!(cache2.entry_count(), 1);
        assert!(cache2
            .get("github", "list_issues", "github__list_issues", Some(&args1))
            .is_some());

        assert_eq!(cache2.clear().unwrap(), 1);
        assert_eq!(cache2.entry_count(), 0);
    }
}
