use aegis_core::{AegisError, CallOutcome, CallToolResult, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const WAL_MAGIC: &[u8; 8] = b"AEGSWAL\x01";
const FLAG_RAW: u8 = 0x00;
const FLAG_LZ4: u8 = 0x01;
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024; // 64 MiB safety cap

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub server: String,
    pub tool: String,
    pub namespaced_tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    pub outcome: CallOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CallToolResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub duration_ms: u64,
    pub cache_hit: bool,
    pub redaction_count: u64,
    #[serde(default)]
    pub redaction_categories: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WalReadStats {
    pub records_read: usize,
    pub corrupted_frames_skipped: usize,
    pub truncated_tail: bool,
}

/// Pure-Rust, crash-safe append-only binary Write-Ahead Log.
///
/// Frame layout:
/// `[u32 LE payload_len][u32 LE crc32][u8 flags][payload bytes]`
/// where `crc32` covers `[flags] || payload` and `payload` is MessagePack
/// (optionally LZ4-compressed via `lz4_flex`).
pub struct TraceWal {
    path: PathBuf,
    compress: bool,
    file: Mutex<File>,
}

impl TraceWal {
    pub fn open(path: impl AsRef<Path>, compress: bool) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;

        let len = file.metadata()?.len();
        if len == 0 {
            file.write_all(WAL_MAGIC)?;
            file.flush()?;
        } else {
            let mut magic = [0u8; 8];
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut magic).map_err(|e| {
                AegisError::Storage(format!("invalid WAL header in '{}': {e}", path.display()))
            })?;
            if &magic != WAL_MAGIC {
                return Err(AegisError::Storage(format!(
                    "unrecognized WAL magic in '{}'",
                    path.display()
                )));
            }
            file.seek(SeekFrom::End(0))?;
        }

        Ok(Self {
            path,
            compress,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, record: &TraceRecord) -> Result<()> {
        let encoded = rmp_serde::to_vec_named(record)
            .map_err(|e| AegisError::Storage(format!("msgpack encode error: {e}")))?;

        let (flags, payload) = if self.compress && encoded.len() >= 64 {
            let compressed = lz4_flex::compress_prepend_size(&encoded);
            if compressed.len() < encoded.len() {
                (FLAG_LZ4, compressed)
            } else {
                (FLAG_RAW, encoded)
            }
        } else {
            (FLAG_RAW, encoded)
        };

        let payload_len = u32::try_from(payload.len())
            .map_err(|_| AegisError::Storage("WAL frame exceeds u32 length".into()))?;

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&[flags]);
        hasher.update(&payload);
        let crc = hasher.finalize();

        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.push(flags);
        frame.extend_from_slice(&payload);

        let mut guard = self
            .file
            .lock()
            .map_err(|_| AegisError::Storage("WAL mutex poisoned".into()))?;
        guard.write_all(&frame)?;
        guard.flush()?;
        Ok(())
    }

    /// Reads all valid records from a WAL file, gracefully tolerating torn tail writes or corrupted frames.
    pub fn read_all(path: impl AsRef<Path>) -> Result<(Vec<TraceRecord>, WalReadStats)> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|e| {
            AegisError::Storage(format!("failed to open WAL '{}': {e}", path.display()))
        })?;
        let mut reader = BufReader::new(file);

        let mut magic = [0u8; 8];
        if let Err(e) = reader.read_exact(&mut magic) {
            return Err(AegisError::Storage(format!(
                "failed to read WAL header from '{}': {e}",
                path.display()
            )));
        }
        if &magic != WAL_MAGIC {
            return Err(AegisError::Storage(format!(
                "invalid WAL magic in '{}'",
                path.display()
            )));
        }

        let mut records = Vec::new();
        let mut stats = WalReadStats::default();

        loop {
            let mut header = [0u8; 9];
            match read_exact_or_eof(&mut reader, &mut header)? {
                ReadOutcome::Eof => break,
                ReadOutcome::Truncated => {
                    stats.truncated_tail = true;
                    break;
                }
                ReadOutcome::Full => {}
            }

            let payload_len =
                u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let expected_crc = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            let flags = header[8];

            if payload_len > MAX_FRAME_BYTES {
                stats.corrupted_frames_skipped += 1;
                stats.truncated_tail = true;
                break;
            }

            let mut payload = vec![0u8; payload_len];
            match read_exact_or_eof(&mut reader, &mut payload)? {
                ReadOutcome::Eof | ReadOutcome::Truncated => {
                    stats.truncated_tail = true;
                    break;
                }
                ReadOutcome::Full => {}
            }

            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&[flags]);
            hasher.update(&payload);
            let actual_crc = hasher.finalize();

            if actual_crc != expected_crc {
                stats.corrupted_frames_skipped += 1;
                continue;
            }

            let raw_msgpack = match flags {
                FLAG_RAW => payload,
                FLAG_LZ4 => match lz4_flex::decompress_size_prepended(&payload) {
                    Ok(buf) => buf,
                    Err(_) => {
                        stats.corrupted_frames_skipped += 1;
                        continue;
                    }
                },
                _ => {
                    stats.corrupted_frames_skipped += 1;
                    continue;
                }
            };

            match rmp_serde::from_slice::<TraceRecord>(&raw_msgpack) {
                Ok(rec) => {
                    records.push(rec);
                    stats.records_read += 1;
                }
                Err(_) => {
                    stats.corrupted_frames_skipped += 1;
                }
            }
        }

        Ok((records, stats))
    }
}

enum ReadOutcome {
    Full,
    Eof,
    Truncated,
}

fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => {
                return Ok(if filled == 0 {
                    ReadOutcome::Eof
                } else {
                    ReadOutcome::Truncated
                });
            }
            n => filled += n,
        }
    }
    Ok(ReadOutcome::Full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn sample_record(id: &str) -> TraceRecord {
        TraceRecord {
            id: id.to_string(),
            timestamp: Utc::now(),
            server: "github".to_string(),
            tool: "list_issues".to_string(),
            namespaced_tool: "github__list_issues".to_string(),
            arguments: Some(json!({"repo": "aegis-mcp/aegis", "state": "open"})),
            outcome: CallOutcome::Allowed,
            result: Some(CallToolResult::text("Issue #1: Initial release")),
            error_message: None,
            duration_ms: 42,
            cache_hit: false,
            redaction_count: 1,
            redaction_categories: BTreeMap::from([("github_token".to_string(), 1)]),
            policy_rule: Some("policy.default:allow".to_string()),
        }
    }

    #[test]
    fn roundtrips_and_recovers_from_torn_tail() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("trace.wal");
        let wal = TraceWal::open(&wal_path, true).unwrap();

        wal.append(&sample_record("rec-1")).unwrap();
        wal.append(&sample_record("rec-2")).unwrap();

        // Append torn garbage bytes simulating crash mid-write
        let mut raw = OpenOptions::new().append(true).open(&wal_path).unwrap();
        raw.write_all(&[0x40, 0x00, 0x00, 0x00, 0xde, 0xad]).unwrap();

        let (records, stats) = TraceWal::read_all(&wal_path).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, "rec-1");
        assert_eq!(records[1].id, "rec-2");
        assert_eq!(stats.records_read, 2);
        assert!(stats.truncated_tail);
    }
}
