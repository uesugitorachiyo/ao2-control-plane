//! Bounded in-memory ring buffer of recent HTTP requests, exposed by
//! the token-gated `GET /api/v1/audit-log` endpoint.
//!
//! Sibling to the structured `tracing::info!(target: "ao2_cp_server::access")`
//! middleware: the tracing event remains the durable on-disk record
//! (operator-controlled retention via `RUST_LOG` + log rotation), while
//! this buffer gives operators a queryable, in-process view of the most
//! recent N requests over HTTPS without having to grep stderr.
//!
//! # Trust boundary
//!
//! - The `Authorization` header value is **never** read or copied into
//!   an [`AuditEntry`]. Only its presence (`auth_attempted`) and the
//!   outcome (`status` ≠ 401 on `/api/v1/*` ⇒ `authenticated`) are
//!   recorded. The literal token bytes can therefore never appear in
//!   the audit-log response or in the [`tracing`] event.
//! - Request and response bodies are likewise never copied. Only the
//!   request line metadata (method, path, status, duration) is kept.
//! - The buffer is bounded by [`AuditLog::capacity`] (default 1024);
//!   appends past capacity evict the oldest entry. Memory use is
//!   strictly capped — there is no path by which a malicious client
//!   can force unbounded growth.
//!
//! # Concurrency
//!
//! The buffer is guarded by a single [`std::sync::Mutex`]. Critical
//! sections are short (one `VecDeque::push_back` + optional
//! `pop_front`) so contention is negligible at every realistic
//! traffic level the control plane is designed for. The mutex is
//! held only by synchronous code; no `.await` happens inside it.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// Broadcast channel capacity for the `/api/v1/audit-log/stream` SSE
/// surface. A slow subscriber that falls behind by this many entries
/// gets a `Lagged(n)` error on its next `recv`, signalling "you missed
/// `n` entries — fall back to polling `/api/v1/audit-log` if you need
/// the gap." Sized to absorb a sudden burst (~250 RPS for 1 s) without
/// dropping fast subscribers; not a substitute for the in-memory ring
/// buffer or the NDJSON persistence file, both of which remain the
/// durable surfaces.
const STREAM_BROADCAST_CAPACITY: usize = 256;

/// Default capacity used when no `AO2_CP_AUDIT_LOG_CAPACITY` override
/// is configured. Each entry is ~200 bytes including path heap data,
/// so 1024 entries ≈ 200 KiB resident — a comfortable default for a
/// long-running observer process.
pub const DEFAULT_AUDIT_LOG_CAPACITY: usize = 1024;

/// One recorded request. Fields mirror the structured access-log
/// tracing event one-to-one so an operator who has both surfaces open
/// sees the same data shape.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    /// Wall-clock microseconds since the Unix epoch when the request
    /// finished. Used by the `since_unix_micros` filter and for
    /// chronological ordering. Saturates at `u64::MAX` if the clock
    /// is far past 2554 AD (effectively never).
    pub timestamp_unix_micros: u64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_micros: u64,
    pub auth_attempted: bool,
    pub authenticated: bool,
}

/// Optional newline-delimited JSON persistence writer. Each successful
/// append writes one line — `{json}\n` — flushing the buffered writer
/// so the entry is visible to `tail -f` and survives a non-clean
/// process exit. A write error is recorded as `last_error`; subsequent
/// appends keep trying so a transient `ENOSPC` does not silently
/// disable persistence forever.
///
/// When `max_bytes` is set, the live file is rotated to a single
/// sidecar `<path>.1` once it grows past the threshold. There is no
/// time-based rotation, no compression, and only one historical
/// generation — operators who want richer retention pipe the live
/// file into their own log shipper. The `writer` is wrapped in
/// `Option` so the rotation path can drop the file handle before
/// renaming (required on Windows, where rename-over-open-file
/// fails).
#[derive(Debug)]
struct PersistenceState {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    last_error: Option<String>,
    /// `None` = rotation disabled. `Some(n)` = rotate to `<path>.1`
    /// once `bytes_written >= n`. Operators set this via
    /// `AO2_CP_AUDIT_LOG_MAX_BYTES`.
    max_bytes: Option<u64>,
    /// Running byte count of the *live* file. Seeded from the
    /// file's metadata at open (so restarting onto an existing file
    /// preserves the rotation cadence), then incremented by every
    /// successful line write. Reset to 0 on rotation.
    bytes_written: u64,
    /// Total successful rotations since boot. Exposed by `/status`
    /// + `/audit-log` so dashboards can spot abnormal churn.
    rotation_count: u64,
    /// Wall-clock micros of the most recent rotation, or `None`
    /// when the file has never rotated this process lifetime.
    last_rotated_unix_micros: Option<u64>,
}

/// Bounded ring buffer of [`AuditEntry`] values, oldest-first.
#[derive(Debug)]
pub struct AuditLog {
    capacity: usize,
    entries: Mutex<VecDeque<AuditEntry>>,
    persistence: Mutex<Option<PersistenceState>>,
    /// Monotonically increasing counter of every entry passed to
    /// [`AuditLog::append`] since boot — even when capacity is zero or
    /// the ring buffer has evicted the entry. Exposed by
    /// `/api/v1/status` as request-volume telemetry that survives
    /// ring-buffer rotation.
    total_appended: AtomicU64,
    /// Monotonically increasing counter of in-memory ring evictions —
    /// every append where the buffer was already at capacity bumps
    /// this counter. Surfaced as the `ao2_cp_audit_log_dropped_total`
    /// Prometheus counter so operators can alert when their configured
    /// `AO2_CP_AUDIT_LOG_CAPACITY` is too small for traffic.
    total_dropped: AtomicU64,
    /// Monotonically increasing counter of persistence write/rotation
    /// failures observed since boot. Surfaced as the
    /// `ao2_cp_audit_log_persistence_errors_total` Prometheus counter so
    /// operators can alert on the non-clearing `last_error` peek
    /// without polling `/api/v1/status` on a tight schedule.
    total_persistence_errors: AtomicU64,
    /// Broadcast sender that fans appended entries out to every live
    /// `/api/v1/audit-log/stream` subscriber. Lossy by design: a slow
    /// subscriber that can't drain the channel fast enough drops to
    /// `Lagged(n)` rather than blocking `append()`. The ring buffer
    /// and persistence file remain the authoritative durable surfaces.
    stream_tx: broadcast::Sender<AuditEntry>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(DEFAULT_AUDIT_LOG_CAPACITY)
    }
}

impl AuditLog {
    /// Construct an empty buffer with the given capacity.
    ///
    /// A capacity of zero is permitted (the buffer accepts appends but
    /// keeps no history), but is mostly useful for opt-out tests.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            persistence: Mutex::new(None),
            total_appended: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_persistence_errors: AtomicU64::new(0),
            stream_tx: broadcast::channel(STREAM_BROADCAST_CAPACITY).0,
        }
    }

    /// Construct a buffer that also mirrors each appended entry to a
    /// newline-delimited JSON file. The parent directory must exist;
    /// the file is opened in append-only mode (created if missing) so
    /// existing audit history is preserved across restart.
    pub fn with_persistence(capacity: usize, path: &Path) -> std::io::Result<Self> {
        let state = open_persistence(path, None)?;
        Ok(Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            persistence: Mutex::new(Some(state)),
            total_appended: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_persistence_errors: AtomicU64::new(0),
            stream_tx: broadcast::channel(STREAM_BROADCAST_CAPACITY).0,
        })
    }

    /// Same as [`AuditLog::with_persistence`] plus size-based rotation:
    /// once the live file grows past `max_bytes`, it is renamed to
    /// `<path>.1` (replacing any prior sidecar) and a fresh file is
    /// opened at `path`. Setting `max_bytes` to `0` is permitted and
    /// rotates after every single entry — useful only for tests.
    pub fn with_persistence_rotated(
        capacity: usize,
        path: &Path,
        max_bytes: u64,
    ) -> std::io::Result<Self> {
        let state = open_persistence(path, Some(max_bytes))?;
        Ok(Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
            persistence: Mutex::new(Some(state)),
            total_appended: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_persistence_errors: AtomicU64::new(0),
            stream_tx: broadcast::channel(STREAM_BROADCAST_CAPACITY).0,
        })
    }

    /// Lock the ring-buffer mutex, recovering from poisoning.
    ///
    /// A poisoned mutex means some *other* thread panicked while holding
    /// this lock. For this always-on read-only observer, propagating that
    /// panic (via `.expect()`) would convert a single upstream fault into
    /// a permanent outage of the audit-log/telemetry subsystem — every
    /// subsequent request that touches the buffer would panic too. The
    /// ring-buffer state remains structurally valid after a poison (it is
    /// a plain `VecDeque`), so we recover the guard with `into_inner()`
    /// and keep serving rather than cascading the failure.
    fn lock_entries(&self) -> MutexGuard<'_, VecDeque<AuditEntry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock the persistence-state mutex, recovering from poisoning.
    ///
    /// Same rationale as [`AuditLog::lock_entries`]: a poisoned
    /// persistence lock must not brick the persistence/telemetry surfaces
    /// of a long-running observer. The `Option<PersistenceState>` behind
    /// the lock stays usable after a poison, so recover and continue;
    /// per-write errors are already tracked via `last_error` /
    /// `total_persistence_errors`.
    fn lock_persistence(&self) -> MutexGuard<'_, Option<PersistenceState>> {
        self.persistence.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Path of the persistence file if persistence is enabled.
    pub fn persistence_path(&self) -> Option<PathBuf> {
        self.lock_persistence()
            .as_ref()
            .map(|state| state.path.clone())
    }

    /// Most recent persistence error (if any), suitable for surfacing
    /// in the structured tracing access log. Reading the value also
    /// clears it so repeated transient errors don't spam the surface.
    pub fn take_persistence_error(&self) -> Option<String> {
        self.lock_persistence()
            .as_mut()
            .and_then(|state| state.last_error.take())
    }

    /// Non-clearing peek at the most recent persistence error. Suitable
    /// for polled telemetry surfaces such as `/api/v1/status` that
    /// must report the same condition on every poll without consuming
    /// it.
    pub fn persistence_last_error(&self) -> Option<String> {
        self.lock_persistence()
            .as_ref()
            .and_then(|state| state.last_error.clone())
    }

    /// Configured rotation threshold in bytes, or `None` when
    /// `AO2_CP_AUDIT_LOG_MAX_BYTES` is unset and the live file grows
    /// without bound.
    pub fn rotation_max_bytes(&self) -> Option<u64> {
        self.lock_persistence()
            .as_ref()
            .and_then(|state| state.max_bytes)
    }

    /// Number of successful rotations since boot. `0` when rotation
    /// is disabled or when the threshold has never been reached.
    pub fn rotation_count(&self) -> u64 {
        self.lock_persistence()
            .as_ref()
            .map(|state| state.rotation_count)
            .unwrap_or(0)
    }

    /// Wall-clock micros of the most recent rotation, or `None` when
    /// no rotation has occurred this process lifetime.
    pub fn last_rotated_unix_micros(&self) -> Option<u64> {
        self.lock_persistence()
            .as_ref()
            .and_then(|state| state.last_rotated_unix_micros)
    }

    /// Append a new entry, evicting the oldest if the buffer is full.
    /// O(1) amortized. If persistence is enabled, the entry is also
    /// appended as a newline-delimited JSON line.
    pub fn append(&self, entry: AuditEntry) {
        if self.capacity > 0 {
            let mut guard = self.lock_entries();
            if guard.len() == self.capacity {
                guard.pop_front();
                // Drop-counter increments only when the ring evicted
                // a *real* prior entry to make room — capacity=0
                // appends do not bump it because there is no
                // historical entry being lost.
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
            }
            guard.push_back(entry.clone());
        }
        self.persist(&entry);
        // Counter increments AFTER successful append so the value
        // monotonically tracks observable request volume; an in-memory
        // ring eviction is still a successful append from the
        // operator's perspective.
        self.total_appended.fetch_add(1, Ordering::Relaxed);
        // Fire-and-forget broadcast to live SSE subscribers. send()
        // returns Err when there are no subscribers (the common case)
        // — we deliberately ignore that. The ring buffer + persistence
        // file are the durable record; the broadcast is best-effort
        // real-time fan-out.
        let _ = self.stream_tx.send(entry);
    }

    /// Subscribe to the live broadcast of newly-appended entries.
    /// Used by the `/api/v1/audit-log/stream` SSE handler; not part of
    /// the durable surface. Subscribers that fall behind by more than
    /// [`STREAM_BROADCAST_CAPACITY`] entries observe
    /// `RecvError::Lagged(n)` on their next `recv` and should fall
    /// back to `/api/v1/audit-log` polling for the gap.
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEntry> {
        self.stream_tx.subscribe()
    }

    /// Number of entries passed to [`AuditLog::append`] since boot.
    /// Continues to grow after the ring buffer has rotated, so a
    /// dashboard can correlate `/api/v1/audit-log`'s `total_buffered`
    /// (currently resident) with total request volume.
    pub fn total_appended_since_boot(&self) -> u64 {
        self.total_appended.load(Ordering::Relaxed)
    }

    /// Number of ring-buffer evictions since boot — i.e. appends that
    /// arrived when the buffer was already at capacity. Operators can
    /// alert on this counter to detect when `AO2_CP_AUDIT_LOG_CAPACITY`
    /// is undersized for sustained traffic.
    pub fn total_dropped_since_boot(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }

    /// Number of persistence write/serialize/rotation failures
    /// observed since boot. Pairs with the non-clearing
    /// `persistence_last_error()` peek: the peek shows the most
    /// recent error message; this counter says how often it has
    /// happened. Use it on the `ao2_cp_audit_log_persistence_errors_total`
    /// Prometheus counter to alert on silent persistence breakage.
    pub fn total_persistence_errors_since_boot(&self) -> u64 {
        self.total_persistence_errors.load(Ordering::Relaxed)
    }

    /// Running byte count of the live persistence file. Returns `0`
    /// when persistence is disabled. This is the same value that
    /// drives the rotation decision, so operators can alert on
    /// `file_bytes / max_bytes > 0.8` to catch a stuck rotation
    /// before it fires.
    pub fn persistence_file_bytes(&self) -> u64 {
        self.lock_persistence()
            .as_ref()
            .map(|state| state.bytes_written)
            .unwrap_or(0)
    }

    /// Wall-clock micros of the oldest entry currently resident in the
    /// ring buffer, or `None` when the buffer is empty. The oldest
    /// entry is at the front of the `VecDeque` because `append()` does
    /// `push_back` and `pop_front`.
    pub fn oldest_resident_unix_micros(&self) -> Option<u64> {
        self.lock_entries()
            .front()
            .map(|entry| entry.timestamp_unix_micros)
    }

    fn persist(&self, entry: &AuditEntry) {
        let mut guard = self.lock_persistence();
        let Some(state) = guard.as_mut() else {
            return;
        };
        let line = match serde_json::to_string(entry) {
            Ok(line) => line,
            Err(err) => {
                state.last_error = Some(format!("audit_log persist serialize failed: {err}"));
                self.total_persistence_errors
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        // `line.len() + 1` accounts for the trailing newline.
        let line_len = (line.len() as u64).saturating_add(1);
        let Some(writer) = state.writer.as_mut() else {
            // Should never happen — rotation always restores the writer
            // before returning. Record + skip rather than panic on the
            // request path.
            state.last_error =
                Some("audit_log persist writer absent (rotation invariant broken)".to_string());
            self.total_persistence_errors
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let result = writer
            .write_all(line.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush());
        match result {
            Ok(()) => {
                state.bytes_written = state.bytes_written.saturating_add(line_len);
                if let Some(max) = state.max_bytes {
                    if state.bytes_written >= max {
                        if let Err(err) = rotate_persistence(state) {
                            state.last_error = Some(format!("audit_log rotate failed: {err}"));
                            self.total_persistence_errors
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            Err(err) => {
                state.last_error = Some(format!("audit_log persist write failed: {err}"));
                self.total_persistence_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot the buffer into a newly-allocated `Vec`. Callers that
    /// want to filter / paginate are expected to do so on the snapshot
    /// rather than holding the lock across filter logic.
    pub fn snapshot(&self) -> Vec<AuditEntry> {
        let guard = self.lock_entries();
        guard.iter().cloned().collect()
    }

    /// Number of entries currently buffered (≤ capacity).
    pub fn len(&self) -> usize {
        self.lock_entries().len()
    }

    /// `true` iff there are zero buffered entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum entries the buffer will retain before evicting the
    /// oldest on each new append.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Open `path` for appending NDJSON. The current file length seeds
/// `bytes_written`, so the rotation cadence is preserved across
/// restart instead of being reset by every fresh process.
fn open_persistence(path: &Path, max_bytes: Option<u64>) -> std::io::Result<PersistenceState> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
    Ok(PersistenceState {
        path: path.to_path_buf(),
        writer: Some(BufWriter::new(file)),
        last_error: None,
        max_bytes,
        bytes_written,
        rotation_count: 0,
        last_rotated_unix_micros: None,
    })
}

/// Path of the rotated sidecar for a live persistence path. Always
/// `<path>.1` — there is only a single generation. Computed by
/// appending the literal suffix to the `OsString` so paths with
/// existing extensions (`audit.ndjson`) end up as `audit.ndjson.1`,
/// not `audit.1` (which `Path::with_extension` would do).
fn rotated_path_for(path: &Path) -> PathBuf {
    let mut buf = path.as_os_str().to_owned();
    buf.push(".1");
    PathBuf::from(buf)
}

/// Rotate the live persistence file: flush + close, replace any
/// existing `<path>.1`, rename live → `.1`, open a fresh live file.
/// The writer is briefly `None` between drop and reopen — the
/// surrounding mutex makes that invisible to concurrent appenders.
fn rotate_persistence(state: &mut PersistenceState) -> std::io::Result<()> {
    // Drop the BufWriter (and its inner File) before rename: on
    // Windows, rename-over-open-file fails with ERROR_SHARING_VIOLATION.
    if let Some(mut w) = state.writer.take() {
        // Best-effort flush; failure here doesn't abort the rotation,
        // since the writer is being closed anyway and the data is
        // already in the page cache after the per-append flush().
        let _ = w.flush();
        drop(w);
    }
    let rotated = rotated_path_for(&state.path);
    // Replace any prior sidecar. On Unix `rename` would overwrite
    // silently; on Windows it would fail without the explicit remove.
    let _ = std::fs::remove_file(&rotated);
    std::fs::rename(&state.path, &rotated)?;

    let fresh = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state.path)?;
    state.writer = Some(BufWriter::new(fresh));
    state.bytes_written = 0;
    state.rotation_count = state.rotation_count.saturating_add(1);
    state.last_rotated_unix_micros = Some(now_unix_micros());
    Ok(())
}

/// Capture the current wall-clock time as microseconds since the Unix
/// epoch. Used by the middleware that calls [`AuditLog::append`] and
/// re-exported for tests that want to write deterministic fixtures.
pub fn now_unix_micros() -> u64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(dur.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(method: &str, status: u16) -> AuditEntry {
        AuditEntry {
            timestamp_unix_micros: now_unix_micros(),
            method: method.to_string(),
            path: "/api/v1/x".to_string(),
            status,
            duration_micros: 1_000,
            auth_attempted: true,
            authenticated: status != 401,
        }
    }

    #[test]
    fn appends_until_capacity_then_evicts_oldest() {
        let log = AuditLog::new(3);
        log.append(sample("GET", 200));
        log.append(sample("GET", 201));
        log.append(sample("GET", 202));
        log.append(sample("GET", 203));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].status, 201);
        assert_eq!(snap[1].status, 202);
        assert_eq!(snap[2].status, 203);
    }

    #[test]
    fn zero_capacity_keeps_nothing() {
        let log = AuditLog::new(0);
        log.append(sample("GET", 200));
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        assert!(log.snapshot().is_empty());
    }

    #[test]
    fn default_capacity_is_1024() {
        assert_eq!(AuditLog::default().capacity(), DEFAULT_AUDIT_LOG_CAPACITY);
    }

    #[test]
    fn persistence_writes_ndjson_one_line_per_entry() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence(8, tmp.path()).expect("open persistence file");
        log.append(sample("GET", 200));
        log.append(sample("POST", 201));
        let on_disk = std::fs::read_to_string(tmp.path()).expect("read back persistence");
        let lines: Vec<&str> = on_disk.lines().collect();
        assert_eq!(lines.len(), 2, "expected one line per appended entry");
        for line in &lines {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("each line parses as JSON");
        }
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["method"], "GET");
        assert_eq!(first["status"], 200);
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["method"], "POST");
        assert_eq!(second["status"], 201);
        assert!(log.persistence_path().is_some());
        assert!(log.take_persistence_error().is_none());
    }

    #[test]
    fn persistence_appends_across_restart_without_truncation() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let log = AuditLog::with_persistence(4, tmp.path()).unwrap();
            log.append(sample("GET", 200));
        }
        {
            let log = AuditLog::with_persistence(4, tmp.path()).unwrap();
            log.append(sample("GET", 204));
        }
        let on_disk = std::fs::read_to_string(tmp.path()).unwrap();
        let lines: Vec<&str> = on_disk.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "second AuditLog must append to existing file, not truncate"
        );
    }

    #[test]
    fn persistence_open_fails_when_parent_dir_missing() {
        let nowhere = std::path::Path::new("/nonexistent-ao2-cp-audit-dir/audit.ndjson");
        let result = AuditLog::with_persistence(4, nowhere);
        assert!(
            result.is_err(),
            "open should fail when parent dir is missing"
        );
    }

    #[test]
    fn total_appended_counts_every_append_even_after_eviction() {
        let log = AuditLog::new(3);
        for _ in 0..7 {
            log.append(sample("GET", 200));
        }
        assert_eq!(log.len(), 3, "ring buffer is bounded to capacity");
        assert_eq!(
            log.total_appended_since_boot(),
            7,
            "counter must survive ring-buffer eviction"
        );
    }

    #[test]
    fn total_appended_counts_zero_capacity_appends() {
        let log = AuditLog::new(0);
        for _ in 0..5 {
            log.append(sample("GET", 200));
        }
        assert_eq!(log.len(), 0);
        assert_eq!(
            log.total_appended_since_boot(),
            5,
            "counter must increment even when capacity is zero"
        );
    }

    #[test]
    fn persistence_last_error_is_non_clearing() {
        // Construct a buffer with a fabricated last_error to exercise
        // the polled-peek semantics. Using `with_persistence` to set
        // up the state, then directly poking last_error via a helper
        // that mirrors what a real write failure would do.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence(4, tmp.path()).unwrap();
        {
            let mut guard = log.persistence.lock().unwrap();
            let state = guard.as_mut().unwrap();
            state.last_error = Some("simulated ENOSPC".to_string());
        }
        assert_eq!(
            log.persistence_last_error().as_deref(),
            Some("simulated ENOSPC")
        );
        assert_eq!(
            log.persistence_last_error().as_deref(),
            Some("simulated ENOSPC"),
            "peek must NOT clear the stored error"
        );
        let taken = log.take_persistence_error();
        assert_eq!(taken.as_deref(), Some("simulated ENOSPC"));
        assert_eq!(
            log.persistence_last_error(),
            None,
            "after take, peek returns None"
        );
    }

    #[test]
    fn append_with_zero_capacity_still_persists_to_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence(0, tmp.path()).unwrap();
        log.append(sample("GET", 200));
        assert!(log.is_empty(), "ring buffer holds nothing at capacity 0");
        let on_disk = std::fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(
            on_disk.lines().count(),
            1,
            "persistence is independent of ring buffer capacity"
        );
    }

    #[test]
    fn rotation_disabled_without_max_bytes_grows_unbounded() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence(8, tmp.path()).unwrap();
        for _ in 0..50 {
            log.append(sample("GET", 200));
        }
        assert_eq!(log.rotation_count(), 0);
        assert!(log.last_rotated_unix_micros().is_none());
        assert!(log.rotation_max_bytes().is_none());
        let sidecar = rotated_path_for(tmp.path());
        assert!(
            !sidecar.exists(),
            "no sidecar must appear when rotation is disabled"
        );
    }

    #[test]
    fn rotation_creates_sidecar_when_size_exceeded() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // ~150-200 bytes/entry. A 1_000-byte threshold lets us write
        // 1-2 entries pre-rotation, then watch rotation fire while
        // still observing post-rotation entries land in the fresh
        // live file before its threshold trips again.
        let log = AuditLog::with_persistence_rotated(8, tmp.path(), 1_000).unwrap();
        // Drive entries until the first rotation happens.
        for _ in 0..20 {
            log.append(sample("GET", 200));
            if log.rotation_count() == 1 {
                break;
            }
        }
        assert_eq!(
            log.rotation_count(),
            1,
            "exactly one rotation should have fired within 20 entries"
        );
        let sidecar = rotated_path_for(tmp.path());
        assert!(
            sidecar.exists(),
            "sidecar must exist after rotation threshold trips"
        );
        let sidecar_lines = std::fs::read_to_string(&sidecar).unwrap();
        let sidecar_count = sidecar_lines.lines().count();
        assert!(
            sidecar_count >= 1,
            "sidecar must hold the rotated-away entries (got {sidecar_count})"
        );
        // Post-rotation, the live file is fresh. Single additional
        // append must land in the live file, not the sidecar.
        log.append(sample("POST", 201));
        let live = std::fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(
            live.lines().count(),
            1,
            "live file holds only the single post-rotation entry"
        );
        let post_first: serde_json::Value =
            serde_json::from_str(live.lines().next().unwrap()).expect("live entry parses as JSON");
        assert_eq!(post_first["method"], "POST");
        std::fs::remove_file(&sidecar).ok();
    }

    #[test]
    fn rotation_replaces_existing_sidecar() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence_rotated(8, tmp.path(), 1).unwrap();
        log.append(sample("GET", 200));
        let sidecar = rotated_path_for(tmp.path());
        let first_sidecar = std::fs::read_to_string(&sidecar).unwrap();
        assert!(first_sidecar.contains("\"status\":200"));

        // Second oversize append: live file (which now holds nothing
        // because we cleared it post-rotation) — actually the rotate
        // trips on the *next* append's write, so we need two more.
        log.append(sample("POST", 201));
        let sidecar_after = std::fs::read_to_string(&sidecar).unwrap();
        assert!(
            !sidecar_after.contains("\"status\":200"),
            "old sidecar entry must be overwritten by the next rotation"
        );
        assert!(sidecar_after.contains("\"status\":201"));
        // The sidecar path is unique — we never accumulate `.2`, `.3`,
        // etc. Walk the parent directory to confirm.
        let parent = tmp.path().parent().unwrap();
        let live_name = tmp.path().file_name().unwrap().to_owned();
        let mut suffixed_count = 0usize;
        for entry in std::fs::read_dir(parent).unwrap().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            let live = live_name.to_string_lossy();
            if s.starts_with(live.as_ref()) && s != live {
                suffixed_count += 1;
            }
        }
        assert_eq!(
            suffixed_count, 1,
            "only one sidecar generation must exist on disk"
        );
        std::fs::remove_file(&sidecar).ok();
    }

    #[test]
    fn rotation_counter_and_timestamp_increment_together() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence_rotated(4, tmp.path(), 1).unwrap();
        let t0 = now_unix_micros();
        log.append(sample("GET", 200));
        assert_eq!(log.rotation_count(), 1);
        let ts = log.last_rotated_unix_micros().expect("timestamp present");
        assert!(
            ts >= t0,
            "last_rotated_unix_micros must be >= the moment before the append"
        );
        log.append(sample("GET", 200));
        assert_eq!(log.rotation_count(), 2);
        let sidecar = rotated_path_for(tmp.path());
        std::fs::remove_file(&sidecar).ok();
    }

    #[test]
    fn total_dropped_counts_ring_buffer_evictions_only() {
        let log = AuditLog::new(3);
        // First 3 appends fill the ring with no evictions.
        for _ in 0..3 {
            log.append(sample("GET", 200));
        }
        assert_eq!(log.total_dropped_since_boot(), 0);
        // Next 4 appends each evict one prior entry.
        for _ in 0..4 {
            log.append(sample("GET", 200));
        }
        assert_eq!(
            log.total_dropped_since_boot(),
            4,
            "one drop per overflow append after capacity is reached"
        );
    }

    #[test]
    fn total_dropped_stays_zero_for_zero_capacity() {
        let log = AuditLog::new(0);
        for _ in 0..5 {
            log.append(sample("GET", 200));
        }
        // Capacity=0 appends have no historical entry to lose, so the
        // drop counter stays zero even as total_appended grows. The
        // counter measures "real evictions of prior entries", not
        // "appends that didn't end up resident".
        assert_eq!(log.total_dropped_since_boot(), 0);
        assert_eq!(log.total_appended_since_boot(), 5);
    }

    #[test]
    fn total_persistence_errors_zero_on_clean_writes() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence(4, tmp.path()).unwrap();
        for _ in 0..3 {
            log.append(sample("GET", 200));
        }
        assert_eq!(log.total_persistence_errors_since_boot(), 0);
    }

    #[test]
    fn persistence_file_bytes_returns_zero_when_disabled() {
        let log = AuditLog::new(4);
        log.append(sample("GET", 200));
        assert_eq!(log.persistence_file_bytes(), 0);
    }

    #[test]
    fn persistence_file_bytes_grows_with_appends() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence(4, tmp.path()).unwrap();
        let after_open = log.persistence_file_bytes();
        log.append(sample("GET", 200));
        let after_one = log.persistence_file_bytes();
        assert!(
            after_one > after_open,
            "file_bytes must grow after a successful append (was {after_open}, now {after_one})"
        );
        log.append(sample("GET", 200));
        let after_two = log.persistence_file_bytes();
        assert!(
            after_two > after_one,
            "file_bytes must keep growing across appends (was {after_one}, now {after_two})"
        );
    }

    #[test]
    fn oldest_resident_unix_micros_returns_none_when_empty() {
        let log = AuditLog::new(4);
        assert!(log.oldest_resident_unix_micros().is_none());
    }

    #[test]
    fn oldest_resident_unix_micros_returns_first_entry_after_appends() {
        let log = AuditLog::new(4);
        let first = sample("GET", 200);
        let first_ts = first.timestamp_unix_micros;
        log.append(first);
        // Mint a second entry with a later timestamp.
        let mut second = sample("GET", 201);
        second.timestamp_unix_micros = first_ts + 1_000_000;
        log.append(second);
        assert_eq!(log.oldest_resident_unix_micros(), Some(first_ts));
    }

    #[test]
    fn oldest_resident_unix_micros_updates_after_eviction() {
        let log = AuditLog::new(2);
        let first = sample("GET", 200);
        let first_ts = first.timestamp_unix_micros;
        log.append(first);
        let mut second = sample("GET", 201);
        second.timestamp_unix_micros = first_ts + 1_000_000;
        log.append(second);
        let mut third = sample("GET", 202);
        third.timestamp_unix_micros = first_ts + 2_000_000;
        log.append(third); // evicts the first
        assert_eq!(
            log.oldest_resident_unix_micros(),
            Some(first_ts + 1_000_000),
            "oldest must reflect the second entry after the first is evicted"
        );
    }

    #[test]
    fn rotation_threshold_preserved_across_reopen() {
        // Open with rotation, write enough to populate the live file
        // but NOT trip rotation, drop, reopen, append once more, and
        // assert the running byte count was carried over so the
        // rotation fires on the second open.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            // A single entry serialises to ~150-200 bytes; pick a
            // threshold above that so the first session writes
            // without rotating.
            let log = AuditLog::with_persistence_rotated(4, tmp.path(), 10_000).unwrap();
            log.append(sample("GET", 200));
            assert_eq!(log.rotation_count(), 0, "no rotation in session 1");
        }
        // Reopen with a tiny threshold; the existing file already has
        // bytes, so the next append should immediately rotate.
        let log = AuditLog::with_persistence_rotated(4, tmp.path(), 1).unwrap();
        log.append(sample("GET", 200));
        assert_eq!(log.rotation_count(), 1, "reopen carried over byte count");
        let sidecar = rotated_path_for(tmp.path());
        std::fs::remove_file(&sidecar).ok();
    }

    /// Poison the `entries` mutex by panicking while holding its guard,
    /// then assert every public reader/writer recovers instead of
    /// cascading the panic. This is the availability guarantee for an
    /// always-on observer: one upstream fault must not permanently brick
    /// the audit-log subsystem. (A panic line on stderr during this test
    /// is expected — it is the deliberately-induced poison.)
    #[test]
    fn recovers_from_poisoned_entries_mutex() {
        let log = AuditLog::new(4);
        log.append(sample("GET", 200));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = log.entries.lock().unwrap();
            panic!("simulated panic while holding entries lock");
        }));
        assert!(
            log.entries.is_poisoned(),
            "entries mutex must be poisoned after the panic"
        );
        // None of these may panic on the poisoned lock.
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
        assert_eq!(log.snapshot().len(), 1);
        assert!(log.oldest_resident_unix_micros().is_some());
        log.append(sample("POST", 201));
        assert_eq!(
            log.snapshot().len(),
            2,
            "append must keep working after poison recovery"
        );
    }

    /// Same guarantee for the `persistence` mutex: a poison must not take
    /// down the persistence/telemetry peek surfaces or the append path.
    #[test]
    fn recovers_from_poisoned_persistence_mutex() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let log = AuditLog::with_persistence(4, tmp.path()).unwrap();
        log.append(sample("GET", 200));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = log.persistence.lock().unwrap();
            panic!("simulated panic while holding persistence lock");
        }));
        assert!(
            log.persistence.is_poisoned(),
            "persistence mutex must be poisoned after the panic"
        );
        // Every persistence-touching surface must recover, not panic.
        assert!(log.persistence_path().is_some());
        assert!(log.persistence_last_error().is_none());
        assert_eq!(log.rotation_count(), 0);
        assert!(log.rotation_max_bytes().is_none());
        assert!(log.last_rotated_unix_micros().is_none());
        let _ = log.persistence_file_bytes();
        // append() calls persist() under the poisoned lock — must not panic.
        log.append(sample("POST", 201));
        assert!(log.take_persistence_error().is_none());
    }
}
