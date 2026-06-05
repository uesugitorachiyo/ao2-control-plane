//! Prometheus exposition format for ao2-control-plane runtime metrics.
//!
//! The control plane emits a small, fixed-cardinality set of counters
//! and gauges suitable for production triage:
//!
//! * `ao2_cp_requests_total{method,status_class}` — total HTTP requests
//!   handled, partitioned by HTTP method and status class
//!   (`2xx` / `3xx` / `4xx` / `5xx`). Tracks the **traffic** and **errors**
//!   Golden Signals.
//! * `ao2_cp_request_duration_seconds_sum` — cumulative wall-clock seconds
//!   spent serving requests (sum). Pair with the count counter below to
//!   derive average latency.
//! * `ao2_cp_request_duration_seconds_count` — total finished requests
//!   counted toward the duration sum.
//! * `ao2_cp_in_flight_requests` — current number of in-flight requests
//!   (gauge implemented as an atomic counter; incremented on request entry,
//!   decremented in a guard). Tracks the **saturation** Golden Signal.
//! * `ao2_cp_storage_total_index_entries` — current count of index entries
//!   on disk, sampled from `Storage::index.read_all().len()` on each
//!   scrape. Tracks observer-evidence growth.
//! * `ao2_cp_audit_log_appended_total` — monotonic count of every entry
//!   appended to the audit-log ring buffer since boot. Mirrors the
//!   `audit_log.total_appended_since_boot` field on `/api/v1/status`.
//! * `ao2_cp_audit_log_rotated_total` — monotonic count of successful
//!   NDJSON file rotations since boot. Mirrors
//!   `audit_log.persistence.rotation.count`.
//! * `ao2_cp_audit_log_persistence_errors_total` — monotonic count of
//!   persistence write/serialize/rotation failures. Pairs with the
//!   non-clearing `persistence.last_error` peek so operators can alert
//!   on silent persistence breakage without polling `/api/v1/status`.
//! * `ao2_cp_audit_log_dropped_total` — monotonic count of ring-buffer
//!   evictions (appends that arrived when the buffer was already at
//!   capacity). Alert when this is non-zero in steady state to detect
//!   an undersized `AO2_CP_AUDIT_LOG_CAPACITY`.
//! * `ao2_cp_audit_log_file_bytes` — current byte size of the live
//!   NDJSON persistence file. `0` when persistence is disabled.
//!   Operators alert on `file_bytes / AO2_CP_AUDIT_LOG_MAX_BYTES > 0.8`
//!   to catch a stuck rotation before it fires (complements the
//!   reactive `_rotated_total` counter).
//! * `ao2_cp_audit_log_oldest_resident_age_seconds` — wall-clock age
//!   in seconds of the oldest entry currently resident in the ring
//!   buffer. `0` when the buffer is empty. Operators alert on the
//!   gauge falling below a target retention horizon to detect a
//!   buffer that's churning too fast for the configured
//!   `AO2_CP_AUDIT_LOG_CAPACITY`.
//!
//! All increments are lock-free atomic adds. The `/metrics` endpoint
//! itself is token-gated (same bearer as the rest of `/api/v1/*`); the
//! reverse-proxy templates allow Prometheus to authenticate via a scrape
//! config bearer token.

use chrono::{DateTime, TimeZone, Utc};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Atomic counter family for HTTP method × status-class metrics.
///
/// Cardinality is bounded at compile time: 5 methods × 4 status classes =
/// 20 atomics. Anything outside the enumerated set falls back to
/// `("other", "other")`.
#[derive(Debug, Default)]
struct RequestCounters {
    // GET
    get_2xx: AtomicU64,
    get_3xx: AtomicU64,
    get_4xx: AtomicU64,
    get_5xx: AtomicU64,
    // POST
    post_2xx: AtomicU64,
    post_3xx: AtomicU64,
    post_4xx: AtomicU64,
    post_5xx: AtomicU64,
    // PUT
    put_2xx: AtomicU64,
    put_3xx: AtomicU64,
    put_4xx: AtomicU64,
    put_5xx: AtomicU64,
    // DELETE
    delete_2xx: AtomicU64,
    delete_3xx: AtomicU64,
    delete_4xx: AtomicU64,
    delete_5xx: AtomicU64,
    // OTHER (HEAD, OPTIONS, PATCH, TRACE, CONNECT, unknown)
    other_2xx: AtomicU64,
    other_3xx: AtomicU64,
    other_4xx: AtomicU64,
    other_5xx: AtomicU64,
}

impl RequestCounters {
    fn record(&self, method: &str, status: u16) {
        let class = status_class(status);
        let counter = match (method, class) {
            ("GET", "2xx") => &self.get_2xx,
            ("GET", "3xx") => &self.get_3xx,
            ("GET", "4xx") => &self.get_4xx,
            ("GET", "5xx") => &self.get_5xx,
            ("POST", "2xx") => &self.post_2xx,
            ("POST", "3xx") => &self.post_3xx,
            ("POST", "4xx") => &self.post_4xx,
            ("POST", "5xx") => &self.post_5xx,
            ("PUT", "2xx") => &self.put_2xx,
            ("PUT", "3xx") => &self.put_3xx,
            ("PUT", "4xx") => &self.put_4xx,
            ("PUT", "5xx") => &self.put_5xx,
            ("DELETE", "2xx") => &self.delete_2xx,
            ("DELETE", "3xx") => &self.delete_3xx,
            ("DELETE", "4xx") => &self.delete_4xx,
            ("DELETE", "5xx") => &self.delete_5xx,
            (_, "2xx") => &self.other_2xx,
            (_, "3xx") => &self.other_3xx,
            (_, "4xx") => &self.other_4xx,
            (_, "5xx") => &self.other_5xx,
            // status_class always returns one of the four 1-character
            // strings above; this arm is unreachable but keeps the match
            // total without panic-on-bug.
            _ => &self.other_5xx,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Vec<(&'static str, &'static str, u64)> {
        vec![
            ("GET", "2xx", self.get_2xx.load(Ordering::Relaxed)),
            ("GET", "3xx", self.get_3xx.load(Ordering::Relaxed)),
            ("GET", "4xx", self.get_4xx.load(Ordering::Relaxed)),
            ("GET", "5xx", self.get_5xx.load(Ordering::Relaxed)),
            ("POST", "2xx", self.post_2xx.load(Ordering::Relaxed)),
            ("POST", "3xx", self.post_3xx.load(Ordering::Relaxed)),
            ("POST", "4xx", self.post_4xx.load(Ordering::Relaxed)),
            ("POST", "5xx", self.post_5xx.load(Ordering::Relaxed)),
            ("PUT", "2xx", self.put_2xx.load(Ordering::Relaxed)),
            ("PUT", "3xx", self.put_3xx.load(Ordering::Relaxed)),
            ("PUT", "4xx", self.put_4xx.load(Ordering::Relaxed)),
            ("PUT", "5xx", self.put_5xx.load(Ordering::Relaxed)),
            ("DELETE", "2xx", self.delete_2xx.load(Ordering::Relaxed)),
            ("DELETE", "3xx", self.delete_3xx.load(Ordering::Relaxed)),
            ("DELETE", "4xx", self.delete_4xx.load(Ordering::Relaxed)),
            ("DELETE", "5xx", self.delete_5xx.load(Ordering::Relaxed)),
            ("other", "2xx", self.other_2xx.load(Ordering::Relaxed)),
            ("other", "3xx", self.other_3xx.load(Ordering::Relaxed)),
            ("other", "4xx", self.other_4xx.load(Ordering::Relaxed)),
            ("other", "5xx", self.other_5xx.load(Ordering::Relaxed)),
        ]
    }
}

#[derive(Debug)]
pub struct Metrics {
    requests: RequestCounters,
    duration_micros_sum: AtomicU64,
    duration_count: AtomicU64,
    in_flight: AtomicU64,
    /// Wall-clock UTC start time as unix microseconds. Set once at
    /// `Metrics::new()` and never mutated. Paired with `started_at`
    /// (monotonic) for two views of process lifetime.
    started_at_unix_micros: i64,
    last_error_at_unix_micros: AtomicI64,
    started_at: Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests: RequestCounters::default(),
            duration_micros_sum: AtomicU64::new(0),
            duration_count: AtomicU64::new(0),
            in_flight: AtomicU64::new(0),
            started_at_unix_micros: Utc::now().timestamp_micros(),
            last_error_at_unix_micros: AtomicI64::new(0),
            started_at: Instant::now(),
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seconds since the metrics struct was constructed (proxy for
    /// process uptime, since `Metrics::new()` runs at server start).
    pub fn uptime_seconds(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64()
    }

    /// Wall-clock UTC time the process started.
    pub fn started_at_utc(&self) -> DateTime<Utc> {
        Utc.timestamp_micros(self.started_at_unix_micros)
            .single()
            .unwrap_or_else(Utc::now)
    }

    /// Most recent wall-clock UTC time a 4xx/5xx response was emitted.
    /// Returns `None` if no error has been recorded since process
    /// start. Updated lock-free on every error-class request.
    pub fn last_error_utc(&self) -> Option<DateTime<Utc>> {
        let micros = self.last_error_at_unix_micros.load(Ordering::Relaxed);
        if micros == 0 {
            None
        } else {
            Utc.timestamp_micros(micros).single()
        }
    }

    /// Snapshot of the error-class counter for the healthz-extended payload.
    pub fn error_request_count(&self) -> u64 {
        self.error_requests()
    }

    /// Total finished requests across all methods + status classes.
    pub fn total_requests(&self) -> u64 {
        self.requests
            .snapshot()
            .into_iter()
            .map(|(_, _, n)| n)
            .sum()
    }

    /// Sum of request error-class counters (4xx + 5xx) across methods.
    pub fn error_requests(&self) -> u64 {
        self.requests
            .snapshot()
            .into_iter()
            .filter(|(_, class, _)| *class == "4xx" || *class == "5xx")
            .map(|(_, _, n)| n)
            .sum()
    }

    /// Current in-flight request count (snapshot, not a live counter).
    pub fn in_flight_count(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Total wall-clock seconds spent serving finished requests.
    pub fn duration_sum_seconds(&self) -> f64 {
        self.duration_micros_sum.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    /// Increment in-flight, returning a guard that decrements on drop.
    pub fn track_in_flight(&self) -> InFlightGuard<'_> {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard {
            in_flight: &self.in_flight,
        }
    }

    /// Record a finished request. Status outside 100-599 is clamped into
    /// the `5xx` bucket so caller bugs never silently disappear.
    pub fn record_request(&self, method: &str, status: u16, duration: Duration) {
        self.requests.record(method, status);
        let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        self.duration_micros_sum
            .fetch_add(micros, Ordering::Relaxed);
        self.duration_count.fetch_add(1, Ordering::Relaxed);
        if (400..600).contains(&status) {
            // Record the latest error wall-clock time; relaxed store is
            // fine because we don't need monotonicity across concurrent errors.
            self.last_error_at_unix_micros
                .store(Utc::now().timestamp_micros(), Ordering::Relaxed);
        }
    }

    /// Render the Prometheus text exposition format (version 0.0.4).
    /// `storage_index_entries` is sampled from the live `Storage` and
    /// `audit_log` from the live `AuditLog` at scrape time. Both are
    /// embedded as gauges/counters in the same scrape body.
    pub fn render(&self, storage_index_entries: u64, audit_log: AuditLogSamples) -> String {
        let mut out = String::with_capacity(2048);
        out.push_str(
            "# HELP ao2_cp_requests_total Total HTTP requests handled by the control plane.\n",
        );
        out.push_str("# TYPE ao2_cp_requests_total counter\n");
        for (method, class, count) in self.requests.snapshot() {
            out.push_str(&format!(
                "ao2_cp_requests_total{{method=\"{method}\",status_class=\"{class}\"}} {count}\n"
            ));
        }
        out.push('\n');

        let sum_seconds = self.duration_micros_sum.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let count = self.duration_count.load(Ordering::Relaxed);
        out.push_str(
            "# HELP ao2_cp_request_duration_seconds_sum Cumulative seconds spent serving requests.\n",
        );
        out.push_str("# TYPE ao2_cp_request_duration_seconds_sum counter\n");
        out.push_str(&format!(
            "ao2_cp_request_duration_seconds_sum {sum_seconds}\n"
        ));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_request_duration_seconds_count Total requests counted toward the duration sum.\n",
        );
        out.push_str("# TYPE ao2_cp_request_duration_seconds_count counter\n");
        out.push_str(&format!("ao2_cp_request_duration_seconds_count {count}\n"));
        out.push('\n');

        let in_flight = self.in_flight.load(Ordering::Relaxed);
        out.push_str(
            "# HELP ao2_cp_in_flight_requests Current number of in-flight HTTP requests.\n",
        );
        out.push_str("# TYPE ao2_cp_in_flight_requests gauge\n");
        out.push_str(&format!("ao2_cp_in_flight_requests {in_flight}\n"));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_storage_total_index_entries Current count of index entries on disk.\n",
        );
        out.push_str("# TYPE ao2_cp_storage_total_index_entries gauge\n");
        out.push_str(&format!(
            "ao2_cp_storage_total_index_entries {storage_index_entries}\n"
        ));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_audit_log_appended_total Total audit-log entries appended since boot.\n",
        );
        out.push_str("# TYPE ao2_cp_audit_log_appended_total counter\n");
        out.push_str(&format!(
            "ao2_cp_audit_log_appended_total {}\n",
            audit_log.appended
        ));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_audit_log_rotated_total Total audit-log NDJSON file rotations since boot.\n",
        );
        out.push_str("# TYPE ao2_cp_audit_log_rotated_total counter\n");
        out.push_str(&format!(
            "ao2_cp_audit_log_rotated_total {}\n",
            audit_log.rotated
        ));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_audit_log_persistence_errors_total Total audit-log persistence write/rotation failures since boot.\n",
        );
        out.push_str("# TYPE ao2_cp_audit_log_persistence_errors_total counter\n");
        out.push_str(&format!(
            "ao2_cp_audit_log_persistence_errors_total {}\n",
            audit_log.persistence_errors
        ));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_audit_log_dropped_total Total audit-log ring-buffer evictions since boot.\n",
        );
        out.push_str("# TYPE ao2_cp_audit_log_dropped_total counter\n");
        out.push_str(&format!(
            "ao2_cp_audit_log_dropped_total {}\n",
            audit_log.dropped
        ));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_audit_log_file_bytes Current byte size of the live audit-log NDJSON persistence file (0 when persistence disabled).\n",
        );
        out.push_str("# TYPE ao2_cp_audit_log_file_bytes gauge\n");
        out.push_str(&format!(
            "ao2_cp_audit_log_file_bytes {}\n",
            audit_log.file_bytes
        ));
        out.push('\n');

        out.push_str(
            "# HELP ao2_cp_audit_log_oldest_resident_age_seconds Wall-clock age in seconds of the oldest entry currently resident in the ring buffer (0 when buffer empty).\n",
        );
        out.push_str("# TYPE ao2_cp_audit_log_oldest_resident_age_seconds gauge\n");
        out.push_str(&format!(
            "ao2_cp_audit_log_oldest_resident_age_seconds {}\n",
            audit_log.oldest_resident_age_seconds
        ));

        out
    }
}

/// Scrape-time snapshot of `AuditLog` counters and gauges for the
/// Prometheus exposition. The first four fields are monotonic
/// counters reset only at process restart; the latter two are
/// point-in-time gauges sampled at the moment of the scrape.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditLogSamples {
    /// Total entries appended to the audit-log ring buffer since boot.
    pub appended: u64,
    /// Total successful NDJSON file rotations since boot.
    pub rotated: u64,
    /// Total persistence write/serialize/rotation failures since boot.
    pub persistence_errors: u64,
    /// Total ring-buffer evictions (capacity-overflow appends) since boot.
    pub dropped: u64,
    /// Current byte size of the live NDJSON persistence file. `0` when
    /// persistence is disabled.
    pub file_bytes: u64,
    /// Wall-clock age in seconds of the oldest entry currently
    /// resident in the ring buffer. `0` when the buffer is empty.
    pub oldest_resident_age_seconds: f64,
}

pub struct InFlightGuard<'a> {
    in_flight: &'a AtomicU64,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Stopwatch helper for callers that prefer an explicit `start()`/`record()`
/// pair over re-deriving the duration in middleware.
pub fn start_request_timer() -> Instant {
    Instant::now()
}

fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "2xx", // 1xx is rare; bucket with 2xx for triage
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_record_known_method_and_status_class() {
        let m = Metrics::new();
        m.record_request("GET", 200, Duration::from_millis(5));
        m.record_request("GET", 404, Duration::from_millis(2));
        m.record_request("POST", 500, Duration::from_millis(10));
        m.record_request("PATCH", 200, Duration::from_millis(1));

        let body = m.render(7, AuditLogSamples::default());
        assert!(body.contains("ao2_cp_requests_total{method=\"GET\",status_class=\"2xx\"} 1"));
        assert!(body.contains("ao2_cp_requests_total{method=\"GET\",status_class=\"4xx\"} 1"));
        assert!(body.contains("ao2_cp_requests_total{method=\"POST\",status_class=\"5xx\"} 1"));
        assert!(body.contains("ao2_cp_requests_total{method=\"other\",status_class=\"2xx\"} 1"));
        assert!(body.contains("ao2_cp_request_duration_seconds_count 4"));
        assert!(body.contains("ao2_cp_storage_total_index_entries 7"));
    }

    #[test]
    fn in_flight_guard_increments_and_decrements() {
        let m = Metrics::new();
        let body0 = m.render(0, AuditLogSamples::default());
        assert!(body0.contains("ao2_cp_in_flight_requests 0"));
        let g = m.track_in_flight();
        let body1 = m.render(0, AuditLogSamples::default());
        assert!(body1.contains("ao2_cp_in_flight_requests 1"));
        drop(g);
        let body2 = m.render(0, AuditLogSamples::default());
        assert!(body2.contains("ao2_cp_in_flight_requests 0"));
    }

    #[test]
    fn duration_sum_accumulates_to_seconds() {
        let m = Metrics::new();
        m.record_request("GET", 200, Duration::from_millis(1500));
        let body = m.render(0, AuditLogSamples::default());
        // 1.5 seconds → "ao2_cp_request_duration_seconds_sum 1.5"
        assert!(body.contains("ao2_cp_request_duration_seconds_sum 1.5"));
    }

    #[test]
    fn audit_log_samples_render_as_counters() {
        let m = Metrics::new();
        let samples = AuditLogSamples {
            appended: 42,
            rotated: 3,
            persistence_errors: 1,
            dropped: 7,
            file_bytes: 8192,
            oldest_resident_age_seconds: 12.5,
        };
        let body = m.render(0, samples);
        assert!(body.contains("# TYPE ao2_cp_audit_log_appended_total counter"));
        assert!(body.contains("ao2_cp_audit_log_appended_total 42"));
        assert!(body.contains("# TYPE ao2_cp_audit_log_rotated_total counter"));
        assert!(body.contains("ao2_cp_audit_log_rotated_total 3"));
        assert!(body.contains("# TYPE ao2_cp_audit_log_persistence_errors_total counter"));
        assert!(body.contains("ao2_cp_audit_log_persistence_errors_total 1"));
        assert!(body.contains("# TYPE ao2_cp_audit_log_dropped_total counter"));
        assert!(body.contains("ao2_cp_audit_log_dropped_total 7"));
        assert!(body.contains("# TYPE ao2_cp_audit_log_file_bytes gauge"));
        assert!(body.contains("ao2_cp_audit_log_file_bytes 8192"));
        assert!(body.contains("# TYPE ao2_cp_audit_log_oldest_resident_age_seconds gauge"));
        assert!(body.contains("ao2_cp_audit_log_oldest_resident_age_seconds 12.5"));
    }

    #[test]
    fn audit_log_samples_default_to_zero() {
        let m = Metrics::new();
        let body = m.render(0, AuditLogSamples::default());
        assert!(body.contains("ao2_cp_audit_log_appended_total 0"));
        assert!(body.contains("ao2_cp_audit_log_rotated_total 0"));
        assert!(body.contains("ao2_cp_audit_log_persistence_errors_total 0"));
        assert!(body.contains("ao2_cp_audit_log_dropped_total 0"));
        assert!(body.contains("ao2_cp_audit_log_file_bytes 0"));
        assert!(body.contains("ao2_cp_audit_log_oldest_resident_age_seconds 0"));
    }

    #[test]
    fn status_class_buckets_match_prometheus_convention() {
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(302), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(500), "5xx");
        assert_eq!(status_class(700), "5xx"); // out-of-range clamps to 5xx
    }
}
