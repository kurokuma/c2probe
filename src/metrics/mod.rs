use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[derive(Debug)]
pub struct Metrics {
    /// Distinct addresses in this worker's target set. Identical across workers,
    /// because sharding splits ports rather than addresses; do not sum it.
    pub targets_total: AtomicU64,
    /// Jobs handed to the scanner, counted where they are generated.
    pub ports_scheduled: AtomicU64,
    /// Jobs skipped before packet construction or after an individual send failure.
    pub targets_skipped: AtomicU64,
    /// Raw SYN jobs skipped after the kernel rejected the individual send.
    pub send_errors: AtomicU64,
    pub syn_packets_sent: AtomicU64,
    pub syn_responses: AtomicU64,
    pub ports_open: AtomicU64,
    pub ports_closed: AtomicU64,
    pub probes_started: AtomicU64,
    pub probes_completed: AtomicU64,
    pub probes_matched: AtomicU64,
    pub probes_timeout: AtomicU64,
    pub active_connections: AtomicU64,
    pub queue_depth: AtomicU64,
    started: Instant,
}
impl Default for Metrics {
    fn default() -> Self {
        Self {
            targets_total: 0.into(),
            ports_scheduled: 0.into(),
            targets_skipped: 0.into(),
            send_errors: 0.into(),
            syn_packets_sent: 0.into(),
            syn_responses: 0.into(),
            ports_open: 0.into(),
            ports_closed: 0.into(),
            probes_started: 0.into(),
            probes_completed: 0.into(),
            probes_matched: 0.into(),
            probes_timeout: 0.into(),
            active_connections: 0.into(),
            queue_depth: 0.into(),
            started: Instant::now(),
        }
    }
}
impl Metrics {
    pub fn inc(a: &AtomicU64) {
        a.fetch_add(1, Ordering::Relaxed);
    }
    pub fn dec_saturating(a: &AtomicU64) {
        let _ = a.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_sub(1))
        });
    }
    pub fn queue_enqueued(&self) {
        Self::inc(&self.queue_depth);
    }
    pub fn queue_dequeued(&self) {
        Self::dec_saturating(&self.queue_depth);
    }
    pub fn connection_started(&self) {
        Self::inc(&self.active_connections);
    }
    pub fn connection_finished(&self) {
        Self::dec_saturating(&self.active_connections);
    }

    /// One-line progress view shared by the periodic status output and the summary.
    pub fn status(&self) -> String {
        let elapsed = self.started.elapsed().as_secs_f64().max(0.001);
        let syn_sent = self.syn_packets_sent.load(Ordering::Relaxed);
        let probes = self.probes_completed.load(Ordering::Relaxed);
        format!(
            "elapsed={elapsed:.2}s targets={} scheduled={} skipped={} send_errors={} syn_sent={} syn_responses={} syn_rate={:.0}/s open={} closed={} probes={} probe_rate={:.0}/s matched={} timeouts={} active={} queue={}",
            self.targets_total.load(Ordering::Relaxed),
            self.ports_scheduled.load(Ordering::Relaxed),
            self.targets_skipped.load(Ordering::Relaxed),
            self.send_errors.load(Ordering::Relaxed),
            syn_sent,
            self.syn_responses.load(Ordering::Relaxed),
            syn_sent as f64 / elapsed,
            self.ports_open.load(Ordering::Relaxed),
            self.ports_closed.load(Ordering::Relaxed),
            probes,
            probes as f64 / elapsed,
            self.probes_matched.load(Ordering::Relaxed),
            self.probes_timeout.load(Ordering::Relaxed),
            self.active_connections.load(Ordering::Relaxed),
            self.queue_depth.load(Ordering::Relaxed),
        )
    }

    pub fn summary(&self) -> String {
        self.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_depth_never_underflows() {
        let metrics = Metrics::default();
        metrics.queue_dequeued();
        assert_eq!(metrics.queue_depth.load(Ordering::Relaxed), 0);
        metrics.queue_enqueued();
        metrics.queue_dequeued();
        assert_eq!(metrics.queue_depth.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn status_reports_discovery_counters() {
        let metrics = Metrics::default();
        Metrics::inc(&metrics.ports_closed);
        Metrics::inc(&metrics.targets_skipped);
        Metrics::inc(&metrics.send_errors);
        metrics.ports_scheduled.store(7, Ordering::Relaxed);
        let status = metrics.status();
        assert!(status.contains("closed=1"), "{status}");
        assert!(status.contains("skipped=1"), "{status}");
        assert!(status.contains("send_errors=1"), "{status}");
        assert!(status.contains("scheduled=7"), "{status}");
    }
}
