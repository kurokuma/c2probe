use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Arc,
};
use tokio::sync::{Mutex, Semaphore, mpsc};

use super::execute;
use crate::{
    cli::OutputMode,
    dsl::CompiledProbe,
    metrics::Metrics,
    output::{DiscoveryResult, ProbeResult, ScanResult, TargetResult},
    shutdown::Shutdown,
};

#[derive(Debug, Clone, Copy)]
pub struct OpenPort {
    pub ip: IpAddr,
    pub port: u16,
    pub syn_rtt_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    pub global_concurrency: usize,
    pub per_host_concurrency: usize,
    pub per_probe_concurrency: usize,
    pub retries: u8,
    pub output_mode: OutputMode,
}

/// Spreading the deduplication set over independent locks keeps it from serialising
/// every probe start at high concurrency.
const DEDUP_SHARDS: usize = 64;

/// Deduplication key from spec section 32: address, port, and probe.
type ProbeKey = (IpAddr, u16, Arc<str>);

#[derive(Default)]
struct SeenProbes {
    shards: Vec<Mutex<HashSet<ProbeKey>>>,
}

impl SeenProbes {
    fn new() -> Self {
        Self {
            shards: (0..DEDUP_SHARDS).map(|_| Mutex::default()).collect(),
        }
    }

    /// Returns true the first time this `(ip, port, probe)` is claimed.
    async fn claim(&self, key: ProbeKey) -> bool {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.0.hash(&mut hasher);
        key.1.hash(&mut hasher);
        let shard = (hasher.finish() as usize) % self.shards.len();
        self.shards[shard].lock().await.insert(key)
    }
}

/// Per-host limiters are reference counted so a long scan does not accumulate one
/// semaphore per address seen.
#[derive(Default)]
struct HostLimits {
    entries: Mutex<HashMap<IpAddr, (Arc<Semaphore>, usize)>>,
}

impl HostLimits {
    async fn acquire(&self, ip: IpAddr, permits: usize) -> Arc<Semaphore> {
        let mut entries = self.entries.lock().await;
        let entry = entries
            .entry(ip)
            .or_insert_with(|| (Arc::new(Semaphore::new(permits)), 0));
        entry.1 += 1;
        entry.0.clone()
    }

    async fn release(&self, ip: IpAddr) {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(&ip) {
            entry.1 -= 1;
            if entry.1 == 0 {
                entries.remove(&ip);
            }
        }
    }
}

pub async fn run_probes(
    input: mpsc::Receiver<OpenPort>,
    probes: Vec<Arc<CompiledProbe>>,
    config: SchedulerConfig,
    metrics: Arc<Metrics>,
    out: mpsc::Sender<ScanResult>,
) -> Result<()> {
    run_probes_with_shutdown(input, probes, config, metrics, out, Shutdown::inactive()).await
}

pub async fn run_probes_with_shutdown(
    mut input: mpsc::Receiver<OpenPort>,
    probes: Vec<Arc<CompiledProbe>>,
    config: SchedulerConfig,
    metrics: Arc<Metrics>,
    out: mpsc::Sender<ScanResult>,
    shutdown: Shutdown,
) -> Result<()> {
    let global = Arc::new(Semaphore::new(config.global_concurrency));
    let hosts = Arc::new(HostLimits::default());
    let probe_limits: Arc<HashMap<Arc<str>, Arc<Semaphore>>> = Arc::new(
        probes
            .iter()
            .map(|probe| {
                (
                    probe.name.clone(),
                    Arc::new(Semaphore::new(config.per_probe_concurrency)),
                )
            })
            .collect(),
    );
    let seen = Arc::new(SeenProbes::new());
    let mut tasks = tokio::task::JoinSet::new();
    while let Some(open) = input.recv().await {
        metrics.queue_dequeued();
        if matches!(config.output_mode, OutputMode::All | OutputMode::Open) {
            send_result(&out, &metrics, open_result(open)).await?;
        }
        // New probe plans stop at Ctrl+C; the ones already running are awaited below.
        if shutdown.is_triggered() {
            continue;
        }
        let plan_permit = global.clone().acquire_owned().await?;
        let probes = probes.clone();
        let hosts = hosts.clone();
        let seen = seen.clone();
        let probe_limits = probe_limits.clone();
        let tx = out.clone();
        let m = metrics.clone();
        tasks.spawn(async move {
            let _plan_permit = plan_permit;
            let host_sem = hosts.acquire(open.ip, config.per_host_concurrency).await;
            let result = run_plan(
                open,
                &probes,
                &host_sem,
                &probe_limits,
                &seen,
                &config,
                &tx,
                &m,
            )
            .await;
            hosts.release(open.ip).await;
            result
        });
    }
    drop(out);
    while let Some(r) = tasks.join_next().await {
        r??;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_plan(
    open: OpenPort,
    probes: &[Arc<CompiledProbe>],
    host_sem: &Semaphore,
    probe_limits: &HashMap<Arc<str>, Arc<Semaphore>>,
    seen: &SeenProbes,
    config: &SchedulerConfig,
    tx: &mpsc::Sender<ScanResult>,
    m: &Arc<Metrics>,
) -> Result<()> {
    for p in probes {
        if !p.allows(open.ip, open.port) {
            continue;
        }
        if !seen.claim((open.ip, open.port, p.name.clone())).await {
            continue;
        }
        let _h = host_sem.acquire().await?;
        let probe_permit = probe_limits
            .get(&p.name)
            .expect("probe limit is built from the probe plan")
            .acquire()
            .await?;
        Metrics::inc(&m.probes_started);
        m.connection_started();
        let mut e = execute(open.ip, open.port, p).await;
        m.connection_finished();
        for _ in 0..config.retries {
            if e.confirmed
                || !matches!(
                    e.status.as_str(),
                    "connect_timeout" | "read_timeout" | "connection_reset" | "probe_error"
                )
            {
                break;
            }
            Metrics::inc(&m.probes_started);
            m.connection_started();
            e = execute(open.ip, open.port, p).await;
            m.connection_finished();
        }
        Metrics::inc(&m.probes_completed);
        drop(probe_permit);
        if e.confirmed {
            Metrics::inc(&m.probes_matched)
        }
        if e.status.ends_with("timeout") {
            Metrics::inc(&m.probes_timeout)
        }
        let should = match config.output_mode {
            OutputMode::All => true,
            OutputMode::Open => false,
            OutputMode::Responsive => e.responsive,
            OutputMode::Detected => e.confirmed || e.probable,
            OutputMode::Matched => e.confirmed,
        };
        if should {
            let r = ScanResult {
                timestamp: chrono::Utc::now(),
                target: TargetResult {
                    ip: open.ip,
                    port: open.port,
                    transport: match p.transport {
                        crate::dsl::TransportType::Tcp => "tcp",
                        crate::dsl::TransportType::Tls => "tls",
                        crate::dsl::TransportType::Starttls => "starttls",
                    }
                    .into(),
                },
                discovery: DiscoveryResult {
                    port_state: "open".into(),
                    syn_rtt_ms: open.syn_rtt_ms,
                },
                probe: Some(ProbeResult {
                    name: p.name.to_string(),
                    family: p.family.to_string(),
                    protocol: p.protocol.to_string(),
                    confirmed: e.confirmed,
                    probable: e.probable,
                    observed: e.observed,
                    confidence: e.confidence,
                    status: e.status,
                    duration_ms: e.duration_ms,
                }),
                fields: e.fields,
            };
            send_result(tx, m, r).await?;
        }
        if e.confirmed {
            break;
        }
    }
    Ok(())
}

async fn send_result(
    out: &mpsc::Sender<ScanResult>,
    metrics: &Metrics,
    result: ScanResult,
) -> Result<()> {
    metrics.queue_enqueued();
    if let Err(error) = out.send(result).await {
        metrics.queue_dequeued();
        return Err(error.into());
    }
    Ok(())
}

fn open_result(o: OpenPort) -> ScanResult {
    ScanResult {
        timestamp: chrono::Utc::now(),
        target: TargetResult {
            ip: o.ip,
            port: o.port,
            transport: "tcp".into(),
        },
        discovery: DiscoveryResult {
            port_state: "open".into(),
            syn_rtt_ms: o.syn_rtt_ms,
        },
        probe: None,
        fields: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_limits_are_dropped_once_idle() {
        let limits = HostLimits::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let first = limits.acquire(ip, 4).await;
        let second = limits.acquire(ip, 4).await;
        assert!(Arc::ptr_eq(&first, &second));
        limits.release(ip).await;
        assert_eq!(limits.entries.lock().await.len(), 1);
        limits.release(ip).await;
        assert!(limits.entries.lock().await.is_empty());
    }

    #[tokio::test]
    async fn duplicate_probe_jobs_are_claimed_once() {
        let seen = SeenProbes::new();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let name: Arc<str> = Arc::from("p");
        assert!(seen.claim((ip, 80, name.clone())).await);
        assert!(!seen.claim((ip, 80, name.clone())).await);
        assert!(seen.claim((ip, 81, name)).await);
    }
}
