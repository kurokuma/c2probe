pub mod cookie;
#[cfg(target_os = "linux")]
mod linux;

use crate::{metrics::Metrics, probe::OpenPort};
use anyhow::Result;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
pub async fn syn_scan(
    jobs: mpsc::Receiver<(IpAddr, u16)>,
    rate: u64,
    batch_size: usize,
    timeout: Duration,
    cpu_ids: Option<Arc<[usize]>>,
    metrics: Arc<Metrics>,
    out: mpsc::Sender<OpenPort>,
) -> Result<()> {
    linux::syn_scan(jobs, rate, batch_size, timeout, cpu_ids, metrics, out).await
}

#[cfg(not(target_os = "linux"))]
pub async fn syn_scan(
    _: mpsc::Receiver<(IpAddr, u16)>,
    _: u64,
    _: usize,
    _: Duration,
    _: Option<Arc<[usize]>>,
    _: Arc<Metrics>,
    _: mpsc::Sender<OpenPort>,
) -> Result<()> {
    Err(crate::error::C2ProbeError::DiscoveryUnsupported.into())
}
