use std::{ffi::OsString, net::IpAddr, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};

use crate::target::{PortSet, TargetSet};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ScanMode {
    Full,
    Discovery,
    Probe,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputMode {
    All,
    Open,
    Responsive,
    Matched,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

#[derive(Debug, Parser)]
#[command(
    name = "c2probe",
    version,
    about = "DSL-driven defensive C2 fingerprint scanner"
)]
pub struct Args {
    /// IP, CIDR, or (in probe mode) IP:PORT. Repeatable.
    #[arg(short = 't', long = "target")]
    pub targets: Vec<String>,
    /// Read IP/CIDR or IP:PORT targets from a file. `-iL` is accepted as an alias.
    #[arg(short = 'i', long = "input-list", alias = "iL")]
    pub input_list: Option<PathBuf>,
    #[arg(short = 'p', long, default_value = "1-65535")]
    pub ports: String,
    #[arg(long, value_enum, default_value_t = ScanMode::Full)]
    pub scan_mode: ScanMode,
    #[arg(long = "probe")]
    pub probes: Vec<PathBuf>,
    #[arg(long)]
    pub probe_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 100_000)]
    pub syn_rate: u64,
    #[arg(long, default_value_t = 100_000)]
    pub max_rate: u64,
    #[arg(long, default_value_t = 1024)]
    pub probe_concurrency: usize,
    #[arg(long, default_value_t = 32)]
    pub per_host_concurrency: usize,
    #[arg(long, default_value_t = 256)]
    pub per_probe_concurrency: usize,
    #[arg(long, default_value_t = 750)]
    pub connect_timeout: u64,
    #[arg(long, default_value_t = 1000)]
    pub read_timeout: u64,
    #[arg(long, default_value_t = 1000)]
    pub syn_timeout: u64,
    #[arg(long, default_value_t = 0)]
    pub retries: u8,
    #[arg(long, default_value_t = 1)]
    pub processes: usize,
    #[arg(long)]
    pub threads: Option<usize>,
    /// Linux CPU IDs, for example 0,2-5. Distributed across worker processes.
    #[arg(long)]
    pub cpu_affinity: Option<String>,
    /// Maximum SYN packets submitted by one Linux sendmmsg call.
    #[arg(long, default_value_t = 64)]
    pub syn_batch_size: usize,
    #[arg(long, hide = true, default_value_t = 0)]
    pub worker_id: usize,
    #[arg(long, hide = true, default_value_t = 1)]
    pub worker_count: usize,
    #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
    pub format: OutputFormat,
    #[arg(long, value_enum, default_value_t = OutputMode::Matched)]
    pub output_mode: OutputMode,
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Minimum log level. RUST_LOG can add module-specific overrides.
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,
    /// Append logs to this file in addition to stderr.
    #[arg(long)]
    pub log_file: Option<PathBuf>,
    /// Milliseconds between output sync_data calls. Each complete record is flushed immediately.
    #[arg(long, default_value_t = 1000)]
    pub flush_interval: u64,
    /// Seconds to wait for in-flight probes after Ctrl+C before dropping them.
    #[arg(long, default_value_t = 10)]
    pub shutdown_grace: u64,
    #[arg(long = "exclude")]
    pub excludes: Vec<String>,
    #[arg(long)]
    pub exclude_file: Option<PathBuf>,
}

impl Args {
    pub async fn validate(&self) -> Result<()> {
        if self.targets.is_empty() && self.input_list.is_none() {
            bail!("provide --target or --input-list");
        }
        if self.syn_rate == 0 || self.syn_rate > self.max_rate {
            bail!("--syn-rate must be 1..=--max-rate");
        }
        if self.probe_concurrency == 0
            || self.per_host_concurrency == 0
            || self.per_probe_concurrency == 0
        {
            bail!("concurrency must be non-zero");
        }
        if self.processes == 0 || self.processes > 64 {
            bail!("--processes must be 1..=64");
        }
        if self.threads == Some(0) {
            bail!("--threads must be non-zero");
        }
        if !(1..=1024).contains(&self.syn_batch_size) {
            bail!("--syn-batch-size must be 1..=1024");
        }
        if self.flush_interval == 0 {
            bail!("--flush-interval must be non-zero");
        }
        if self.log_file.is_some() && self.log_file == self.output {
            bail!("--log-file and --output must be different files");
        }
        if let Some(value) = &self.cpu_affinity {
            let cpus = crate::affinity::parse_cpu_set(value)?;
            if !cfg!(target_os = "linux") {
                bail!("--cpu-affinity is currently supported on Linux only");
            }
            if self.processes > cpus.len() {
                bail!("--cpu-affinity must provide at least one CPU per process");
            }
        }
        if self.worker_count == 0 || self.worker_id >= self.worker_count {
            bail!("invalid internal worker shard");
        }
        if self.processes > 1 {
            let threads = self.threads.unwrap_or(1);
            if self.processes > threads {
                bail!("--processes cannot exceed --threads");
            }
            if self.processes > self.probe_concurrency {
                bail!("--processes cannot exceed --probe-concurrency");
            }
            if self.processes > self.per_host_concurrency {
                bail!("--processes cannot exceed --per-host-concurrency");
            }
            if self.processes > self.per_probe_concurrency {
                bail!("--processes cannot exceed --per-probe-concurrency");
            }
            if self.processes as u64 > self.syn_rate {
                bail!("--processes cannot exceed --syn-rate");
            }
            if self.format != OutputFormat::Jsonl {
                bail!("multi-process mode currently supports --format jsonl only");
            }
        }
        if self.runs_probes() && self.probes.is_empty() && self.probe_dir.is_none() {
            bail!("probe execution requires --probe or --probe-dir");
        }
        Ok(())
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout)
    }
    pub fn read_timeout(&self) -> Duration {
        Duration::from_millis(self.read_timeout)
    }
    pub fn flush_interval(&self) -> Duration {
        Duration::from_millis(self.flush_interval)
    }
    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.shutdown_grace)
    }

    /// Probe results can only be emitted by the modes below, so any other combination
    /// would open connections whose results are discarded.
    pub fn runs_probes(&self) -> bool {
        self.scan_mode != ScanMode::Discovery && self.output_mode != OutputMode::Open
    }

    /// Raw SYN discovery is IPv4 only; rejecting IPv6 up front avoids a scan that
    /// silently produces nothing.
    pub fn check_target_support(&self, targets: &TargetSet) -> Result<()> {
        if self.scan_mode != ScanMode::Probe && targets.has_ipv6_nets() {
            bail!(
                "IPv6 targets require --scan-mode probe; raw SYN discovery is IPv4 only in this release"
            );
        }
        Ok(())
    }

    pub async fn load_targets(&self) -> Result<TargetSet> {
        let mut lines = self.targets.clone();
        if let Some(path) = &self.input_list {
            let text = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("read {}", path.display()))?;
            lines.extend(text.lines().map(str::to_owned));
        }
        let mut excluded = self.excludes.clone();
        if let Some(path) = &self.exclude_file {
            let text = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("read {}", path.display()))?;
            excluded.extend(text.lines().map(str::to_owned));
        }
        Ok(TargetSet::parse(
            &lines,
            &excluded,
            self.scan_mode == ScanMode::Probe,
        )?)
    }

    pub fn load_ports(&self) -> Result<PortSet> {
        PortSet::from_str(&self.ports).map_err(Into::into)
    }

    pub fn is_worker(&self) -> bool {
        self.worker_count > 1
    }

    pub fn cpu_ids(&self) -> Result<Option<Vec<usize>>> {
        self.cpu_affinity
            .as_deref()
            .map(crate::affinity::parse_cpu_set)
            .transpose()
    }
}

/// `-iL <file>` is the form used by nmap and by spec.md, but clap parses it as the
/// short `-i` with the value `L`. Rewrite the exact token before parsing.
pub fn normalize_arguments<I>(raw: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    raw.into_iter()
        .map(|argument| {
            if argument == *"-iL" {
                OsString::from("--input-list")
            } else {
                argument
            }
        })
        .collect()
}

impl Args {
    pub fn parse_from_env() -> Self {
        Self::parse_from(normalize_arguments(std::env::args_os()))
    }
}

pub fn parse_socket_target(value: &str) -> Option<(IpAddr, u16)> {
    value
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|s| (s.ip(), s.port()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_nmap_style_input_list() {
        let raw = ["c2probe", "-iL", "targets.txt", "-p", "80"].map(OsString::from);
        assert_eq!(
            normalize_arguments(raw),
            ["c2probe", "--input-list", "targets.txt", "-p", "80"].map(OsString::from)
        );
        let args = Args::parse_from(normalize_arguments(
            ["c2probe", "-iL", "targets.txt"].map(OsString::from),
        ));
        assert_eq!(args.input_list, Some(PathBuf::from("targets.txt")));
    }

    #[test]
    fn ipv6_requires_probe_mode() {
        let mut args = Args::parse_from(["c2probe", "-t", "2001:db8::/126"].map(OsString::from));
        let targets = TargetSet::parse(&["2001:db8::/126".into()], &[], false).unwrap();
        assert!(args.check_target_support(&targets).is_err());
        args.scan_mode = ScanMode::Probe;
        assert!(args.check_target_support(&targets).is_ok());
    }

    #[test]
    fn probes_are_skipped_when_only_open_ports_are_reported() {
        let mut args = Args::parse_from(["c2probe", "-t", "192.0.2.1"].map(OsString::from));
        assert!(args.runs_probes());
        args.output_mode = OutputMode::Open;
        assert!(!args.runs_probes());
    }

    #[test]
    fn parses_explicit_log_level() {
        let args = Args::parse_from(
            ["c2probe", "-t", "192.0.2.1", "--log-level", "debug"].map(OsString::from),
        );
        assert_eq!(args.log_level, LogLevel::Debug);
    }
}
