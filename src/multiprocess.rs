use std::{
    ffi::{OsStr, OsString},
    path::Path,
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    process::Command,
    sync::mpsc,
    task::JoinSet,
};

use crate::{cli::Args, shutdown::Shutdown};

const OVERRIDDEN_OPTIONS: &[&str] = &[
    "--processes",
    "--threads",
    "--syn-rate",
    "--max-rate",
    "--probe-concurrency",
    "--per-host-concurrency",
    "--per-probe-concurrency",
    "--output",
    "--worker-id",
    "--worker-count",
    "--cpu-affinity",
];

pub async fn run(args: &Args) -> Result<()> {
    let worker_count = args.processes;
    let total_threads = args.threads.expect("main sets an effective thread count");
    let executable = std::env::current_exe().context("resolve current executable")?;
    let original = crate::cli::normalize_arguments(std::env::args_os())
        .into_iter()
        .skip(1)
        .collect::<Vec<_>>();
    // Registering a listener stops the default SIGINT termination, which would
    // otherwise discard whatever is still buffered in the aggregate writer.
    let shutdown = Shutdown::listen();
    let mut children = Vec::with_capacity(worker_count);
    let mut readers = JoinSet::new();
    let (line_tx, mut line_rx) = mpsc::channel::<Vec<u8>>(10_000);

    tracing::info!(
        processes = worker_count,
        threads = total_threads,
        syn_rate = args.syn_rate,
        probe_concurrency = args.probe_concurrency,
        "starting worker processes"
    );

    for worker_id in 0..worker_count {
        let worker_args = worker_arguments(&original, args, worker_id);
        let mut child = Command::new(&executable)
            .args(worker_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn worker {worker_id}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("worker {worker_id} stdout is unavailable"))?;
        let tx = line_tx.clone();
        readers.spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let bytes = reader.read_until(b'\n', &mut line).await?;
                if bytes == 0 {
                    break;
                }
                tx.send(line).await?;
            }
            Ok::<_, anyhow::Error>(())
        });
        children.push((worker_id, child));
    }
    drop(line_tx);

    let mut writer = AggregateWriter::new(args.output.as_deref()).await?;
    let mut ticker = tokio::time::interval(args.flush_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = std::pin::pin!(tokio::time::sleep(Duration::MAX));
    let mut stopping = false;
    let mut signal = shutdown.clone();
    loop {
        tokio::select! {
            received = line_rx.recv() => match received {
                Some(line) => {
                    writer.write_line(&line).await?;
                }
                None => break,
            },
            _ = ticker.tick() => writer.sync().await?,
            _ = signal.wait(), if !stopping => {
                // Workers receive the same terminal signal and shut down on their
                // own; bound how long the aggregate waits for their remaining output.
                stopping = true;
                deadline
                    .as_mut()
                    .reset(tokio::time::Instant::now() + args.shutdown_grace());
            }
            _ = &mut deadline, if stopping => {
                tracing::warn!("worker grace period expired; stopping aggregation");
                break;
            }
        }
    }
    // The file must be complete before workers are reaped or the process exits.
    writer.sync().await?;

    if stopping {
        for (_, child) in children.iter_mut() {
            let _ = child.start_kill();
        }
    }
    readers.shutdown().await;

    let mut failures = Vec::new();
    for (worker_id, child) in children.iter_mut() {
        let status = child
            .wait()
            .await
            .with_context(|| format!("wait for worker {worker_id}"))?;
        if !status.success() && !stopping {
            failures.push(format!("worker {worker_id}: {status}"));
        }
    }
    if !failures.is_empty() {
        bail!("one or more workers failed: {}", failures.join(", "));
    }
    Ok(())
}

struct AggregateWriter {
    writer: BufWriter<Box<dyn AsyncWrite + Unpin + Send>>,
    sync_file: Option<File>,
}

impl AggregateWriter {
    async fn new(path: Option<&Path>) -> Result<Self> {
        let (writer, sync_file): (Box<dyn AsyncWrite + Unpin + Send>, Option<File>) = match path {
            Some(path) => {
                let file = File::create(path)
                    .await
                    .with_context(|| format!("create {}", path.display()))?;
                let sync_file = file
                    .try_clone()
                    .await
                    .with_context(|| format!("clone output handle {}", path.display()))?;
                (Box::new(file), Some(sync_file))
            }
            None => (Box::new(tokio::io::stdout()), None),
        };
        Ok(Self {
            writer: BufWriter::new(writer),
            sync_file,
        })
    }

    async fn write_line(&mut self, line: &[u8]) -> Result<()> {
        self.writer.write_all(line).await?;
        if !line.ends_with(b"\n") {
            self.writer.write_all(b"\n").await?;
        }
        self.writer.flush().await?;
        Ok(())
    }

    async fn sync(&mut self) -> Result<()> {
        self.writer.flush().await?;
        if let Some(file) = &self.sync_file {
            file.sync_data().await?;
        }
        Ok(())
    }
}

fn worker_arguments(original: &[OsString], args: &Args, worker_id: usize) -> Vec<OsString> {
    let mut rewritten = strip_overridden_options(original);
    let worker_count = args.processes;
    append_option(&mut rewritten, "--processes", 1);
    append_option(
        &mut rewritten,
        "--threads",
        share_usize(args.threads.unwrap_or(1), worker_id, worker_count),
    );
    let worker_rate = share_u64(args.syn_rate, worker_id, worker_count);
    append_option(&mut rewritten, "--syn-rate", worker_rate);
    append_option(&mut rewritten, "--max-rate", worker_rate);
    append_option(
        &mut rewritten,
        "--probe-concurrency",
        share_usize(args.probe_concurrency, worker_id, worker_count),
    );
    append_option(
        &mut rewritten,
        "--per-host-concurrency",
        share_usize(args.per_host_concurrency, worker_id, worker_count),
    );
    append_option(
        &mut rewritten,
        "--per-probe-concurrency",
        share_usize(args.per_probe_concurrency, worker_id, worker_count),
    );
    append_option(&mut rewritten, "--worker-id", worker_id);
    append_option(&mut rewritten, "--worker-count", worker_count);
    if let Ok(Some(cpus)) = args.cpu_ids() {
        let assigned = cpus
            .iter()
            .copied()
            .skip(worker_id)
            .step_by(worker_count)
            .collect::<Vec<_>>();
        if !assigned.is_empty() {
            append_option(
                &mut rewritten,
                "--cpu-affinity",
                crate::affinity::format_cpu_set(&assigned),
            );
        }
    }
    rewritten
}

fn strip_overridden_options(original: &[OsString]) -> Vec<OsString> {
    let mut result = Vec::with_capacity(original.len());
    let mut index = 0;
    while index < original.len() {
        let current = &original[index];
        let current_text = current.to_string_lossy();
        let exact = OVERRIDDEN_OPTIONS
            .iter()
            .any(|option| current == OsStr::new(option));
        let assigned = OVERRIDDEN_OPTIONS
            .iter()
            .any(|option| current_text.starts_with(&format!("{option}=")));
        if exact {
            index = index.saturating_add(2);
        } else if assigned {
            index += 1;
        } else {
            result.push(current.clone());
            index += 1;
        }
    }
    result
}

fn append_option<T: ToString>(arguments: &mut Vec<OsString>, name: &str, value: T) {
    arguments.push(name.into());
    arguments.push(value.to_string().into());
}

fn share_u64(total: u64, worker_id: usize, worker_count: usize) -> u64 {
    total / worker_count as u64 + u64::from((worker_id as u64) < total % worker_count as u64)
}

fn share_usize(total: usize, worker_id: usize, worker_count: usize) -> usize {
    total / worker_count + usize::from(worker_id < total % worker_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_preserve_totals() {
        assert_eq!(
            (0..3).map(|id| share_u64(10, id, 3)).collect::<Vec<_>>(),
            vec![4, 3, 3]
        );
        assert_eq!((0..3).map(|id| share_usize(8, id, 3)).sum::<usize>(), 8);
    }

    #[test]
    fn overridden_arguments_are_removed_in_both_forms() {
        let original = [
            "--target",
            "192.0.2.1",
            "--processes",
            "4",
            "--threads=8",
            "--output",
            "result.jsonl",
        ]
        .map(OsString::from);
        let actual = strip_overridden_options(&original);
        assert_eq!(actual, ["--target", "192.0.2.1"].map(OsString::from));
    }
}
