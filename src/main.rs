use anyhow::{Result, anyhow};
use c2probe::{
    cli::{Args, ScanMode},
    discovery, dsl,
    metrics::Metrics,
    multiprocess,
    output::OutputWriter,
    probe::{self, OpenPort, SchedulerConfig},
    shutdown::Shutdown,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;

fn main() -> Result<()> {
    let mut args = Args::parse_from_env();
    let threads = args.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4)
    });
    args.threads = Some(threads);
    let cpu_ids = args.cpu_ids()?;
    if let Some(cpus) = &cpu_ids {
        c2probe::affinity::validate_available(cpus)?;
    }
    let runtime_threads = if args.processes > 1 { 1 } else { threads };
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(runtime_threads).enable_all();
    if args.processes <= 1
        && let Some(cpus) = cpu_ids
    {
        let cpus: Arc<[usize]> = cpus.into();
        let next = Arc::new(AtomicUsize::new(0));
        builder.on_thread_start(move || {
            let cpu = cpus[next.fetch_add(1, Ordering::Relaxed) % cpus.len()];
            if let Err(error) = c2probe::affinity::pin_current(cpu) {
                eprintln!("failed to apply CPU affinity: {error:#}");
            }
        });
    }
    builder.build()?.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    c2probe::logging::init(args.log_level, args.log_file.as_deref())?;
    args.validate().await?;
    if args.processes > 1 {
        return multiprocess::run(&args).await;
    }
    let targets = args.load_targets().await?;
    args.check_target_support(&targets)?;
    let ports = args.load_ports()?;
    let total = targets.job_count(&ports);
    let probe_paths = args.probes.clone();
    let probe_dir = args.probe_dir.clone();
    let probes = if args.runs_probes() {
        let probe_parameters = args.probe_parameter_map()?;
        dsl::load_probes_with_params(
            &probe_paths,
            probe_dir.as_deref(),
            args.connect_timeout(),
            args.read_timeout(),
            &probe_parameters,
        )
        .await?
    } else {
        Vec::new()
    };
    tracing::info!(
        mode = ?args.scan_mode,
        targets = %targets.target_count(),
        jobs = %total,
        probes = probes.len(),
        processes = args.processes,
        threads = args.threads.unwrap_or(1),
        syn_rate = args.syn_rate,
        "starting scan"
    );
    if args.scan_mode != ScanMode::Discovery && probes.is_empty() {
        tracing::warn!(
            "--output-mode open reports discovery results only; probes will not be executed"
        );
    }
    if total > 100_000_000 {
        tracing::warn!(scheduled=%total,"large scan; confirm routing, authorization, and output capacity")
    }
    let shutdown = Shutdown::listen();
    let metrics = Arc::new(Metrics::default());
    metrics.targets_total.store(
        targets.target_count().min(u64::MAX as u128) as u64,
        Ordering::Relaxed,
    );
    let (open_tx, open_rx) = mpsc::channel(100_000);
    let (result_tx, mut result_rx) = mpsc::channel(100_000);
    let mut writer = OutputWriter::new(args.format, args.output.as_deref()).await?;
    let output_metrics = metrics.clone();
    let flush_interval = args.flush_interval();
    let output_shutdown = shutdown.clone();
    let output_task = tokio::spawn(async move {
        let result = async {
            let mut ticker = tokio::time::interval(flush_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    received = result_rx.recv() => match received {
                        Some(r) => {
                            output_metrics.queue_dequeued();
                            writer.write(&r).await?
                        }
                        None => break,
                    },
                    _ = ticker.tick() => writer.flush().await?,
                }
            }
            writer.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = &result {
            tracing::error!(%error, "output task failed; requesting graceful shutdown");
            output_shutdown.request();
        }
        result
    });
    let scheduler_mode = if probes.is_empty() {
        c2probe::cli::OutputMode::Open
    } else {
        args.output_mode
    };
    let scheduler_shutdown = shutdown.clone();
    let scheduler_signal = shutdown.clone();
    let scheduler_metrics = metrics.clone();
    let scheduler_config = SchedulerConfig {
        global_concurrency: args.probe_concurrency,
        per_host_concurrency: args.per_host_concurrency,
        per_probe_concurrency: args.per_probe_concurrency,
        retries: args.retries,
        output_mode: scheduler_mode,
    };
    let mut scheduler = tokio::spawn(async move {
        let result = probe::run_probes_with_shutdown(
            open_rx,
            probes,
            scheduler_config,
            scheduler_metrics,
            result_tx,
            scheduler_signal,
        )
        .await;
        if let Err(error) = &result {
            tracing::error!(%error, "probe scheduler failed; requesting graceful shutdown");
            scheduler_shutdown.request();
        }
        result
    });
    let status = tokio::spawn(report_status(metrics.clone(), args.flush_interval()));
    let mut pipeline_error: Option<anyhow::Error> = None;
    match args.scan_mode {
        ScanMode::Probe => {
            let mut signal = shutdown.clone();
            for (ip, port) in
                targets.socket_targets_shard(&ports, args.worker_id, args.worker_count)
            {
                metrics.queue_enqueued();
                Metrics::inc(&metrics.ports_scheduled);
                tokio::select! {
                    sent = open_tx.send(OpenPort { ip, port, syn_rtt_ms: None }) => {
                        if sent.is_err() { metrics.queue_dequeued(); break; }
                    }
                    _ = signal.wait() => { metrics.queue_dequeued(); break; }
                }
            }
            drop(open_tx)
        }
        ScanMode::Full | ScanMode::Discovery => {
            let (job_tx, job_rx) = mpsc::channel(100_000);
            let scan = tokio::spawn(discovery::syn_scan(
                job_rx,
                args.syn_rate,
                args.syn_batch_size,
                Duration::from_millis(args.syn_timeout),
                args.cpu_ids()?.map(Arc::from),
                metrics.clone(),
                open_tx,
            ));
            let mut signal = shutdown.clone();
            for job in targets.socket_targets_shard(&ports, args.worker_id, args.worker_count) {
                metrics.queue_enqueued();
                Metrics::inc(&metrics.ports_scheduled);
                tokio::select! {
                    sent = job_tx.send(job) => { if sent.is_err() { metrics.queue_dequeued(); break; } }
                    _ = signal.wait() => { metrics.queue_dequeued(); break; }
                }
            }
            drop(job_tx);
            match scan.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::error!(%error, "discovery failed; draining completed results");
                    shutdown.request();
                    pipeline_error = Some(error);
                }
                Err(error) => {
                    tracing::error!(%error, "discovery task failed; draining completed results");
                    shutdown.request();
                    pipeline_error = Some(error.into());
                }
            }
        }
    }
    // In-flight probes get a bounded grace period, so Ctrl+C cannot hang on a peer
    // that never answers. Aborting releases the result senders and lets the output
    // task close the file cleanly.
    let mut signal = shutdown.clone();
    let finished = tokio::select! {
        joined = &mut scheduler => Some(joined),
        _ = signal.wait() => None,
    };
    let scheduler_result = match finished {
        Some(joined) => flatten_task(joined),
        None => {
            let grace = args.shutdown_grace();
            tracing::info!(seconds = grace.as_secs(), "waiting for in-flight probes");
            match tokio::time::timeout(grace, &mut scheduler).await {
                Ok(joined) => flatten_task(joined),
                Err(_) => {
                    tracing::warn!("probe grace period expired; dropping in-flight probes");
                    scheduler.abort();
                    let _ = scheduler.await;
                    Ok(())
                }
            }
        }
    };
    if let Err(error) = scheduler_result
        && pipeline_error.is_none()
    {
        pipeline_error = Some(error);
    }
    status.abort();
    let _ = status.await;
    match output_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) if pipeline_error.is_none() => pipeline_error = Some(error),
        Err(error) if pipeline_error.is_none() => pipeline_error = Some(error.into()),
        _ => {}
    }
    if args.is_worker() {
        eprintln!(
            "worker={}/{} {}",
            args.worker_id + 1,
            args.worker_count,
            metrics.summary()
        );
    } else {
        eprintln!("{}", metrics.summary());
    }
    match pipeline_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn flatten_task(joined: std::result::Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    match joined {
        Ok(result) => result,
        Err(error) => Err(anyhow!(error)),
    }
}

async fn report_status(metrics: Arc<Metrics>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(5)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        tracing::info!("{}", metrics.status());
    }
}
