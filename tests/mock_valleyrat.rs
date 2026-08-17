use c2probe::{
    cli::OutputMode,
    dsl,
    metrics::Metrics,
    probe::{OpenPort, SchedulerConfig, execute, run_probes},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivateKeyDer},
};

async fn probe(name: &str) -> std::sync::Arc<c2probe::dsl::CompiledProbe> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("probes/valleyrat")
        .join(name);
    dsl::load_probes(
        &[path],
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .unwrap()
    .remove(0)
}

#[tokio::test]
async fn vvas_matches_reference_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 3];
        s.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [0x33, 0x32, 0]);
        let mut response = [0u8; 14];
        response[..4].copy_from_slice(&307214u32.to_le_bytes());
        s.write_all(&response).await.unwrap();
    });
    let compiled = probe("vvas.yaml").await;
    let result = execute(addr.ip(), addr.port(), compiled.as_ref()).await;
    server.await.unwrap();
    assert!(result.confirmed);
    assert_eq!(result.status, "vvas_stage_header_match");
    assert_eq!(result.fields["declared_stage_size"], 307214);
}

#[tokio::test]
async fn vvas_rejects_wrong_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 3];
        s.read_exact(&mut request).await.unwrap();
        s.write_all(&[0u8; 14]).await.unwrap();
    });
    let compiled = probe("vvas.yaml").await;
    let result = execute(addr.ip(), addr.port(), compiled.as_ref()).await;
    server.await.unwrap();
    assert!(!result.confirmed);
    assert!(result.responsive);
}

#[tokio::test]
async fn winos_matches_encrypted_command() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 15];
        s.read_exact(&mut request).await.unwrap();
        assert_eq!(
            request,
            [
                0x0f, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0xca, 0, 0x67
            ]
        );
        let mut response = [0u8; 15];
        response[..4].copy_from_slice(&15u32.to_le_bytes());
        response[4] = 0x78;
        response[14] = 0xc9 ^ (0x78u8.wrapping_add(0x36));
        s.write_all(&response).await.unwrap();
    });
    let compiled = probe("winos.yaml").await;
    let result = execute(addr.ip(), addr.port(), compiled.as_ref()).await;
    server.await.unwrap();
    assert!(result.confirmed);
    assert_eq!(result.fields["response_command"], 0xc9);
}

#[tokio::test]
async fn n520_matches_server_first_magic_and_crc() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        let session = 0x1234_5678u32;
        let mixed = ((session >> 16) ^ (session & 0xffff)) | 0xa5a5_0000;
        let magic = session ^ mixed;
        let mut frame = [0u8; 44];
        frame[..4].copy_from_slice(&session.to_le_bytes());
        frame[4..8].copy_from_slice(&magic.to_le_bytes());
        let crc = crc32fast::hash(&frame[..40]);
        frame[40..].copy_from_slice(&crc.to_le_bytes());
        tls.write_all(&frame).await.unwrap();
    });
    let compiled = probe("n520.yaml").await;
    let result = execute(addr.ip(), addr.port(), compiled.as_ref()).await;
    server.await.unwrap();
    assert!(result.confirmed);
    assert_eq!(result.status, "n520_server_first_handshake_match");
    assert_eq!(result.fields["stored_crc"], result.fields["calculated_crc"]);
}

#[tokio::test]
async fn multiprocess_probe_mode_shards_and_merges_jsonl() {
    async fn mock() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 3];
            socket.read_exact(&mut request).await.unwrap();
            let mut response = [0u8; 14];
            response[..4].copy_from_slice(&307214u32.to_le_bytes());
            socket.write_all(&response).await.unwrap();
        });
        (address, task)
    }

    let (first, first_server) = mock().await;
    let (second, second_server) = mock().await;
    let probe_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("probes/valleyrat/vvas.yaml");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_c2probe"));
    command.current_dir(env!("CARGO_MANIFEST_DIR")).args([
        "--target",
        &first.to_string(),
        "--target",
        &second.to_string(),
        "--scan-mode",
        "probe",
        "--probe",
        probe_path.to_str().unwrap(),
        "--processes",
        "2",
        "--threads",
        "2",
        "--syn-rate",
        "2",
        "--max-rate",
        "2",
        "--probe-concurrency",
        "2",
        "--per-host-concurrency",
        "2",
        "--output-mode",
        "matched",
    ]);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("multi-process command timed out")
        .unwrap();
    first_server.await.unwrap();
    second_server.await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter(|line| line.starts_with("worker=") && line.ends_with("active=0 queue=0"))
            .count(),
        2
    );
    let mut ports = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["target"]["port"]
                .as_u64()
                .unwrap() as u16
        })
        .collect::<Vec<_>>();
    ports.sort_unstable();
    let mut expected = vec![first.port(), second.port()];
    expected.sort_unstable();
    assert_eq!(ports, expected);
}

fn cli() -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_c2probe"));
    command.current_dir(env!("CARGO_MANIFEST_DIR"));
    command
}

#[tokio::test]
async fn ipv6_discovery_is_rejected_instead_of_silently_skipped() {
    let output = cli()
        .args([
            "--target",
            "2001:db8::/126",
            "--ports",
            "80",
            "--probe",
            "probes/valleyrat/vvas.yaml",
        ])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("--scan-mode probe"), "{stderr}");
}

#[tokio::test]
async fn nmap_style_input_list_flag_is_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let list = directory.path().join("targets.txt");
    tokio::fs::write(&list, "192.0.2.10\n# comment\n\n")
        .await
        .unwrap();
    let output = cli()
        .args([
            "-iL",
            list.to_str().unwrap(),
            "-p",
            "80",
            "--scan-mode",
            "probe",
            "--output-mode",
            "open",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"ip\":\"192.0.2.10\""),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn log_file_receives_selected_level_output() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("c2probe.log");
    let output = cli()
        .env_remove("RUST_LOG")
        .args([
            "--target",
            "127.0.0.1:1",
            "--scan-mode",
            "probe",
            "--output-mode",
            "open",
            "--log-level",
            "debug",
            "--log-file",
            log.to_str().unwrap(),
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = tokio::fs::read_to_string(log).await.unwrap();
    assert!(text.contains("starting scan"), "{text}");
}

#[tokio::test]
async fn probe_definition_faults_are_reported_at_load_time() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broken.yaml");
    tokio::fs::write(
        &path,
        "dsl_version: 1\nname: broken\ntransport: {type: tcp}\nsteps:\n\
         - recv_exact: {bytes: 4, save_as: r}\n\
         - extract: {source: r, name: v, type: u32le, offset: 900}\n\
         - match: {eq: {left: '$v', right: 1}}\nresult: {family: t, protocol: t}\n",
    )
    .await
    .unwrap();
    let output = cli()
        .args([
            "--target",
            "192.0.2.10:1",
            "--scan-mode",
            "probe",
            "--probe",
            path.to_str().unwrap(),
        ])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("exceeds the 4 byte source buffer"),
        "{stderr}"
    );
}

#[tokio::test]
async fn unmatched_protocol_is_distinguished_from_transport_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 3];
        socket.read_exact(&mut request).await.unwrap();
        socket.write_all(&[0xff; 14]).await.unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("no-status.yaml");
    tokio::fs::write(
        &path,
        "dsl_version: 1\nname: no-status\ntransport: {type: tcp}\nsteps:\n\
         - send: {hex: '33 32 00'}\n\
         - recv_exact: {bytes: 14, save_as: r}\n\
         - extract: {source: r, name: v, type: u32le, offset: 0}\n\
         - match: {eq: {left: '$v', right: 307214}}\nresult: {family: t, protocol: t}\n",
    )
    .await
    .unwrap();
    let compiled = dsl::load_probes(
        &[path],
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .unwrap()
    .remove(0);
    let result = execute(addr.ip(), addr.port(), compiled.as_ref()).await;
    server.await.unwrap();
    assert!(!result.confirmed);
    assert!(result.responsive);
    assert_eq!(result.status, "protocol_mismatch");
}

#[tokio::test]
async fn connection_refused_is_not_reported_as_a_timeout() {
    // Binding and dropping a listener leaves a port that refuses connections.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let compiled = probe("vvas.yaml").await;
    let result = execute(addr.ip(), addr.port(), compiled.as_ref()).await;
    assert!(!result.confirmed);
    assert!(!result.responsive);
    assert!(
        matches!(
            result.status.as_str(),
            "connection_refused" | "connect_timeout"
        ),
        "unexpected status {}",
        result.status
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_probe_concurrency_is_enforced() {
    async fn mock(
        active: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(now, Ordering::SeqCst);
            let mut request = [0; 3];
            socket.read_exact(&mut request).await.unwrap();
            tokio::time::sleep(Duration::from_millis(75)).await;
            let mut response = [0; 14];
            response[..4].copy_from_slice(&307214u32.to_le_bytes());
            socket.write_all(&response).await.unwrap();
            active.fetch_sub(1, Ordering::SeqCst);
        });
        (address, task)
    }

    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let (first, first_task) = mock(active.clone(), maximum.clone()).await;
    let (second, second_task) = mock(active, maximum.clone()).await;
    let (input_tx, input_rx) = tokio::sync::mpsc::channel(2);
    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel(2);
    let scheduler = tokio::spawn(run_probes(
        input_rx,
        vec![probe("vvas.yaml").await],
        SchedulerConfig {
            global_concurrency: 2,
            per_host_concurrency: 2,
            per_probe_concurrency: 1,
            retries: 0,
            output_mode: OutputMode::Matched,
        },
        Arc::new(Metrics::default()),
        result_tx,
    ));
    for address in [first, second] {
        input_tx
            .send(OpenPort {
                ip: address.ip(),
                port: address.port(),
                syn_rtt_ms: None,
            })
            .await
            .unwrap();
    }
    drop(input_tx);
    scheduler.await.unwrap().unwrap();
    first_task.await.unwrap();
    second_task.await.unwrap();
    let mut matched = 0;
    while result_rx.recv().await.is_some() {
        matched += 1;
    }
    assert_eq!(matched, 2);
    assert_eq!(maximum.load(Ordering::SeqCst), 1);
}
