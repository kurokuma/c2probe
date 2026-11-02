use c2probe::{
    dsl,
    dsl::CompiledProbe,
    probe::{ProbeExecution, execute},
};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivateKeyDer},
};

const LOGS_PIN: &str = "9e254cab8c68944cea18a3ac5523fe491eb14f9447b352dca33729b64eaeeac3";
const PRELUDE_PIN: &str = "67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b";
const DIRECT_PIN: &str = "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57";

fn params() -> HashMap<String, String> {
    HashMap::from([
        (
            "purelogs.acknowledge_profile".into(),
            "purelogs-0f2abaab-logs-uvexio-8443-ping-v1".into(),
        ),
        (
            "purerat.acknowledge_profile".into(),
            "purerat-e554-tirakian-legacy-prelude".into(),
        ),
        ("purerat.tirakian_ip".into(), "192.0.2.15".into()),
    ])
}

async fn load(name: &str, pin_override: Option<&str>) -> Arc<CompiledProbe> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut source = std::fs::read_to_string(root.join("probes").join(name)).unwrap();
    // Only the test copy's certificate is replaced. Production scope, acknowledgement,
    // requests, and response checks stay intact. execute is called directly on loopback.
    if let Some(pin) = pin_override {
        for expected in [LOGS_PIN, PRELUDE_PIN, DIRECT_PIN] {
            source = source.replace(expected, pin);
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("probe.yaml");
    std::fs::write(&path, source).unwrap();
    dsl::load_probes_with_params(
        &[path],
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &params(),
    )
    .await
    .unwrap()
    .remove(0)
}

async fn exercise(name: &str, response: &[u8], matching_pin: bool) -> (ProbeExecution, Vec<u8>) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pin = hex::encode(Sha256::digest(generated.cert.der()));
    let compiled = load(name, matching_pin.then_some(pin.as_str())).await;
    let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert!(
        !compiled.allows(addr.ip(), addr.port()),
        "production scope must exclude loopback"
    );
    let prelude = compiled.prelude.clone();
    let expect_http = name.starts_with("purelogs") && matching_pin;
    let response = response.to_vec();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            if let Some(prelude) = prelude {
                let mut received = vec![0; prelude.len()];
                socket.read_exact(&mut received).await.unwrap();
                assert_eq!(received, [4, 0, 0, 0]);
            }
            let mut socket = acceptor.accept(socket).await.unwrap();
            let mut request = Vec::new();
            if expect_http {
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                    assert!(request.len() <= 256);
                }
                // Fragmentation must not affect the bounded parser.
                for chunk in response.chunks(17) {
                    if socket.write_all(chunk).await.is_err() {
                        break;
                    }
                }
                let _ = socket.shutdown().await;
            }
            let mut extra = Vec::new();
            // rustls clients may close without close_notify; any application bytes
            // still appear in extra before EOF/UnexpectedEof.
            let _ = socket.read_to_end(&mut extra).await;
            assert!(extra.is_empty(), "unexpected follow-up/application data");
            request
        })
        .await
        .expect("local mock timed out")
    });
    let result = execute(addr.ip(), addr.port(), &compiled).await;
    (result, server.await.unwrap())
}

#[tokio::test]
async fn purelogs_requires_certificate_before_sending_the_single_ping() {
    let (result, request) = exercise("purelogs/https-ping.yaml", b"", false).await;
    assert!(request.is_empty());
    assert_eq!(
        result.status,
        "purelogs_certificate_mismatch_no_request_sent"
    );
    assert!(!result.probable && !result.confirmed);
    assert_eq!(result.confidence, 0.0);
}

#[tokio::test]
async fn purelogs_exact_ok_is_probable_without_publishing_body() {
    let (result, request) = exercise(
        "purelogs/https-ping.yaml",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        true,
    )
    .await;
    let request = String::from_utf8(request).unwrap();
    assert!(request.starts_with("GET /ping HTTP/1.1\r\n"));
    assert!(request.contains("Host: logs.uvexio.com\r\n"));
    assert!(request.ends_with("\r\n\r\n"));
    assert!(result.probable && !result.confirmed);
    assert_eq!(result.confidence, 0.70);
    assert_eq!(result.fields["response_body_published"], false);
    assert!(!result.fields.contains_key("body"));
}

#[tokio::test]
async fn purelogs_rejects_redirects_malformed_and_nonexact_responses() {
    for response in [
        "HTTP/1.1 302 Found\r\nContent-Length: 2\r\nLocation: /other\r\n\r\nOK",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nNO",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nO",
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK!",
        "HTTP/1.1 200 OK\r\n\r\nOK",
        "HTTP/1.1 200 OK\r\nContent-Length: 02\r\n\r\nOK",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nOK",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Encoding: gzip\r\n\r\nOK",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: \x01\r\n\r\nOK",
        "HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nOK",
        "GET /ping HTTP/1.1\r\nHost: logs.uvexio.com\r\n\r\n",
    ] {
        let (result, _) = exercise("purelogs/https-ping.yaml", response.as_bytes(), true).await;
        assert!(
            !result.probable && !result.confirmed,
            "accepted {response:?}"
        );
        assert_eq!(result.confidence, 0.0);
    }
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nX-Pad: {}\r\nContent-Length: 2\r\n\r\nOK",
        "a".repeat(1022)
    );
    let (result, _) = exercise("purelogs/https-ping.yaml", oversized.as_bytes(), true).await;
    assert!(!result.probable && !result.confirmed);
}

#[tokio::test]
async fn purerat_certificate_matches_are_only_probable_and_mismatches_are_inconclusive() {
    for (name, confidence) in [
        ("purerat/prelude-tls-cert.yaml", 0.60),
        ("purerat/direct-tls-d025.yaml", 0.75),
    ] {
        for matching in [true, false] {
            let (result, request) = exercise(name, b"", matching).await;
            assert!(request.is_empty());
            assert_eq!(result.probable, matching);
            assert!(!result.confirmed);
            assert_eq!(result.confidence, if matching { confidence } else { 0.0 });
            assert_eq!(result.fields["certificate_mismatch_excludes_c2"], false);
            assert_eq!(result.fields["tls_version_enforced"], false);
        }
    }
    let (result, _) = exercise("purerat/prelude-tls-observe.yaml", b"", false).await;
    assert!(result.observed && !result.probable && !result.confirmed);
}

#[tokio::test]
async fn pure_profile_scopes_and_acknowledgements_fail_closed() {
    let logs = load("purelogs/https-ping.yaml", None).await;
    assert!(logs.allows("193.26.115.118".parse().unwrap(), 8443));
    assert!(!logs.allows("193.26.115.119".parse().unwrap(), 8443));
    assert!(!logs.allows("193.26.115.118".parse().unwrap(), 443));
    let rat = load("purerat/prelude-tls-cert.yaml", None).await;
    for port in [56001, 56002, 56003] {
        assert!(rat.allows("192.0.2.15".parse().unwrap(), port));
    }
    assert!(!rat.allows("192.0.2.16".parse().unwrap(), 56001));
    assert!(!rat.allows("192.0.2.15".parse().unwrap(), 443));
    let direct = load("purerat/direct-tls-d025.yaml", None).await;
    assert!(direct.allows("45.192.211.77".parse().unwrap(), 56001));
    assert!(!direct.allows("45.192.211.78".parse().unwrap(), 56001));
    for (name, key) in [
        ("purelogs/https-ping.yaml", "purelogs.acknowledge_profile"),
        (
            "purerat/prelude-tls-cert.yaml",
            "purerat.acknowledge_profile",
        ),
        (
            "purerat/prelude-tls-observe.yaml",
            "purerat.acknowledge_profile",
        ),
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("probes")
            .join(name);
        for value in [None, Some("wrong-profile")] {
            let mut parameters = params();
            parameters.remove(key);
            if let Some(value) = value {
                parameters.insert(key.into(), value.into());
            }
            assert!(
                dsl::load_probes_with_params(
                    std::slice::from_ref(&path),
                    None,
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    &parameters
                )
                .await
                .is_err()
            );
        }
    }
}
