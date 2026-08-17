use base64::Engine;
use c2probe::{
    dsl::{self, CompiledProbe},
    probe::execute,
};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io::Write, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivateKeyDer},
};

async fn probe(path: &str, parameters: &[(&str, &str)]) -> Arc<CompiledProbe> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("probes")
        .join(path);
    let parameters = parameters
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect::<HashMap<_, _>>();
    dsl::load_probes_with_params(
        &[path],
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
        &parameters,
    )
    .await
    .unwrap()
    .remove(0)
}

#[tokio::test]
async fn ftp_banner_is_observation_not_agenttesla_confirmation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"220 mock FTP ready\r\n").await.unwrap();
    });
    let compiled = probe("agenttesla/ftp-banner.yaml", &[]).await;
    let result = execute(addr.ip(), addr.port(), &compiled).await;
    server.await.unwrap();
    assert!(result.observed);
    assert!(!result.confirmed);
    assert!(!result.probable);
}

#[tokio::test]
async fn darkcomet_raw_challenge_requires_the_reviewed_rc4_key() {
    let key = b"reviewed-key";
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(key);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ciphertext = rc4(b"IDTYPE", key);
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(&ciphertext).await.unwrap();
    });
    let compiled = probe(
        "darkcomet/raw.yaml",
        &[("darkcomet.key_base64", &encoded_key)],
    )
    .await;
    let result = execute(addr.ip(), addr.port(), &compiled).await;
    server.await.unwrap();
    assert!(result.confirmed);
    assert_eq!(result.status, "darkcomet_server_first_idtype_match");
}

#[tokio::test]
async fn asyncrat_ping_validates_length_gzip_and_messagepack() {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let mut request = [0u8; 50];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(u32::from_le_bytes(request[..4].try_into().unwrap()), 46);

        let messagepack = b"\x81\xa6Packet\xa4pong";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(messagepack).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut payload = (messagepack.len() as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(&compressed);
        socket
            .write_all(&(payload.len() as u32).to_le_bytes())
            .await
            .unwrap();
        socket.write_all(&payload).await.unwrap();
    });
    let compiled = probe("dotnet-rat/asyncrat.yaml", &[]).await;
    let result = execute(addr.ip(), addr.port(), &compiled).await;
    server.await.unwrap();
    assert!(result.confirmed);
    assert_eq!(result.fields["response_packet"], "pong");
}

#[tokio::test]
async fn redline_sends_the_reviewed_vector_and_accepts_only_boolean_envelope() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 357];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&request)),
            "dd8c02ce792cd8d4e9ce3e05c32ff19c8d1633d24312203b9ec5018645e45f33"
        );
        let body = concat!(
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">",
            "<s:Body><CheckConnectResponse xmlns=\"http://tempuri.org/\">",
            "<CheckConnectResult>true</CheckConnectResult>",
            "</CheckConnectResponse></s:Body></s:Envelope>"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
    });
    let compiled = probe("redline/checkconnect-production.yaml", &[]).await;
    let result = execute(addr.ip(), addr.port(), &compiled).await;
    server.await.unwrap();
    assert!(result.confirmed);
    assert_eq!(result.status, "redline_checkconnect_boolean_match");
}

fn rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut state = [0u8; 256];
    for (index, value) in state.iter_mut().enumerate() {
        *value = index as u8;
    }
    let mut right = 0usize;
    for left in 0..256 {
        right = (right + usize::from(state[left]) + usize::from(key[left % key.len()])) & 0xff;
        state.swap(left, right);
    }
    let (mut left, mut right) = (0usize, 0usize);
    data.iter()
        .map(|byte| {
            left = (left + 1) & 0xff;
            right = (right + usize::from(state[left])) & 0xff;
            state.swap(left, right);
            byte ^ state[(usize::from(state[left]) + usize::from(state[right])) & 0xff]
        })
        .collect()
}
