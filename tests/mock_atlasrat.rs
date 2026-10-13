use c2probe::{dsl, probe::execute};
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn check_response(response: Vec<u8>, expected_match: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("mock server did not receive a connection")
            .unwrap();
        let mut request = [0u8; 8];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(request, *b"SFuck\0\0\0");
        // Exercise recv_exact across fragmented TCP writes.
        for chunk in response.chunks(257) {
            socket.write_all(chunk).await.unwrap();
        }
        socket.shutdown().await.unwrap();
        let mut followup = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut followup))
            .await
            .expect("probe did not close its connection")
            .unwrap();
        assert!(
            followup.is_empty(),
            "probe must not send follow-up commands"
        );
    });
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("probes/atlasrat/loader-sfuck.yaml");
    let probe = dsl::load_probes(
        &[path],
        None,
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .await
    .unwrap()
    .remove(0);
    let result = execute(addr.ip(), addr.port(), &probe).await;
    server.await.unwrap();
    assert_eq!(result.probable, expected_match);
    assert!(!result.confirmed);
    if expected_match {
        assert_eq!(result.fields["response_bytes_inspected"], 7174);
        assert_eq!(result.fields["payload_executed"], false);
    }
}

fn candidate_response() -> Vec<u8> {
    let mut response = vec![0; 7174];
    response[..5].copy_from_slice(&[0x48, 0x89, 0x5c, 0x24, 0x10]);
    response[7172..].copy_from_slice(b"MZ");
    response
}

#[tokio::test]
async fn documented_layout_is_probable() {
    check_response(candidate_response(), true).await;
}

#[tokio::test]
async fn matching_prologue_without_embedded_pe_is_rejected() {
    let mut response = candidate_response();
    response[7172] = 0;
    check_response(response, false).await;
}

#[tokio::test]
async fn embedded_pe_without_matching_prologue_is_rejected() {
    let mut response = candidate_response();
    response[0] = 0;
    check_response(response, false).await;
}

#[tokio::test]
async fn truncated_response_is_not_probable() {
    let mut response = candidate_response();
    response.pop();
    check_response(response, false).await;
}

#[tokio::test]
async fn reflected_checkin_is_not_probable() {
    check_response(b"SFuck\0\0\0".to_vec(), false).await;
}
