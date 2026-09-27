use c2probe::{dsl, probe::execute};
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn check_response(response: [u8; 3], expected_match: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 5];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [0x33, 0x66, 0x99, 0x01, b'c']);
        socket.write_all(&response).await.unwrap();
    });
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("probes/condi/registration.yaml");
    let probe = dsl::load_probes(
        &[path],
        None,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .unwrap()
    .remove(0);
    let result = execute(addr.ip(), addr.port(), &probe).await;
    server.await.unwrap();
    assert_eq!(result.probable, expected_match);
    assert!(!result.confirmed);
    assert_eq!(result.fields["followup_command_sent"], false);
}

#[tokio::test]
async fn documented_heartbeat_code_is_a_candidate() {
    check_response([0x99, 0x66, 0x33], true).await;
}

#[tokio::test]
async fn reflected_registration_prefix_is_not_a_candidate() {
    check_response([0x33, 0x66, 0x99], false).await;
}

#[tokio::test]
async fn unrelated_response_is_not_a_candidate() {
    check_response([0x01, 0x02, 0x03], false).await;
}
