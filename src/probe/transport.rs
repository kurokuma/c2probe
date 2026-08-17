use async_trait::async_trait;
#[cfg(feature = "tls")]
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
#[cfg(feature = "tls")]
use sha2::{Digest, Sha256};
#[cfg(feature = "tls")]
use std::{fmt::Debug, sync::Arc};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
#[cfg(feature = "tls")]
use tokio_rustls::TlsConnector;

use crate::dsl::{CompiledProbe, TransportType};

/// Failure categories from spec section 34. Classifying at the point of failure keeps
/// the reported status from depending on how an `io::Error` happens to be worded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeFailure {
    ConnectionRefused,
    ConnectTimeout,
    ReadTimeout,
    ConnectionReset,
    TlsError,
    InvalidResponse,
    ProbeError,
    InternalError,
}

impl ProbeFailure {
    pub fn status(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectTimeout => "connect_timeout",
            Self::ReadTimeout => "read_timeout",
            Self::ConnectionReset => "connection_reset",
            Self::TlsError => "tls_error",
            Self::InvalidResponse => "invalid_response",
            Self::ProbeError => "probe_error",
            Self::InternalError => "internal_error",
        }
    }
}

/// Transport-level `io::Error`s describe what the peer did, so they never map to the
/// probe-definition categories (`invalid_response`, `internal_error`).
fn from_io(error: &io::Error) -> ProbeFailure {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ProbeFailure::ConnectionRefused,
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => ProbeFailure::ConnectionReset,
        io::ErrorKind::TimedOut => ProbeFailure::ReadTimeout,
        io::ErrorKind::UnexpectedEof => ProbeFailure::ConnectionReset,
        _ => ProbeFailure::ProbeError,
    }
}

pub type ProbeResult<T> = Result<T, ProbeFailure>;

#[async_trait]
pub trait ProbeIo: Send {
    async fn send_all(&mut self, data: &[u8]) -> ProbeResult<()>;
    async fn recv_exact(&mut self, len: usize, d: Duration) -> ProbeResult<Vec<u8>>;
    async fn recv_up_to(&mut self, min: usize, max: usize, d: Duration) -> ProbeResult<Vec<u8>>;
    async fn recv_until(
        &mut self,
        delimiter: &[u8],
        max: usize,
        d: Duration,
    ) -> ProbeResult<Vec<u8>>;
    fn peer_certificate_sha256(&self) -> ProbeResult<[u8; 32]>;
}

async fn read_exact<S>(stream: &mut S, len: usize, d: Duration) -> ProbeResult<Vec<u8>>
where
    S: AsyncReadExt + Unpin + Send,
{
    let mut b = vec![0; len];
    match timeout(d, stream.read_exact(&mut b)).await {
        Err(_) => Err(ProbeFailure::ReadTimeout),
        Ok(Err(error)) => Err(from_io(&error)),
        Ok(Ok(_)) => Ok(b),
    }
}

async fn read_up_to<S>(stream: &mut S, min: usize, max: usize, d: Duration) -> ProbeResult<Vec<u8>>
where
    S: AsyncReadExt + Unpin + Send,
{
    let deadline = tokio::time::Instant::now() + d;
    let mut output = Vec::with_capacity(max.min(8192));
    let mut chunk = [0u8; 4096];
    while output.len() < max {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let wanted = chunk.len().min(max - output.len());
        match timeout(remaining, stream.read(&mut chunk[..wanted])).await {
            Err(_) => break,
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => output.extend_from_slice(&chunk[..read]),
            Ok(Err(error)) => return Err(from_io(&error)),
        }
    }
    if output.len() < min {
        if output.is_empty() {
            Err(ProbeFailure::ReadTimeout)
        } else {
            Err(ProbeFailure::InvalidResponse)
        }
    } else {
        Ok(output)
    }
}

async fn read_until<S>(
    stream: &mut S,
    delimiter: &[u8],
    max: usize,
    d: Duration,
) -> ProbeResult<Vec<u8>>
where
    S: AsyncReadExt + Unpin + Send,
{
    let future = async {
        let mut output = Vec::with_capacity(max.min(8192));
        let mut byte = [0u8; 1];
        while output.len() < max {
            match stream.read_exact(&mut byte).await {
                Ok(_) => {
                    output.push(byte[0]);
                    if output.ends_with(delimiter) {
                        return Ok(output);
                    }
                }
                Err(error) => return Err(from_io(&error)),
            }
        }
        Err(ProbeFailure::InvalidResponse)
    };
    timeout(d, future)
        .await
        .map_err(|_| ProbeFailure::ReadTimeout)?
}

pub struct TcpIo(TcpStream);
#[async_trait]
impl ProbeIo for TcpIo {
    async fn send_all(&mut self, data: &[u8]) -> ProbeResult<()> {
        self.0.write_all(data).await.map_err(|e| from_io(&e))
    }
    async fn recv_exact(&mut self, len: usize, d: Duration) -> ProbeResult<Vec<u8>> {
        read_exact(&mut self.0, len, d).await
    }
    async fn recv_up_to(&mut self, min: usize, max: usize, d: Duration) -> ProbeResult<Vec<u8>> {
        read_up_to(&mut self.0, min, max, d).await
    }
    async fn recv_until(
        &mut self,
        delimiter: &[u8],
        max: usize,
        d: Duration,
    ) -> ProbeResult<Vec<u8>> {
        read_until(&mut self.0, delimiter, max, d).await
    }
    fn peer_certificate_sha256(&self) -> ProbeResult<[u8; 32]> {
        Err(ProbeFailure::TlsError)
    }
}
#[cfg(feature = "tls")]
pub struct TlsIo(tokio_rustls::client::TlsStream<TcpStream>);
#[cfg(feature = "tls")]
#[async_trait]
impl ProbeIo for TlsIo {
    async fn send_all(&mut self, data: &[u8]) -> ProbeResult<()> {
        self.0.write_all(data).await.map_err(|e| from_io(&e))
    }
    async fn recv_exact(&mut self, len: usize, d: Duration) -> ProbeResult<Vec<u8>> {
        read_exact(&mut self.0, len, d).await
    }
    async fn recv_up_to(&mut self, min: usize, max: usize, d: Duration) -> ProbeResult<Vec<u8>> {
        read_up_to(&mut self.0, min, max, d).await
    }
    async fn recv_until(
        &mut self,
        delimiter: &[u8],
        max: usize,
        d: Duration,
    ) -> ProbeResult<Vec<u8>> {
        read_until(&mut self.0, delimiter, max, d).await
    }
    fn peer_certificate_sha256(&self) -> ProbeResult<[u8; 32]> {
        let certificate = self
            .0
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(ProbeFailure::TlsError)?;
        Ok(Sha256::digest(certificate.as_ref()).into())
    }
}

pub async fn connect(ip: IpAddr, port: u16, p: &CompiledProbe) -> ProbeResult<Box<dyn ProbeIo>> {
    let tcp = match timeout(
        p.connect_timeout,
        TcpStream::connect(SocketAddr::new(ip, port)),
    )
    .await
    {
        Err(_) => return Err(ProbeFailure::ConnectTimeout),
        Ok(Err(error)) => return Err(from_io(&error)),
        Ok(Ok(stream)) => stream,
    };
    tcp.set_nodelay(true).map_err(|e| from_io(&e))?;
    match p.transport {
        TransportType::Tcp => Ok(Box::new(TcpIo(tcp))),
        TransportType::Tls => connect_tls(ip, tcp, p).await,
        TransportType::Starttls => {
            let prelude = p.prelude.as_deref().ok_or(ProbeFailure::InternalError)?;
            let mut tcp = tcp;
            tcp.write_all(prelude)
                .await
                .map_err(|error| from_io(&error))?;
            connect_tls(ip, tcp, p).await
        }
    }
}

#[cfg(feature = "tls")]
async fn connect_tls(
    ip: IpAddr,
    tcp: TcpStream,
    p: &CompiledProbe,
) -> ProbeResult<Box<dyn ProbeIo>> {
    // The compiler rejects `type: tls` without `insecure_tls: true`, because this build
    // ships no root store and fingerprinting targets are not expected to present a
    // chain that would validate.
    debug_assert!(p.insecure_tls);
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let name = p
        .server_name
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| ip.to_string());
    let server = ServerName::try_from(name).map_err(|_| ProbeFailure::InternalError)?;
    let tls = match timeout(
        p.connect_timeout,
        TlsConnector::from(Arc::new(config)).connect(server, tcp),
    )
    .await
    {
        // A handshake that never completes is still a connect-phase timeout.
        Err(_) => return Err(ProbeFailure::ConnectTimeout),
        Ok(Err(_)) => return Err(ProbeFailure::TlsError),
        Ok(Ok(stream)) => stream,
    };
    Ok(Box::new(TlsIo(tls)))
}

#[cfg(not(feature = "tls"))]
async fn connect_tls(_: IpAddr, _: TcpStream, _: &CompiledProbe) -> ProbeResult<Box<dyn ProbeIo>> {
    Err(ProbeFailure::InternalError)
}

#[cfg(feature = "tls")]
#[derive(Debug)]
struct NoVerifier;
#[cfg(feature = "tls")]
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_map_to_peer_side_categories() {
        for (kind, expected) in [
            (
                io::ErrorKind::ConnectionRefused,
                ProbeFailure::ConnectionRefused,
            ),
            (
                io::ErrorKind::ConnectionReset,
                ProbeFailure::ConnectionReset,
            ),
            (io::ErrorKind::UnexpectedEof, ProbeFailure::ConnectionReset),
            (io::ErrorKind::TimedOut, ProbeFailure::ReadTimeout),
            (io::ErrorKind::AddrInUse, ProbeFailure::ProbeError),
        ] {
            assert_eq!(from_io(&io::Error::new(kind, "x")), expected);
        }
        assert_eq!(ProbeFailure::InternalError.status(), "internal_error");
    }
}
