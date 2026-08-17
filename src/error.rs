use thiserror::Error;

#[derive(Debug, Error)]
pub enum C2ProbeError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("invalid port specification: {0}")]
    InvalidPorts(String),
    #[error("invalid probe: {0}")]
    InvalidProbe(String),
    #[error("raw SYN discovery is supported only on Linux")]
    DiscoveryUnsupported,
    #[error("raw SYN discovery requires CAP_NET_RAW or root")]
    MissingRawCapability,
}
