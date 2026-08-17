use super::TransportType;
use ipnet::IpNet;
use regex::bytes::Regex;
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Debug, Clone)]
pub struct CompiledProbe {
    pub name: Arc<str>,
    pub plan_order: u32,
    pub family: Arc<str>,
    pub protocol: Arc<str>,
    pub transport: TransportType,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub insecure_tls: bool,
    pub server_name: Option<Arc<str>>,
    pub prelude: Option<Arc<[u8]>>,
    pub scope_ips: Arc<[IpNet]>,
    pub scope_ports: Arc<[u16]>,
    pub ops: Arc<[Op]>,
    pub result: CompiledResult,
}

#[derive(Debug, Clone)]
pub enum Op {
    SendLiteral(Arc<[u8]>),
    SendBuffer(usize),
    Literal {
        data: Arc<[u8]>,
        dst: usize,
    },
    Pack {
        expr: ValueExpr,
        kind: NumberKind,
        /// When false, a value that does not fit `kind` is an error instead of
        /// being silently truncated.
        wrap: bool,
        dst: usize,
    },
    Concat {
        sources: Arc<[usize]>,
        dst: usize,
    },
    RecvExact {
        length: usize,
        dst: usize,
    },
    RecvUpTo {
        min: usize,
        max: usize,
        dst: usize,
    },
    RecvUntil {
        delimiter: Arc<[u8]>,
        max: usize,
        dst: usize,
    },
    RecvFrame {
        kind: NumberKind,
        min: usize,
        max: usize,
        dst: usize,
        length_dst: usize,
    },
    RecvHttp {
        max_header: usize,
        max_body: usize,
        headers_only: bool,
        header_dst: usize,
        body_dst: usize,
        status_dst: usize,
        content_length_dst: usize,
    },
    SendHttp {
        method: Arc<str>,
        path: Arc<str>,
        headers: Arc<[(Arc<str>, Arc<str>)]>,
        body_src: Option<usize>,
    },
    Reconnect,
    PeerCertificateSha256 {
        dst: usize,
    },
    Transform {
        src: usize,
        dst: usize,
        kind: TransformKind,
    },
    RejectIf {
        condition: BoolExpr,
        confidence: f64,
        status: Arc<str>,
    },
    Extract {
        src: usize,
        offset: usize,
        kind: NumberKind,
        dst: usize,
    },
    Crc32 {
        src: usize,
        offset: usize,
        length: usize,
        dst: usize,
    },
    BufferLen {
        src: usize,
        dst: usize,
    },
    AsciiDecimal {
        src: usize,
        offset: usize,
        length: usize,
        dst: usize,
    },
    Compute {
        expr: ValueExpr,
        dst: usize,
    },
    Match {
        condition: BoolExpr,
        confidence: Option<f64>,
        status: Option<Arc<str>>,
    },
}

#[derive(Debug, Clone)]
pub enum TransformKind {
    AsciiHexDecode,
    Base64Decode,
    Base64Encode,
    Rc4(Arc<[u8]>),
    GzipDecompress { offset: usize, max: usize },
    MsgpackString { key: Arc<str> },
}

#[derive(Debug, Clone, Copy)]
pub enum NumberKind {
    U8,
    U16Le,
    U16Be,
    U32Le,
    U32Be,
    U64Le,
    U64Be,
}

impl NumberKind {
    pub fn size(self) -> usize {
        match self {
            NumberKind::U8 => 1,
            NumberKind::U16Le | NumberKind::U16Be => 2,
            NumberKind::U32Le | NumberKind::U32Be => 4,
            NumberKind::U64Le | NumberKind::U64Be => 8,
        }
    }

    /// Largest value representable in this width, used to reject silent truncation.
    pub fn max_value(self) -> u64 {
        match self.size() {
            1 => u64::from(u8::MAX),
            2 => u64::from(u16::MAX),
            4 => u64::from(u32::MAX),
            _ => u64::MAX,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValueExpr {
    Literal(u64),
    Register(usize),
    Add(Box<ValueExpr>, Box<ValueExpr>),
    Sub(Box<ValueExpr>, Box<ValueExpr>),
    Xor(Box<ValueExpr>, Box<ValueExpr>),
    And(Box<ValueExpr>, Box<ValueExpr>),
    Or(Box<ValueExpr>, Box<ValueExpr>),
    ShiftLeft(Box<ValueExpr>, Box<ValueExpr>),
    ShiftRight(Box<ValueExpr>, Box<ValueExpr>),
}

#[derive(Debug, Clone)]
pub enum BoolExpr {
    All(Vec<BoolExpr>),
    Any(Vec<BoolExpr>),
    Not(Box<BoolExpr>),
    Eq(ValueExpr, ValueExpr),
    Ne(ValueExpr, ValueExpr),
    Lt(ValueExpr, ValueExpr),
    Gt(ValueExpr, ValueExpr),
    BytesEq {
        src: usize,
        offset: usize,
        bytes: Arc<[u8]>,
    },
    BytesContains {
        src: usize,
        bytes: Arc<[u8]>,
    },
    BytesRegex {
        src: usize,
        regex: Arc<Regex>,
    },
    BufferStartsWith {
        src: usize,
        prefix: usize,
    },
}

#[derive(Debug, Clone)]
pub struct CompiledResult {
    pub classification: MatchClass,
    pub confidence: f64,
    pub unmatched_confidence: f64,
    pub status: Arc<str>,
    pub unmatched_status: Arc<str>,
    pub fields: BTreeMap<String, FieldTemplate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchClass {
    Confirmed,
    Probable,
    Observation,
}

impl CompiledProbe {
    pub fn allows(&self, ip: std::net::IpAddr, port: u16) -> bool {
        (self.scope_ips.is_empty() || self.scope_ips.iter().any(|net| net.contains(&ip)))
            && (self.scope_ports.is_empty() || self.scope_ports.contains(&port))
    }
}

#[derive(Debug, Clone)]
pub enum FieldTemplate {
    Register(usize),
    BufferHex(usize),
    BufferText(usize),
    Rejected,
    Literal(Value),
}
