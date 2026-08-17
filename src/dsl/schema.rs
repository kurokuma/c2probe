use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeDocument {
    pub dsl_version: u32,
    pub name: String,
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(default)]
    pub scope: Scope,
    pub transport: Transport,
    pub steps: Vec<Step>,
    pub result: ResultSpec,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_plan_order")]
    pub plan_order: u32,
}

fn default_plan_order() -> u32 {
    1000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    #[serde(rename = "type")]
    pub kind: TransportType,
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub read_timeout_ms: Option<u64>,
    #[serde(default)]
    pub insecure_tls: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    /// Plaintext bytes sent before upgrading the same TCP stream to TLS.
    #[serde(default)]
    pub prelude_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Tcp,
    Tls,
    Starttls,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default)]
    pub send: Option<SendSpec>,
    #[serde(default)]
    pub literal: Option<LiteralSpec>,
    #[serde(default)]
    pub pack: Option<PackSpec>,
    #[serde(default)]
    pub concat: Option<ConcatSpec>,
    #[serde(default)]
    pub recv_exact: Option<RecvSpec>,
    #[serde(default)]
    pub recv_up_to: Option<RecvUpToSpec>,
    #[serde(default)]
    pub recv_until: Option<RecvUntilSpec>,
    #[serde(default)]
    pub recv_frame: Option<RecvFrameSpec>,
    #[serde(default)]
    pub recv_http: Option<RecvHttpSpec>,
    #[serde(default)]
    pub send_http: Option<SendHttpSpec>,
    #[serde(default)]
    pub reconnect: Option<EmptySpec>,
    #[serde(default)]
    pub peer_certificate: Option<PeerCertificateSpec>,
    #[serde(default)]
    pub transform: Option<TransformSpec>,
    #[serde(default)]
    pub reject_if: Option<RejectSpec>,
    #[serde(default)]
    pub extract: Option<ExtractSpec>,
    #[serde(default)]
    pub compute: Option<ComputeSpec>,
    #[serde(default, rename = "match")]
    pub match_value: Option<MatchSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptySpec {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiteralSpec {
    pub name: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendSpec {
    #[serde(default)]
    pub hex: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSpec {
    pub name: String,
    pub value: Expr,
    #[serde(rename = "type")]
    pub kind: PackType,
    /// Allow values wider than `type` to be truncated instead of failing.
    #[serde(default)]
    pub wrap: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackType {
    U8,
    U16le,
    U16be,
    U32le,
    U32be,
    U64le,
    U64be,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcatSpec {
    pub name: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecvSpec {
    pub bytes: usize,
    pub save_as: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecvUpToSpec {
    #[serde(default = "default_min_bytes")]
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub save_as: String,
}

fn default_min_bytes() -> usize {
    1
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecvUntilSpec {
    pub delimiter_hex: String,
    pub max_bytes: usize,
    pub save_as: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecvFrameSpec {
    #[serde(rename = "type")]
    pub kind: PackType,
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub save_as: String,
    pub length_as: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecvHttpSpec {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    #[serde(default)]
    pub headers_only: bool,
    pub body_as: String,
    pub header_as: String,
    pub status_as: String,
    pub content_length_as: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendHttpSpec {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body_source: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCertificateSpec {
    pub save_as: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformSpec {
    pub source: String,
    pub name: String,
    #[serde(default)]
    pub ascii_hex_decode: Option<EmptySpec>,
    #[serde(default)]
    pub base64_decode: Option<EmptySpec>,
    #[serde(default)]
    pub base64_encode: Option<EmptySpec>,
    #[serde(default)]
    pub rc4: Option<Rc4Spec>,
    #[serde(default)]
    pub gzip_decompress: Option<GzipSpec>,
    #[serde(default)]
    pub msgpack_string: Option<MsgpackStringSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rc4Spec {
    pub key_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GzipSpec {
    #[serde(default)]
    pub offset: usize,
    pub max_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgpackStringSpec {
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractSpec {
    pub source: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ExtractType,
    pub offset: usize,
    #[serde(default)]
    pub length: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractType {
    U8,
    U16le,
    U16be,
    U32le,
    U32be,
    U64le,
    U64be,
    Crc32,
    BufferLen,
    AsciiDecimal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeSpec {
    pub name: String,
    pub expr: Expr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Expr {
    Number(u64),
    Reference(String),
    Operation(Box<ExprOperation>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExprOperation {
    #[serde(default)]
    pub add: Option<BinaryExpr>,
    #[serde(default)]
    pub sub: Option<BinaryExpr>,
    #[serde(default)]
    pub xor: Option<BinaryExpr>,
    #[serde(default)]
    pub and: Option<BinaryExpr>,
    #[serde(default)]
    pub or: Option<BinaryExpr>,
    #[serde(default)]
    pub shift_left: Option<BinaryExpr>,
    #[serde(default)]
    pub shift_right: Option<BinaryExpr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryExpr {
    pub left: Expr,
    pub right: Expr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    #[serde(flatten)]
    pub condition: Condition,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectSpec {
    #[serde(flatten)]
    pub condition: Condition,
    pub status: String,
    #[serde(default)]
    pub confidence: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    #[serde(default)]
    pub all: Option<Vec<Condition>>,
    #[serde(default)]
    pub any: Option<Vec<Condition>>,
    #[serde(default)]
    pub not: Option<Box<Condition>>,
    #[serde(default)]
    pub eq: Option<Comparison>,
    #[serde(default)]
    pub ne: Option<Comparison>,
    #[serde(default)]
    pub lt: Option<Comparison>,
    #[serde(default)]
    pub gt: Option<Comparison>,
    #[serde(default)]
    pub bytes_eq: Option<BytesComparison>,
    #[serde(default)]
    pub bytes_contains: Option<BytesContains>,
    #[serde(default)]
    pub bytes_regex: Option<BytesRegex>,
    #[serde(default)]
    pub buffer_starts_with: Option<BufferPrefixComparison>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub left: Expr,
    pub right: Expr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytesComparison {
    pub source: String,
    pub offset: usize,
    pub hex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytesContains {
    pub source: String,
    pub hex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BytesRegex {
    pub source: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BufferPrefixComparison {
    pub source: String,
    pub prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSpec {
    pub family: String,
    pub protocol: String,
    #[serde(default)]
    pub classification: MatchClassification,
    #[serde(default = "default_confirmed")]
    pub confirmed: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub unmatched_confidence: f64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub unmatched_status: String,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchClassification {
    #[default]
    Confirmed,
    Probable,
    Observation,
}

fn default_confirmed() -> String {
    "$match".into()
}
fn default_confidence() -> f64 {
    0.95
}
