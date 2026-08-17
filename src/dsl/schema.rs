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
    pub transport: Transport,
    pub steps: Vec<Step>,
    pub result: ResultSpec,
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
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Tcp,
    Tls,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    #[serde(default)]
    pub send: Option<SendSpec>,
    #[serde(default)]
    pub pack: Option<PackSpec>,
    #[serde(default)]
    pub concat: Option<ConcatSpec>,
    #[serde(default)]
    pub recv_exact: Option<RecvSpec>,
    #[serde(default)]
    pub extract: Option<ExtractSpec>,
    #[serde(default)]
    pub compute: Option<ComputeSpec>,
    #[serde(default, rename = "match")]
    pub match_value: Option<MatchSpec>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSpec {
    pub family: String,
    pub protocol: String,
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

fn default_confirmed() -> String {
    "$match".into()
}
fn default_confidence() -> f64 {
    0.95
}
