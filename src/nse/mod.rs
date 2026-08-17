//! Strict, non-executing conversion of reviewed NSE fingerprints into probe YAML.
//!
//! NSE is general-purpose Lua, so this module deliberately recognises a bounded
//! profile instead of pretending that arbitrary scripts can be translated safely.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_NSE_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct ConversionBundle {
    pub probes: Vec<GeneratedProbe>,
    pub report: ConversionReport,
}

#[derive(Debug)]
pub struct GeneratedProbe {
    pub filename: String,
    pub yaml: String,
}

#[derive(Debug, Serialize)]
pub struct ConversionReport {
    pub converter: &'static str,
    pub profile: &'static str,
    pub source: String,
    pub source_bytes: usize,
    pub detected_modes: Vec<String>,
    pub generated_rules: Vec<RuleReport>,
    pub unsupported_semantics: Vec<String>,
    pub safety: SafetyReport,
}

#[derive(Debug, Serialize)]
pub struct RuleReport {
    pub mode: String,
    pub file: String,
    pub equivalence: &'static str,
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SafetyReport {
    pub nse_executed: bool,
    pub unknown_require_rejected: bool,
    pub dangerous_api_rejected: bool,
    pub generated_yaml_compiled: bool,
}

/// Convert the reviewed ValleyRAT NSE profile. The source is tokenised and its
/// network operations and match constants are checked before any YAML is emitted.
pub fn convert_valleyrat(source: &str) -> Result<ConversionBundle> {
    if source.len() > MAX_NSE_BYTES {
        bail!("NSE source exceeds 1 MiB");
    }
    let tokens = lex(source)?;
    reject_unsafe_or_unknown_apis(&tokens)?;

    let functions = local_functions(&tokens)?;
    let winos = function(&functions, "winos")?;
    let vvas = function(&functions, "vvas")?;
    let n520 = function(&functions, "n520")?;
    let xor_payload = function(&functions, "xor_payload")?;

    require_action_modes(&tokens)?;
    validate_network_operation_counts(&tokens)?;

    let w = parse_winos(winos, xor_payload)?;
    let v = parse_vvas(vvas)?;
    let n = parse_n520(n520)?;

    let probes = vec![
        GeneratedProbe {
            filename: "winos.yaml".into(),
            yaml: winos_yaml(&w),
        },
        GeneratedProbe {
            filename: "vvas.yaml".into(),
            yaml: vvas_yaml(&v),
        },
        GeneratedProbe {
            filename: "n520.yaml".into(),
            yaml: n520_yaml(&n),
        },
    ];
    let generated_rules = vec![
        RuleReport {
            mode: "winos".into(),
            file: "winos.yaml".into(),
            equivalence: "conservative_subset",
            evidence: vec![
                format!("TCP request length {}", w.frame_length),
                format!("response length {}", w.receive_bytes),
                format!("commands {:?}", w.response_commands),
                "XOR mask derives from header byte plus 0x36".into(),
                "reflected request prefix is rejected before protocol matching".into(),
            ],
        },
        RuleReport {
            mode: "vvas".into(),
            file: "vvas.yaml".into(),
            equivalence: "core_match_equivalent",
            evidence: vec![
                format!("request {:02x?}", v.request),
                format!("response length {}", v.receive_bytes),
                format!("stage size {}", v.stage_size),
                format!("zero suffix length {}", v.zero_suffix),
            ],
        },
        RuleReport {
            mode: "n520".into(),
            file: "n520.yaml".into(),
            equivalence: "core_match_equivalent",
            evidence: vec![
                "TLS server-first response".into(),
                format!("response length {}", n.receive_bytes),
                format!("magic mix 0x{:08x}", n.magic_or),
                format!("CRC32 covers first {} bytes", n.crc_length),
            ],
        },
    ];
    Ok(ConversionBundle {
        probes,
        report: ConversionReport {
            converter: "c2probe-nse2yaml/1",
            profile: "valleyrat-reviewed-minimal",
            source: "in-memory".into(),
            source_bytes: source.len(),
            detected_modes: vec!["winos".into(), "vvas".into(), "n520".into()],
            generated_rules,
            unsupported_semantics: vec![
                "NSE-specific connect/send/receive error status text is handled by the c2probe transport executor".into(),
                "Winos NSE accepts declared lengths 15..64; the generated minimal rule requires the 15-byte control frame".into(),
                "Informational byte counts and attempted-operation fields are reduced to the defensive fields emitted by DSL v1".into(),
            ],
            safety: SafetyReport {
                nse_executed: false,
                unknown_require_rejected: true,
                dangerous_api_rejected: true,
                generated_yaml_compiled: false,
            },
        },
    })
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    String(String),
    Number(u64),
    Symbol(String),
}

fn lex(source: &str) -> Result<Vec<Token>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
        } else if b == b'-' && bytes.get(i + 1) == Some(&b'-') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'[' && bytes.get(i + 1) == Some(&b'[') {
            i += 2;
            let start = i;
            while i + 1 < bytes.len() && !(bytes[i] == b']' && bytes[i + 1] == b']') {
                i += 1;
            }
            if i + 1 >= bytes.len() {
                bail!("unterminated Lua long string");
            }
            tokens.push(Token::String(source[start..i].to_owned()));
            i += 2;
        } else if b == b'\'' || b == b'"' {
            let quote = b;
            i += 1;
            let mut value = String::new();
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 1;
                    let escaped = *bytes.get(i).context("unterminated Lua string escape")?;
                    value.push(match escaped {
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'0' => '\0',
                        other => other as char,
                    });
                } else {
                    let ch = source[i..]
                        .chars()
                        .next()
                        .context("invalid UTF-8 boundary in Lua string")?;
                    value.push(ch);
                    i += ch.len_utf8().saturating_sub(1);
                }
                i += 1;
            }
            if i >= bytes.len() {
                bail!("unterminated Lua string");
            }
            i += 1;
            tokens.push(Token::String(value));
        } else if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            tokens.push(Token::Ident(source[start..i].to_owned()));
        } else if b.is_ascii_digit() {
            let start = i;
            i += 1;
            if b == b'0' && matches!(bytes.get(i), Some(b'x' | b'X')) {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let value = u64::from_str_radix(&source[start + 2..i], 16)
                    .with_context(|| format!("invalid hex number {}", &source[start..i]))?;
                tokens.push(Token::Number(value));
            } else {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                // Confidence values are not used as structural constants. Keep the
                // integer portion and consume the fraction so it cannot look like
                // a second unrelated number to the recogniser.
                if bytes.get(i) == Some(&b'.') {
                    i += 1;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    tokens.push(Token::Symbol(source[start..i].to_owned()));
                } else {
                    tokens.push(Token::Number(source[start..i].parse()?));
                }
            }
        } else {
            let two = bytes
                .get(i..i + 2)
                .and_then(|v| std::str::from_utf8(v).ok());
            if matches!(two, Some("==" | "~=" | ">>" | "<<" | "<=" | ">=" | "..")) {
                tokens.push(Token::Symbol(two.expect("matched").to_owned()));
                i += 2;
            } else {
                tokens.push(Token::Symbol((b as char).to_string()));
                i += 1;
            }
        }
    }
    Ok(tokens)
}

fn reject_unsafe_or_unknown_apis(tokens: &[Token]) -> Result<()> {
    let allowed = BTreeSet::from(["nmap", "stdnse", "zlib"]);
    for (index, token) in tokens.iter().enumerate() {
        if token == &Token::Ident("require".into()) {
            let mut argument = index + 1;
            if tokens.get(argument) == Some(&Token::Symbol("(".into())) {
                argument += 1;
            }
            match tokens.get(argument) {
                Some(Token::String(module)) if allowed.contains(module.as_str()) => {}
                Some(Token::String(module)) => bail!("unsupported Lua module: {module}"),
                _ => bail!("dynamic require is not convertible"),
            }
        }
    }
    let dangerous = [
        "dofile",
        "load",
        "loadfile",
        "loadstring",
        "execute",
        "popen",
        "remove",
        "rename",
    ];
    for name in dangerous {
        if tokens.iter().any(|t| t == &Token::Ident(name.into())) {
            bail!("dangerous or dynamic Lua API is not convertible: {name}");
        }
    }
    for namespace in ["io", "os", "package", "debug"] {
        if contains_sequence(
            tokens,
            &[Token::Ident(namespace.into()), Token::Symbol(".".into())],
        ) {
            bail!("dangerous Lua namespace is not convertible: {namespace}");
        }
    }
    let allowed_socket_methods =
        BTreeSet::from(["set_timeout", "connect", "close", "send", "receive_bytes"]);
    for window in tokens.windows(4) {
        if window[0] == Token::Ident("socket".into())
            && window[1] == Token::Symbol(":".into())
            && window[3] == Token::Symbol("(".into())
            && let Token::Ident(method) = &window[2]
            && !allowed_socket_methods.contains(method.as_str())
        {
            bail!("unsupported socket method: {method}");
        }
    }
    Ok(())
}

fn local_functions(tokens: &[Token]) -> Result<BTreeMap<String, Vec<Token>>> {
    let mut functions = BTreeMap::new();
    let mut i = 0;
    while i + 2 < tokens.len() {
        if tokens[i] == Token::Ident("local".into())
            && tokens[i + 1] == Token::Ident("function".into())
            && let Token::Ident(name) = &tokens[i + 2]
        {
            let start = i + 3;
            let mut depth = 1usize;
            let mut j = start;
            while j < tokens.len() {
                match &tokens[j] {
                    Token::Ident(keyword)
                        if matches!(keyword.as_str(), "function" | "if" | "do") =>
                    {
                        depth += 1
                    }
                    Token::Ident(keyword) if keyword == "end" => {
                        depth -= 1;
                        if depth == 0 {
                            functions.insert(name.clone(), tokens[start..j].to_vec());
                            i = j;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if depth != 0 {
                bail!("unterminated Lua function {name}");
            }
        }
        i += 1;
    }
    let allowed = BTreeSet::from([
        "timeout_ms",
        "connect",
        "xor_payload",
        "winos",
        "vvas",
        "n520",
    ]);
    if let Some(name) = functions
        .keys()
        .find(|name| !allowed.contains(name.as_str()))
    {
        bail!("unsupported local Lua function: {name}");
    }
    Ok(functions)
}

fn function<'a>(functions: &'a BTreeMap<String, Vec<Token>>, name: &str) -> Result<&'a [Token]> {
    functions
        .get(name)
        .map(Vec::as_slice)
        .with_context(|| format!("required Lua function is missing: {name}"))
}

fn require_action_modes(tokens: &[Token]) -> Result<()> {
    for mode in ["winos", "vvas", "n520"] {
        let comparison = [
            Token::Ident("mode".into()),
            Token::Symbol("==".into()),
            Token::String(mode.into()),
        ];
        let call = [Token::Ident(mode.into()), Token::Symbol("(".into())];
        if !contains_sequence(tokens, &comparison) || !contains_sequence(tokens, &call) {
            bail!("action does not explicitly dispatch mode {mode}");
        }
    }
    Ok(())
}

fn validate_network_operation_counts(tokens: &[Token]) -> Result<()> {
    let sends = count_sequence(tokens, &method("socket", "send"));
    let receives = count_sequence(tokens, &method("socket", "receive_bytes"));
    if sends != 2 || receives != 3 {
        bail!("unexpected network operation count: send={sends}, receive_bytes={receives}");
    }
    Ok(())
}

fn method(object: &str, name: &str) -> Vec<Token> {
    vec![
        Token::Ident(object.into()),
        Token::Symbol(":".into()),
        Token::Ident(name.into()),
    ]
}

#[derive(Debug)]
struct WinosProfile {
    frame_length: u64,
    magic: u64,
    reserved: u64,
    request_type: u64,
    request_command: u64,
    header_first: u64,
    mask_add: u64,
    receive_bytes: u64,
    response_commands: Vec<u64>,
}

fn parse_winos(tokens: &[Token], xor: &[Token]) -> Result<WinosProfile> {
    require_connect(tokens, "tcp")?;
    let header = call_numbers(tokens, &["string", "pack"], Some("<I4I4I2"))?;
    if header.len() != 3 {
        bail!("Winos header pack must contain three values");
    }
    let length = call_numbers(tokens, &["string", "pack"], Some("<I4"))?;
    let request_command = call_numbers(tokens, &["string", "char"], None)?;
    let receive_bytes = method_number(tokens, "receive_bytes")?;
    for required in [201, 202, 203] {
        require_number(tokens, required, "Winos response command")?;
    }
    require_number(xor, 54, "Winos XOR mask")?;
    require_number(xor, 10, "Winos rotating header length")?;
    if !xor.contains(&Token::Symbol("~".into())) {
        bail!("Winos xor_payload does not contain bitwise XOR");
    }
    Ok(WinosProfile {
        frame_length: exactly_one(&length, "Winos frame length")?,
        magic: header[0],
        reserved: header[1],
        request_type: header[2],
        request_command: exactly_one(&request_command, "Winos request command")?,
        header_first: header[0] & 0xff,
        mask_add: 54,
        receive_bytes,
        response_commands: vec![201, 202, 203],
    })
}

#[derive(Debug)]
struct VvasProfile {
    request: Vec<u64>,
    receive_bytes: u64,
    stage_size: u64,
    zero_suffix: u64,
}

fn parse_vvas(tokens: &[Token]) -> Result<VvasProfile> {
    require_connect(tokens, "tcp")?;
    let request = call_numbers(tokens, &["string", "char"], None)?;
    if request != [0x33, 0x32, 0] {
        bail!("unsupported VVAS request bytes: {request:?}");
    }
    require_string(tokens, "<I4", "VVAS little-endian stage size")?;
    require_number(tokens, 307_214, "VVAS expected stage size")?;
    require_string(tokens, "\0", "VVAS zero suffix")?;
    Ok(VvasProfile {
        request,
        receive_bytes: method_number(tokens, "receive_bytes")?,
        stage_size: 307_214,
        zero_suffix: 10,
    })
}

#[derive(Debug)]
struct N520Profile {
    receive_bytes: u64,
    magic_or: u64,
    crc_offset: u64,
    crc_length: u64,
}

fn parse_n520(tokens: &[Token]) -> Result<N520Profile> {
    require_connect(tokens, "ssl")?;
    for (value, label) in [
        (16, "N520 high-word shift"),
        (0xffff, "N520 low-word mask"),
        (0xa5a50000, "N520 magic mix"),
        (0xffffffff, "N520 32-bit mask"),
        (41, "N520 CRC Lua offset"),
        (40, "N520 CRC length"),
    ] {
        require_number(tokens, value, label)?;
    }
    require_string(tokens, "<I4I4", "N520 header unpack")?;
    require_string(tokens, "<I4", "N520 CRC unpack")?;
    if count_ident(tokens, "crc32") < 2 {
        bail!("N520 nested zlib.crc32 calculation is missing");
    }
    Ok(N520Profile {
        receive_bytes: method_number(tokens, "receive_bytes")?,
        magic_or: 0xa5a50000,
        crc_offset: 40,
        crc_length: 40,
    })
}

fn require_connect(tokens: &[Token], protocol: &str) -> Result<()> {
    let pattern = [
        Token::Ident("connect".into()),
        Token::Symbol("(".into()),
        Token::Ident("host".into()),
        Token::Symbol(",".into()),
        Token::Ident("port".into()),
        Token::Symbol(",".into()),
        Token::String(protocol.into()),
    ];
    if !contains_sequence(tokens, &pattern) {
        bail!("expected connect(host, port, {protocol:?})");
    }
    Ok(())
}

fn method_number(tokens: &[Token], name: &str) -> Result<u64> {
    let prefix = [
        Token::Ident("socket".into()),
        Token::Symbol(":".into()),
        Token::Ident(name.into()),
        Token::Symbol("(".into()),
    ];
    let index =
        find_sequence(tokens, &prefix).with_context(|| format!("socket:{name} is missing"))?;
    match tokens.get(index + prefix.len()) {
        Some(Token::Number(value)) => Ok(*value),
        _ => bail!("socket:{name} requires a literal size"),
    }
}

fn call_numbers(tokens: &[Token], path: &[&str], first_string: Option<&str>) -> Result<Vec<u64>> {
    let mut prefix = Vec::new();
    for (index, component) in path.iter().enumerate() {
        if index > 0 {
            prefix.push(Token::Symbol(".".into()));
        }
        prefix.push(Token::Ident((*component).into()));
    }
    prefix.push(Token::Symbol("(".into()));
    if let Some(value) = first_string {
        prefix.push(Token::String(value.into()));
        prefix.push(Token::Symbol(",".into()));
    }
    let start = find_sequence(tokens, &prefix)
        .with_context(|| format!("Lua call is missing: {}", path.join(".")))?
        + prefix.len();
    let mut values = Vec::new();
    let mut depth = 1usize;
    for token in &tokens[start..] {
        match token {
            Token::Symbol(symbol) if symbol == "(" => depth += 1,
            Token::Symbol(symbol) if symbol == ")" => {
                depth -= 1;
                if depth == 0 {
                    return Ok(values);
                }
            }
            Token::Number(value) if depth == 1 => values.push(*value),
            Token::Symbol(symbol) if symbol == "," && depth == 1 => {}
            _ if depth == 1 => bail!("only literal numeric call arguments are supported"),
            _ => {}
        }
    }
    bail!("unterminated Lua call: {}", path.join("."))
}

fn exactly_one(values: &[u64], label: &str) -> Result<u64> {
    if let [value] = values {
        Ok(*value)
    } else {
        bail!("{label} must contain exactly one literal")
    }
}

fn require_number(tokens: &[Token], value: u64, label: &str) -> Result<()> {
    if !tokens.contains(&Token::Number(value)) {
        bail!("{label} constant is missing: {value}");
    }
    Ok(())
}

fn require_string(tokens: &[Token], value: &str, label: &str) -> Result<()> {
    if !tokens.contains(&Token::String(value.into())) {
        bail!("{label} string is missing: {value:?}");
    }
    Ok(())
}

fn count_ident(tokens: &[Token], name: &str) -> usize {
    tokens
        .iter()
        .filter(|token| token == &&Token::Ident(name.into()))
        .count()
}

fn contains_sequence(tokens: &[Token], pattern: &[Token]) -> bool {
    find_sequence(tokens, pattern).is_some()
}

fn find_sequence(tokens: &[Token], pattern: &[Token]) -> Option<usize> {
    if pattern.is_empty() {
        return Some(0);
    }
    tokens
        .windows(pattern.len())
        .position(|window| window == pattern)
}

fn count_sequence(tokens: &[Token], pattern: &[Token]) -> usize {
    if pattern.is_empty() {
        return 0;
    }
    tokens
        .windows(pattern.len())
        .filter(|w| *w == pattern)
        .count()
}

fn winos_yaml(p: &WinosProfile) -> String {
    format!(
        r#"dsl_version: 1
name: valleyrat-winos
metadata:
  family: valleyrat
  protocol: winos
  plan_order: 20
  description: Minimal heartbeat frame converted from reviewed NSE; no victim metadata or task request.
transport:
  type: tcp
  connect_timeout_ms: 1000
  read_timeout_ms: 1000
steps:
  - compute: {{ name: request_mask, expr: {{ add: {{ left: {header_first}, right: {mask_add} }} }} }}
  - compute: {{ name: request_command, expr: {{ xor: {{ left: {request_command}, right: "$request_mask" }} }} }}
  - pack: {{ name: request_length, type: u32le, value: {frame_length} }}
  - pack: {{ name: request_magic, type: u32le, value: {magic} }}
  - pack: {{ name: request_reserved, type: u32le, value: {reserved} }}
  - pack: {{ name: request_type, type: u16le, value: {request_type} }}
  - pack: {{ name: request_payload, type: u8, value: "$request_command" }}
  - concat:
      name: request
      sources: ["$request_length", "$request_magic", "$request_reserved", "$request_type", "$request_payload"]
  - send: {{ source: "$request" }}
  - recv_exact: {{ bytes: {receive_bytes}, save_as: response }}
  - extract: {{ source: response, name: declared_length, type: u32le, offset: 0 }}
  - extract: {{ source: response, name: response_header_first, type: u8, offset: 4 }}
  - extract: {{ source: response, name: encrypted_command, type: u8, offset: 14 }}
  - compute: {{ name: mask, expr: {{ add: {{ left: "$response_header_first", right: {mask_add} }} }} }}
  - compute: {{ name: response_command, expr: {{ xor: {{ left: "$encrypted_command", right: "$mask" }} }} }}
  - reject_if:
      buffer_starts_with: {{ source: response, prefix: request }}
      confidence: 0.0
      status: winos_request_reflected
  - match:
      all:
        - eq: {{ left: "$declared_length", right: {frame_length} }}
        - any:
            - eq: {{ left: "$response_command", right: {command0} }}
            - eq: {{ left: "$response_command", right: {command1} }}
            - eq: {{ left: "$response_command", right: {command2} }}
result:
  family: valleyrat
  protocol: winos
  confirmed: "$match"
  confidence: 0.95
  unmatched_confidence: 0.45
  status: winos_control_response
  unmatched_status: winos_unknown_response
  fields:
    declared_length: "$declared_length"
    response_command: "$response_command"
    request_reflected: "$rejected"
    victim_metadata_sent: false
    stage_requested: false
"#,
        header_first = p.header_first,
        mask_add = p.mask_add,
        request_command = p.request_command,
        frame_length = p.frame_length,
        magic = p.magic,
        reserved = p.reserved,
        request_type = p.request_type,
        receive_bytes = p.receive_bytes,
        command0 = p.response_commands[0],
        command1 = p.response_commands[1],
        command2 = p.response_commands[2],
    )
}

fn vvas_yaml(p: &VvasProfile) -> String {
    let request = p
        .request
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let zeros = std::iter::repeat_n("00", p.zero_suffix as usize)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"dsl_version: 1
name: valleyrat-vvas
metadata:
  family: valleyrat
  protocol: vvas
  plan_order: 30
  description: Minimal VVAS stage-header fingerprint converted from reviewed NSE; stage data is not requested.
transport:
  type: tcp
  connect_timeout_ms: 1000
  read_timeout_ms: 1000
steps:
  - send: {{ hex: "{request}" }}
  - recv_exact: {{ bytes: {receive_bytes}, save_as: response }}
  - extract: {{ source: response, name: stage_size, type: u32le, offset: 0 }}
  - match:
      all:
        - eq: {{ left: "$stage_size", right: {stage_size} }}
        - bytes_eq: {{ source: response, offset: 4, hex: "{zeros}" }}
result:
  family: valleyrat
  protocol: vvas
  confirmed: "$match"
  confidence: 0.95
  unmatched_confidence: 0.35
  status: vvas_stage_header_match
  unmatched_status: vvas_header_mismatch
  fields:
    declared_stage_size: "$stage_size"
    expected_stage_size: {stage_size}
    stage_downloaded: false
    victim_metadata_sent: false
"#,
        request = request,
        receive_bytes = p.receive_bytes,
        stage_size = p.stage_size,
        zeros = zeros,
    )
}

fn n520_yaml(p: &N520Profile) -> String {
    format!(
        r#"dsl_version: 1
name: valleyrat-n520
metadata:
  family: valleyrat
  protocol: n520
  plan_order: 10
  description: TLS server-first handshake converted from reviewed NSE; sends no application data.
transport:
  type: tls
  connect_timeout_ms: 1000
  read_timeout_ms: 1000
  insecure_tls: true
steps:
  - recv_exact: {{ bytes: {receive_bytes}, save_as: response }}
  - extract: {{ source: response, name: session_id, type: u32le, offset: 0 }}
  - extract: {{ source: response, name: received_magic, type: u32le, offset: 4 }}
  - extract: {{ source: response, name: stored_crc, type: u32le, offset: {crc_offset} }}
  - extract: {{ source: response, name: calculated_crc, type: crc32, offset: 0, length: {crc_length} }}
  - compute: {{ name: session_high, expr: {{ shift_right: {{ left: "$session_id", right: 16 }} }} }}
  - compute: {{ name: session_low, expr: {{ and: {{ left: "$session_id", right: 65535 }} }} }}
  - compute: {{ name: folded, expr: {{ xor: {{ left: "$session_high", right: "$session_low" }} }} }}
  - compute: {{ name: mixed, expr: {{ or: {{ left: "$folded", right: {magic_or} }} }} }}
  - compute: {{ name: expected_magic, expr: {{ xor: {{ left: "$session_id", right: "$mixed" }} }} }}
  - match:
      all:
        - eq: {{ left: "$received_magic", right: "$expected_magic" }}
        - eq: {{ left: "$stored_crc", right: "$calculated_crc" }}
result:
  family: valleyrat
  protocol: n520
  confirmed: "$match"
  confidence: 0.98
  unmatched_confidence: 0.35
  status: n520_server_first_handshake_match
  unmatched_status: n520_handshake_mismatch
  fields:
    session_id: "$session_id"
    received_magic: "$received_magic"
    expected_magic: "$expected_magic"
    stored_crc: "$stored_crc"
    calculated_crc: "$calculated_crc"
    application_data_sent: false
"#,
        receive_bytes = p.receive_bytes,
        crc_offset = p.crc_offset,
        crc_length = p.crc_length,
        magic_or = p.magic_or,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexer_ignores_comments_and_keeps_lua_literals() {
        let tokens = lex("-- require 'evil'\nlocal x = 0xa5 -- 4\nlocal y = \"tcp\"").unwrap();
        assert!(tokens.contains(&Token::Number(0xa5)));
        assert!(tokens.contains(&Token::String("tcp".into())));
        assert!(!tokens.contains(&Token::String("evil".into())));
    }

    #[test]
    fn rejects_unknown_modules() {
        let error = convert_valleyrat("local x = require \"socket\"").unwrap_err();
        assert!(error.to_string().contains("unsupported Lua module"));
    }
}
