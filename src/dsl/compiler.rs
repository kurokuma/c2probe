use anyhow::{Context, Result, bail};
use base64::Engine;
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::fs;

use super::{
    BinaryExpr, BoolExpr, CompiledProbe, CompiledResult, Condition, Expr, ExtractType,
    FieldTemplate, MatchClass, MatchClassification, NumberKind, Op, PackType, ProbeDocument,
    TransformKind, TransportType, ValueExpr,
};

/// Probe registries are organised per family, and may nest further; walk the tree with
/// a bounded depth instead of stopping after one level.
const MAX_PROBE_DIR_DEPTH: usize = 8;
/// Buffers a single probe may hold at once, across every concurrent connection.
const MAX_PROBE_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUFFER_BYTES: usize = 1024 * 1024;

pub async fn load_probes(
    paths: &[PathBuf],
    dir: Option<&Path>,
    default_connect: Duration,
    default_read: Duration,
) -> Result<Vec<Arc<CompiledProbe>>> {
    load_probes_with_params(paths, dir, default_connect, default_read, &HashMap::new()).await
}

pub async fn load_probes_with_params(
    paths: &[PathBuf],
    dir: Option<&Path>,
    default_connect: Duration,
    default_read: Duration,
    parameters: &HashMap<String, String>,
) -> Result<Vec<Arc<CompiledProbe>>> {
    let mut files = paths.to_vec();
    let explicit = paths.iter().cloned().collect::<HashSet<_>>();
    if let Some(dir) = dir {
        collect_yaml(dir, MAX_PROBE_DIR_DEPTH, &mut files)
            .await
            .with_context(|| format!("read probe directory {}", dir.display()))?;
    }
    files.sort();
    files.dedup();
    let mut probes = Vec::new();
    for path in files {
        let bytes = fs::read(&path)
            .await
            .with_context(|| format!("read {}", path.display()))?;
        if bytes.len() > 1024 * 1024 {
            bail!("probe file exceeds 1 MiB: {}", path.display());
        }
        let doc = match parse_parameterized_probe(&bytes, parameters) {
            Ok(document) => document,
            Err(error)
                if !explicit.contains(&path)
                    && error.downcast_ref::<MissingProbeParameter>().is_some() =>
            {
                let missing = error
                    .downcast_ref::<MissingProbeParameter>()
                    .expect("guard checked");
                tracing::warn!(
                    probe = %path.display(),
                    parameter = %missing.name,
                    "skipping parameterized probe; provide --probe-param to enable it"
                );
                continue;
            }
            Err(error) => return Err(error).with_context(|| format!("parse {}", path.display())),
        };
        probes.push(Arc::new(
            compile(doc, default_connect, default_read)
                .with_context(|| path.display().to_string())?,
        ));
    }
    probes.sort_by(|a, b| {
        a.plan_order
            .cmp(&b.plan_order)
            .then_with(|| a.name.cmp(&b.name))
    });
    if probes.is_empty() {
        bail!("no YAML probes found");
    }
    Ok(probes)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParameterSpec {
    #[serde(default)]
    required: bool,
    #[serde(default)]
    secret: bool,
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    min_length: Option<usize>,
    #[serde(default)]
    max_length: Option<usize>,
    #[serde(default)]
    decoded_min_length: Option<usize>,
    #[serde(default)]
    decoded_max_length: Option<usize>,
    #[serde(rename = "type")]
    kind: ParameterType,
}

#[derive(Debug, thiserror::Error)]
#[error("missing required probe parameter {name}")]
struct MissingProbeParameter {
    name: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ParameterType {
    Base64,
    Hex,
    Decimal,
    Token,
    HttpHost,
    HttpPath,
    Ip,
}

fn parse_parameterized_probe(
    bytes: &[u8],
    supplied: &HashMap<String, String>,
) -> Result<ProbeDocument> {
    let mut value: serde_yaml::Value = serde_yaml::from_slice(bytes)?;
    let root = value
        .as_mapping_mut()
        .context("probe document must be a mapping")?;
    let definitions = root
        .remove(serde_yaml::Value::String("parameters".into()))
        .unwrap_or_else(|| serde_yaml::Value::Mapping(Default::default()));
    let definitions: BTreeMap<String, ParameterSpec> = serde_yaml::from_value(definitions)?;
    let mut resolved = HashMap::new();
    for (name, definition) in definitions {
        // An explicit empty default is meaningful for optional form fields (for
        // example Lumma's optional cid). CLI values remain non-empty by CLI
        // validation, while a required parameter may never resolve to empty.
        let selected = supplied.get(&name).cloned().or(definition.default);
        let Some(selected) = selected else {
            if definition.required {
                let _secret = definition.secret;
                return Err(MissingProbeParameter { name }.into());
            }
            continue;
        };
        if definition.required && selected.is_empty() {
            return Err(MissingProbeParameter { name }.into());
        }
        validate_parameter(&name, &selected, definition.kind)?;
        if definition
            .min_length
            .is_some_and(|minimum| selected.len() < minimum)
            || definition
                .max_length
                .is_some_and(|maximum| selected.len() > maximum)
        {
            bail!("probe parameter {name} length is outside its declared bounds");
        }
        if definition.decoded_min_length.is_some() || definition.decoded_max_length.is_some() {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&selected)
                .with_context(|| format!("decode probe parameter {name}"))?;
            if definition
                .decoded_min_length
                .is_some_and(|minimum| decoded.len() < minimum)
                || definition
                    .decoded_max_length
                    .is_some_and(|maximum| decoded.len() > maximum)
            {
                bail!("decoded probe parameter {name} length is outside its declared bounds");
            }
        }
        resolved.insert(name, selected);
    }
    substitute_parameters(&mut value, &resolved)?;
    serde_yaml::from_value(value).map_err(Into::into)
}

fn validate_parameter(name: &str, value: &str, kind: ParameterType) -> Result<()> {
    if value.len() > 4096 {
        bail!("probe parameter {name} exceeds 4096 bytes");
    }
    let valid = match kind {
        ParameterType::Base64 => base64::engine::general_purpose::STANDARD
            .decode(value)
            .is_ok(),
        ParameterType::Hex => {
            !value.is_empty()
                && value.len().is_multiple_of(2)
                && value.bytes().all(|b| b.is_ascii_hexdigit())
        }
        ParameterType::Decimal => value.bytes().all(|b| b.is_ascii_digit()),
        ParameterType::Token => value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        ParameterType::HttpHost => {
            !value.is_empty()
                && value.len() <= 253
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:-[]".contains(&b))
        }
        ParameterType::HttpPath => value.starts_with('/') && !value.contains(['\r', '\n', '\0']),
        ParameterType::Ip => value.parse::<std::net::IpAddr>().is_ok(),
    };
    if !valid {
        bail!("probe parameter {name} does not satisfy {kind:?}");
    }
    Ok(())
}

fn substitute_parameters(
    value: &mut serde_yaml::Value,
    resolved: &HashMap<String, String>,
) -> Result<()> {
    match value {
        serde_yaml::Value::String(text) => {
            for (name, replacement) in resolved {
                *text = text.replace(&format!("${{{name}}}"), replacement);
            }
            if text.contains("${") {
                bail!("unresolved probe parameter in {text:?}");
            }
        }
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                substitute_parameters(value, resolved)?;
            }
        }
        serde_yaml::Value::Mapping(values) => {
            for (_, value) in values {
                substitute_parameters(value, resolved)?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn collect_yaml(dir: &Path, depth: usize, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut pending = vec![(dir.to_path_buf(), depth)];
    while let Some((current, remaining)) = pending.pop() {
        let mut entries = fs::read_dir(&current)
            .await
            .with_context(|| format!("read {}", current.display()))?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            // file_type() does not follow symlinks, so a symlinked cycle cannot be
            // walked into.
            let kind = entry.file_type().await?;
            if kind.is_dir() {
                if remaining > 1 {
                    pending.push((path, remaining - 1));
                } else {
                    tracing::warn!(path=%path.display(), "probe directory depth limit reached");
                }
            } else if kind.is_file() && is_yaml(&path) {
                files.push(path);
            }
        }
    }
    Ok(())
}

fn is_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|v| v.to_str()),
        Some("yaml" | "yml")
    )
}

pub fn compile(
    doc: ProbeDocument,
    default_connect: Duration,
    default_read: Duration,
) -> Result<CompiledProbe> {
    if doc.dsl_version != 1 {
        bail!("unsupported dsl_version {}", doc.dsl_version);
    }
    if doc.name.trim().is_empty() {
        bail!("probe name is empty");
    }
    if matches!(
        doc.transport.kind,
        TransportType::Tls | TransportType::Starttls
    ) && !doc.transport.insecure_tls
    {
        bail!(
            "TLS transports require insecure_tls: true; this build performs no \
             certificate validation, and a probe must opt into that explicitly"
        );
    }
    let prelude = match (&doc.transport.kind, &doc.transport.prelude_hex) {
        (TransportType::Starttls, Some(value)) => {
            let bytes = parse_hex(value)?;
            if bytes.is_empty() || bytes.len() > 4096 {
                bail!("starttls prelude_hex must be 1..=4096 bytes");
            }
            Some(Arc::<[u8]>::from(bytes))
        }
        (TransportType::Starttls, None) => bail!("starttls requires prelude_hex"),
        (_, Some(_)) => bail!("prelude_hex is only valid for starttls"),
        (_, None) => None,
    };
    let scope_ips = doc
        .scope
        .ips
        .iter()
        .map(|value| parse_scope_ip(value))
        .collect::<Result<Vec<_>>>()?;
    if doc.scope.ports.contains(&0) {
        bail!("scope ports must be 1..=65535");
    }
    let mut buffers = HashMap::new();
    let mut registers = HashMap::new();
    let mut ops = Vec::new();
    // Buffer sizes are static, so offsets can be range-checked before the scan runs.
    let mut sizes: Vec<usize> = Vec::new();
    let mut next_buf = 0usize;
    let mut next_reg = 0usize;
    let mut matches = 0usize;
    for step in doc.steps {
        let count = usize::from(step.send.is_some())
            + usize::from(step.literal.is_some())
            + usize::from(step.pack.is_some())
            + usize::from(step.concat.is_some())
            + usize::from(step.recv_exact.is_some())
            + usize::from(step.recv_up_to.is_some())
            + usize::from(step.recv_until.is_some())
            + usize::from(step.recv_frame.is_some())
            + usize::from(step.recv_http.is_some())
            + usize::from(step.send_http.is_some())
            + usize::from(step.reconnect.is_some())
            + usize::from(step.peer_certificate.is_some())
            + usize::from(step.transform.is_some())
            + usize::from(step.reject_if.is_some())
            + usize::from(step.extract.is_some())
            + usize::from(step.compute.is_some())
            + usize::from(step.match_value.is_some());
        if count != 1 {
            bail!("each step must contain exactly one operation");
        }
        if let Some(s) = step.send {
            match (s.hex, s.source) {
                (Some(hex), None) => {
                    let bytes = parse_hex(&hex)?;
                    if bytes.is_empty() {
                        bail!("send cannot be empty");
                    }
                    ops.push(Op::SendLiteral(bytes.into()));
                }
                (None, Some(source)) => ops.push(Op::SendBuffer(buffer(&buffers, &source)?)),
                _ => bail!("send requires exactly one of hex or source"),
            }
        } else if let Some(s) = step.literal {
            let data = s.text.into_bytes();
            if data.is_empty() || data.len() > MAX_BUFFER_BYTES {
                bail!("literal {} must be 1..=1048576 bytes", s.name);
            }
            add_buffer(&mut buffers, &mut sizes, &s.name, next_buf, data.len())?;
            ops.push(Op::Literal {
                data: data.into(),
                dst: next_buf,
            });
            next_buf += 1;
        } else if let Some(s) = step.pack {
            if buffers.contains_key(&s.name) {
                bail!("duplicate buffer {}", s.name);
            }
            let kind = pack_kind(s.kind);
            let expr = value_expr(&s.value, &registers)?;
            if let ValueExpr::Literal(value) = expr
                && !s.wrap
                && value > kind.max_value()
            {
                bail!(
                    "pack {}: value {value} does not fit {:?}; set wrap: true to truncate",
                    s.name,
                    s.kind
                );
            }
            add_buffer(&mut buffers, &mut sizes, &s.name, next_buf, kind.size())?;
            ops.push(Op::Pack {
                expr,
                kind,
                wrap: s.wrap,
                dst: next_buf,
            });
            next_buf += 1;
        } else if let Some(s) = step.concat {
            if buffers.contains_key(&s.name) {
                bail!("duplicate buffer {}", s.name);
            }
            if s.sources.is_empty() {
                bail!("concat requires at least one source");
            }
            let sources = s
                .sources
                .iter()
                .map(|name| buffer(&buffers, name))
                .collect::<Result<Vec<_>>>()?;
            let length = sources
                .iter()
                .try_fold(0usize, |total, src| total.checked_add(sizes[*src]))
                .ok_or_else(|| anyhow::anyhow!("concat {} overflows", s.name))?;
            if length > MAX_BUFFER_BYTES {
                bail!("concat {} exceeds 1 MiB ({length} bytes)", s.name);
            }
            add_buffer(&mut buffers, &mut sizes, &s.name, next_buf, length)?;
            ops.push(Op::Concat {
                sources: sources.into(),
                dst: next_buf,
            });
            next_buf += 1;
        } else if let Some(s) = step.recv_exact {
            if s.bytes == 0 || s.bytes > MAX_BUFFER_BYTES {
                bail!("recv_exact bytes must be 1..=1048576");
            }
            add_buffer(&mut buffers, &mut sizes, &s.save_as, next_buf, s.bytes)?;
            ops.push(Op::RecvExact {
                length: s.bytes,
                dst: next_buf,
            });
            next_buf += 1;
        } else if let Some(s) = step.recv_up_to {
            validate_dynamic_buffer(s.min_bytes, s.max_bytes, "recv_up_to")?;
            add_buffer(&mut buffers, &mut sizes, &s.save_as, next_buf, s.max_bytes)?;
            ops.push(Op::RecvUpTo {
                min: s.min_bytes,
                max: s.max_bytes,
                dst: next_buf,
            });
            next_buf += 1;
        } else if let Some(s) = step.recv_until {
            validate_dynamic_buffer(1, s.max_bytes, "recv_until")?;
            let delimiter = parse_hex(&s.delimiter_hex)?;
            if delimiter.is_empty() || delimiter.len() > s.max_bytes {
                bail!("recv_until delimiter must fit inside max_bytes");
            }
            add_buffer(&mut buffers, &mut sizes, &s.save_as, next_buf, s.max_bytes)?;
            ops.push(Op::RecvUntil {
                delimiter: delimiter.into(),
                max: s.max_bytes,
                dst: next_buf,
            });
            next_buf += 1;
        } else if let Some(s) = step.recv_frame {
            validate_dynamic_buffer(s.min_bytes, s.max_bytes, "recv_frame")?;
            let kind = pack_kind(s.kind);
            add_buffer(&mut buffers, &mut sizes, &s.save_as, next_buf, s.max_bytes)?;
            let length_dst = add_register(&mut registers, &s.length_as, next_reg)?;
            ops.push(Op::RecvFrame {
                kind,
                min: s.min_bytes,
                max: s.max_bytes,
                dst: next_buf,
                length_dst,
            });
            next_buf += 1;
            next_reg += 1;
        } else if let Some(s) = step.recv_http {
            validate_dynamic_buffer(1, s.max_header_bytes, "recv_http max_header_bytes")?;
            if s.max_body_bytes > MAX_BUFFER_BYTES {
                bail!("recv_http max_body_bytes must be <=1048576");
            }
            let header_dst = next_buf;
            add_buffer(
                &mut buffers,
                &mut sizes,
                &s.header_as,
                header_dst,
                s.max_header_bytes,
            )?;
            next_buf += 1;
            let body_dst = next_buf;
            add_buffer(
                &mut buffers,
                &mut sizes,
                &s.body_as,
                body_dst,
                s.max_body_bytes,
            )?;
            next_buf += 1;
            let status_dst = add_register(&mut registers, &s.status_as, next_reg)?;
            next_reg += 1;
            let content_length_dst = add_register(&mut registers, &s.content_length_as, next_reg)?;
            next_reg += 1;
            ops.push(Op::RecvHttp {
                max_header: s.max_header_bytes,
                max_body: s.max_body_bytes,
                headers_only: s.headers_only,
                header_dst,
                body_dst,
                status_dst,
                content_length_dst,
            });
        } else if let Some(s) = step.send_http {
            validate_http_token(&s.method, "HTTP method")?;
            validate_http_path(&s.path)?;
            let mut headers = Vec::with_capacity(s.headers.len());
            for (name, value) in s.headers {
                validate_http_token(&name, "HTTP header name")?;
                if value.contains(['\r', '\n']) || value.len() > 4096 {
                    bail!("unsafe HTTP header value for {name}");
                }
                headers.push((Arc::from(name), Arc::from(value)));
            }
            let body_src = s
                .body_source
                .as_deref()
                .map(|v| buffer(&buffers, v))
                .transpose()?;
            ops.push(Op::SendHttp {
                method: s.method.into(),
                path: s.path.into(),
                headers: headers.into(),
                body_src,
            });
        } else if step.reconnect.is_some() {
            ops.push(Op::Reconnect);
        } else if let Some(s) = step.peer_certificate {
            if !matches!(
                doc.transport.kind,
                TransportType::Tls | TransportType::Starttls
            ) {
                bail!("peer_certificate requires a TLS transport");
            }
            add_buffer(&mut buffers, &mut sizes, &s.save_as, next_buf, 32)?;
            ops.push(Op::PeerCertificateSha256 { dst: next_buf });
            next_buf += 1;
        } else if let Some(s) = step.transform {
            let src = buffer(&buffers, &s.source)?;
            let count = usize::from(s.ascii_hex_decode.is_some())
                + usize::from(s.base64_decode.is_some())
                + usize::from(s.base64_encode.is_some())
                + usize::from(s.rc4.is_some())
                + usize::from(s.gzip_decompress.is_some())
                + usize::from(s.msgpack_string.is_some());
            if count != 1 {
                bail!("transform requires exactly one operation");
            }
            let (kind, max) = if s.ascii_hex_decode.is_some() {
                (TransformKind::AsciiHexDecode, sizes[src] / 2)
            } else if s.base64_decode.is_some() {
                (TransformKind::Base64Decode, sizes[src])
            } else if s.base64_encode.is_some() {
                (
                    TransformKind::Base64Encode,
                    sizes[src].saturating_add(2) / 3 * 4,
                )
            } else if let Some(rc4) = s.rc4 {
                let key = base64::engine::general_purpose::STANDARD
                    .decode(rc4.key_base64)
                    .context("invalid RC4 key_base64")?;
                if !(1..=256).contains(&key.len()) {
                    bail!("RC4 key must be 1..=256 bytes");
                }
                (TransformKind::Rc4(key.into()), sizes[src])
            } else if let Some(gzip) = s.gzip_decompress {
                if gzip.offset >= sizes[src]
                    || gzip.max_bytes == 0
                    || gzip.max_bytes > MAX_BUFFER_BYTES
                {
                    bail!("gzip_decompress offset/max_bytes is out of bounds");
                }
                (
                    TransformKind::GzipDecompress {
                        offset: gzip.offset,
                        max: gzip.max_bytes,
                    },
                    gzip.max_bytes,
                )
            } else {
                let msgpack = s.msgpack_string.expect("count checked");
                if msgpack.key.is_empty() || msgpack.key.len() > 128 {
                    bail!("msgpack key must be 1..=128 bytes");
                }
                (
                    TransformKind::MsgpackString {
                        key: msgpack.key.into(),
                    },
                    sizes[src],
                )
            };
            if max == 0 || max > MAX_BUFFER_BYTES {
                bail!("transform output must be 1..=1048576 bytes");
            }
            add_buffer(&mut buffers, &mut sizes, &s.name, next_buf, max)?;
            ops.push(Op::Transform {
                src,
                dst: next_buf,
                kind,
            });
            next_buf += 1;
        } else if let Some(s) = step.reject_if {
            if s.status.trim().is_empty() {
                bail!("reject_if status must not be empty");
            }
            if !(0.0..=1.0).contains(&s.confidence) {
                bail!("reject_if confidence must be in 0..=1");
            }
            ops.push(Op::RejectIf {
                condition: bool_expr(&s.condition, &registers, &buffers, &sizes)?,
                confidence: s.confidence,
                status: s.status.into(),
            });
        } else if let Some(s) = step.extract {
            if registers.contains_key(&s.name) {
                bail!("duplicate register {}", s.name);
            }
            let src = buffer(&buffers, &s.source)?;
            let dst = next_reg;
            match s.kind {
                ExtractType::Crc32 => {
                    let length = s
                        .length
                        .ok_or_else(|| anyhow::anyhow!("crc32 requires length"))?;
                    if length == 0 {
                        bail!("crc32 {} requires a non-zero length", s.name);
                    }
                    check_range(&s.name, sizes[src], s.offset, length)?;
                    ops.push(Op::Crc32 {
                        src,
                        offset: s.offset,
                        length,
                        dst,
                    });
                }
                ExtractType::BufferLen => {
                    if s.offset != 0 || s.length.is_some() {
                        bail!("buffer_len does not accept offset or length");
                    }
                    ops.push(Op::BufferLen { src, dst });
                }
                ExtractType::AsciiDecimal => {
                    let length = s.length.context("ascii_decimal requires length")?;
                    if length == 0 || length > 20 {
                        bail!("ascii_decimal length must be 1..=20");
                    }
                    check_range(&s.name, sizes[src], s.offset, length)?;
                    ops.push(Op::AsciiDecimal {
                        src,
                        offset: s.offset,
                        length,
                        dst,
                    });
                }
                kind => {
                    let kind = number_kind(kind);
                    check_range(&s.name, sizes[src], s.offset, kind.size())?;
                    ops.push(Op::Extract {
                        src,
                        offset: s.offset,
                        kind,
                        dst,
                    });
                }
            }
            registers.insert(s.name, dst);
            next_reg += 1;
        } else if let Some(s) = step.compute {
            if registers.contains_key(&s.name) {
                bail!("duplicate register {}", s.name);
            }
            let expr = value_expr(&s.expr, &registers)?;
            let dst = next_reg;
            registers.insert(s.name, dst);
            next_reg += 1;
            ops.push(Op::Compute { expr, dst });
        } else if let Some(s) = step.match_value {
            let condition = bool_expr(&s.condition, &registers, &buffers, &sizes)?;
            if let Some(confidence) = s.confidence
                && !(0.0..=1.0).contains(&confidence)
            {
                bail!("match confidence must be in 0..=1");
            }
            ops.push(Op::Match {
                condition,
                confidence: s.confidence,
                status: s.status.map(Into::into),
            });
            matches += 1;
        }
    }
    match matches {
        0 => bail!("probe requires a match step"),
        // More than one match step made the reported confidence depend on which step
        // ran last; compose conditions with all/any/not instead.
        1 => {}
        n => bail!("probe must contain exactly one match step, found {n}"),
    }
    let budget = sizes
        .iter()
        .try_fold(0usize, |total, size| total.checked_add(*size));
    match budget {
        Some(total) if total <= MAX_PROBE_BUFFER_BYTES => {}
        _ => bail!(
            "probe buffers exceed {} bytes per connection",
            MAX_PROBE_BUFFER_BYTES
        ),
    }
    if doc.result.confirmed != "$match" {
        bail!("result.confirmed must be $match");
    }
    for value in [doc.result.confidence, doc.result.unmatched_confidence] {
        if !(0.0..=1.0).contains(&value) {
            bail!("confidence must be in 0..=1");
        }
    }
    let mut fields = std::collections::BTreeMap::new();
    for (name, value) in doc.result.fields {
        let t = match &value {
            Value::String(s) if s.starts_with("$hex:") => {
                FieldTemplate::BufferHex(buffer(&buffers, &s[5..])?)
            }
            Value::String(s) if s.starts_with("$text:") => {
                FieldTemplate::BufferText(buffer(&buffers, &s[6..])?)
            }
            Value::String(s) if s == "$rejected" => FieldTemplate::Rejected,
            Value::String(s) if s.starts_with('$') => {
                FieldTemplate::Register(register(&registers, s)?)
            }
            _ => FieldTemplate::Literal(value),
        };
        fields.insert(name, t);
    }
    Ok(CompiledProbe {
        name: doc.name.into(),
        plan_order: doc.metadata.plan_order,
        family: doc.result.family.into(),
        protocol: doc.result.protocol.into(),
        transport: doc.transport.kind,
        connect_timeout: doc
            .transport
            .connect_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(default_connect),
        read_timeout: doc
            .transport
            .read_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(default_read),
        insecure_tls: doc.transport.insecure_tls,
        server_name: doc.transport.server_name.map(Into::into),
        prelude,
        scope_ips: scope_ips.into(),
        scope_ports: doc.scope.ports.into(),
        ops: ops.into(),
        result: CompiledResult {
            classification: match doc.result.classification {
                MatchClassification::Confirmed => MatchClass::Confirmed,
                MatchClassification::Probable => MatchClass::Probable,
                MatchClassification::Observation => MatchClass::Observation,
            },
            confidence: doc.result.confidence,
            unmatched_confidence: doc.result.unmatched_confidence,
            status: doc.result.status.into(),
            unmatched_status: doc.result.unmatched_status.into(),
            fields,
        },
    })
}

fn add_buffer(
    buffers: &mut HashMap<String, usize>,
    sizes: &mut Vec<usize>,
    name: &str,
    index: usize,
    size: usize,
) -> Result<()> {
    if name.is_empty() || buffers.insert(name.to_owned(), index).is_some() {
        bail!("duplicate or empty buffer {name}");
    }
    sizes.push(size);
    Ok(())
}

fn add_register(registers: &mut HashMap<String, usize>, name: &str, index: usize) -> Result<usize> {
    if name.is_empty() || registers.insert(name.to_owned(), index).is_some() {
        bail!("duplicate or empty register {name}");
    }
    Ok(index)
}

fn validate_dynamic_buffer(min: usize, max: usize, operation: &str) -> Result<()> {
    if min == 0 || min > max || max > MAX_BUFFER_BYTES {
        bail!("{operation} requires 1 <= min <= max <= 1048576");
    }
    Ok(())
}

fn validate_http_token(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        bail!("invalid {label}: {value:?}");
    }
    Ok(())
}

fn validate_http_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.contains(['\r', '\n', '\0'])
    {
        bail!("unsafe HTTP path");
    }
    Ok(())
}

fn parse_scope_ip(value: &str) -> Result<IpNet> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net);
    }
    let ip = value
        .parse::<std::net::IpAddr>()
        .with_context(|| format!("invalid scope IP {value}"))?;
    IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).context("invalid scope prefix")
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(
        s.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    )
    .context("invalid hex")
}
fn buffer(map: &HashMap<String, usize>, name: &str) -> Result<usize> {
    map.get(name.trim_start_matches('$'))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("unknown buffer {name}"))
}
fn register(map: &HashMap<String, usize>, name: &str) -> Result<usize> {
    map.get(name.trim_start_matches('$'))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("unknown register {name}"))
}
fn number_kind(k: ExtractType) -> NumberKind {
    match k {
        ExtractType::U8 => NumberKind::U8,
        ExtractType::U16le => NumberKind::U16Le,
        ExtractType::U16be => NumberKind::U16Be,
        ExtractType::U32le => NumberKind::U32Le,
        ExtractType::U32be => NumberKind::U32Be,
        ExtractType::U64le => NumberKind::U64Le,
        ExtractType::U64be => NumberKind::U64Be,
        ExtractType::Crc32 | ExtractType::BufferLen | ExtractType::AsciiDecimal => unreachable!(),
    }
}

fn pack_kind(k: PackType) -> NumberKind {
    match k {
        PackType::U8 => NumberKind::U8,
        PackType::U16le => NumberKind::U16Le,
        PackType::U16be => NumberKind::U16Be,
        PackType::U32le => NumberKind::U32Le,
        PackType::U32be => NumberKind::U32Be,
        PackType::U64le => NumberKind::U64Le,
        PackType::U64be => NumberKind::U64Be,
    }
}

fn value_expr(e: &Expr, regs: &HashMap<String, usize>) -> Result<ValueExpr> {
    Ok(match e {
        Expr::Number(n) => ValueExpr::Literal(*n),
        Expr::Reference(s) => ValueExpr::Register(register(regs, s)?),
        Expr::Operation(op) => {
            let count = [
                op.add.is_some(),
                op.sub.is_some(),
                op.xor.is_some(),
                op.and.is_some(),
                op.or.is_some(),
                op.shift_left.is_some(),
                op.shift_right.is_some(),
            ]
            .into_iter()
            .filter(|x| *x)
            .count();
            if count != 1 {
                bail!("expression requires exactly one operation");
            }
            if let Some(x) = &op.add {
                binary(x, regs, ValueExpr::Add)?
            } else if let Some(x) = &op.sub {
                binary(x, regs, ValueExpr::Sub)?
            } else if let Some(x) = &op.xor {
                binary(x, regs, ValueExpr::Xor)?
            } else if let Some(x) = &op.and {
                binary(x, regs, ValueExpr::And)?
            } else if let Some(x) = &op.or {
                binary(x, regs, ValueExpr::Or)?
            } else if let Some(x) = &op.shift_left {
                binary(x, regs, ValueExpr::ShiftLeft)?
            } else {
                binary(
                    op.shift_right.as_ref().unwrap(),
                    regs,
                    ValueExpr::ShiftRight,
                )?
            }
        }
    })
}
fn binary<F>(b: &BinaryExpr, regs: &HashMap<String, usize>, f: F) -> Result<ValueExpr>
where
    F: FnOnce(Box<ValueExpr>, Box<ValueExpr>) -> ValueExpr,
{
    Ok(f(
        Box::new(value_expr(&b.left, regs)?),
        Box::new(value_expr(&b.right, regs)?),
    ))
}
fn check_range(name: &str, size: usize, offset: usize, length: usize) -> Result<()> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("{name}: offset {offset} + {length} overflows"))?;
    if end > size {
        bail!("{name}: offset {offset} + {length} exceeds the {size} byte source buffer");
    }
    Ok(())
}

fn bool_expr(
    c: &Condition,
    regs: &HashMap<String, usize>,
    bufs: &HashMap<String, usize>,
    sizes: &[usize],
) -> Result<BoolExpr> {
    let count = [
        c.all.is_some(),
        c.any.is_some(),
        c.not.is_some(),
        c.eq.is_some(),
        c.ne.is_some(),
        c.lt.is_some(),
        c.gt.is_some(),
        c.bytes_eq.is_some(),
        c.bytes_contains.is_some(),
        c.bytes_regex.is_some(),
        c.buffer_starts_with.is_some(),
    ]
    .into_iter()
    .filter(|x| *x)
    .count();
    if count != 1 {
        bail!("condition requires exactly one operator");
    }
    Ok(if let Some(v) = &c.all {
        if v.is_empty() {
            bail!("all requires at least one condition");
        }
        BoolExpr::All(
            v.iter()
                .map(|x| bool_expr(x, regs, bufs, sizes))
                .collect::<Result<_>>()?,
        )
    } else if let Some(v) = &c.any {
        if v.is_empty() {
            bail!("any requires at least one condition");
        }
        BoolExpr::Any(
            v.iter()
                .map(|x| bool_expr(x, regs, bufs, sizes))
                .collect::<Result<_>>()?,
        )
    } else if let Some(x) = &c.not {
        BoolExpr::Not(Box::new(bool_expr(x, regs, bufs, sizes)?))
    } else if let Some(x) = &c.eq {
        BoolExpr::Eq(value_expr(&x.left, regs)?, value_expr(&x.right, regs)?)
    } else if let Some(x) = &c.ne {
        BoolExpr::Ne(value_expr(&x.left, regs)?, value_expr(&x.right, regs)?)
    } else if let Some(x) = &c.lt {
        BoolExpr::Lt(value_expr(&x.left, regs)?, value_expr(&x.right, regs)?)
    } else if let Some(x) = &c.gt {
        BoolExpr::Gt(value_expr(&x.left, regs)?, value_expr(&x.right, regs)?)
    } else if let Some(x) = &c.bytes_eq {
        let src = buffer(bufs, &x.source)?;
        let bytes = parse_hex(&x.hex)?;
        // An empty pattern compares equal to everything, which would silently turn a
        // typo into a confirmed detection.
        if bytes.is_empty() {
            bail!("bytes_eq on {} requires at least one byte", x.source);
        }
        check_range(&x.source, sizes[src], x.offset, bytes.len())?;
        BoolExpr::BytesEq {
            src,
            offset: x.offset,
            bytes: bytes.into(),
        }
    } else if let Some(x) = &c.bytes_contains {
        let src = buffer(bufs, &x.source)?;
        let bytes = parse_hex(&x.hex)?;
        if bytes.is_empty() {
            bail!("bytes_contains on {} requires at least one byte", x.source);
        }
        BoolExpr::BytesContains {
            src,
            bytes: bytes.into(),
        }
    } else if let Some(x) = &c.bytes_regex {
        let src = buffer(bufs, &x.source)?;
        if x.pattern.len() > 4096 {
            bail!("bytes_regex pattern exceeds 4096 bytes");
        }
        let regex = regex::bytes::Regex::new(&x.pattern).context("invalid bytes_regex")?;
        BoolExpr::BytesRegex {
            src,
            regex: Arc::new(regex),
        }
    } else {
        let x = c
            .buffer_starts_with
            .as_ref()
            .expect("operator count checked");
        let src = buffer(bufs, &x.source)?;
        let prefix = buffer(bufs, &x.prefix)?;
        BoolExpr::BufferStartsWith { src, prefix }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(steps: &str, transport: &str) -> Result<crate::dsl::CompiledProbe> {
        let text = format!(
            "dsl_version: 1\nname: x\nmetadata: {{}}\ntransport: {transport}\nsteps:\n{steps}result: {{family: x, protocol: x}}"
        );
        let doc: ProbeDocument = serde_yaml::from_str(&text)
            .unwrap_or_else(|error| panic!("parse failure for {text}: {error}"));
        compile(doc, Duration::from_secs(1), Duration::from_secs(1))
    }

    #[test]
    fn rejects_unknown_register() {
        let y = "dsl_version: 1\nname: x\nmetadata: {}\ntransport: {type: tcp}\nsteps:\n- match: {eq: {left: '$missing', right: 1}}\nresult: {family: x, protocol: x}";
        let d: ProbeDocument = serde_yaml::from_str(y).unwrap();
        assert!(compile(d, Duration::from_secs(1), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn rejects_reads_past_the_end_of_a_buffer() {
        let error = build(
            "- recv_exact: {bytes: 4, save_as: r}\n- extract: {source: r, name: v, type: u32le, offset: 900}\n- match: {eq: {left: '$v', right: 1}}\n",
            "{type: tcp}",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("exceeds the 4 byte source buffer"),
            "{error}"
        );
        assert!(
            build(
                "- recv_exact: {bytes: 8, save_as: r}\n- extract: {source: r, name: v, type: crc32, offset: 4, length: 8}\n- match: {eq: {left: '$v', right: 1}}\n",
                "{type: tcp}",
            )
            .is_err()
        );
        assert!(
            build(
                "- recv_exact: {bytes: 8, save_as: r}\n- extract: {source: r, name: v, type: u32le, offset: 4}\n- match: {eq: {left: '$v', right: 1}}\n",
                "{type: tcp}",
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_always_true_byte_comparison() {
        let error = build(
            "- recv_exact: {bytes: 4, save_as: r}\n- match: {bytes_eq: {source: r, offset: 0, hex: ''}}\n",
            "{type: tcp}",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("at least one byte"), "{error}");
    }

    #[test]
    fn rejects_byte_comparison_past_the_buffer() {
        assert!(
            build(
                "- recv_exact: {bytes: 4, save_as: r}\n- match: {bytes_eq: {source: r, offset: 2, hex: '00 00 00'}}\n",
                "{type: tcp}",
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_multiple_match_steps() {
        let error = build(
            "- recv_exact: {bytes: 4, save_as: r}\n- match: {eq: {left: 1, right: 1}}\n- match: {eq: {left: 2, right: 1}}\n",
            "{type: tcp}",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("exactly one match step"), "{error}");
    }

    #[test]
    fn rejects_silent_pack_truncation_but_allows_opt_in() {
        assert!(
            build(
                "- pack: {name: a, type: u8, value: 300}\n- send: {source: '$a'}\n- match: {eq: {left: 1, right: 1}}\n",
                "{type: tcp}",
            )
            .is_err()
        );
        assert!(
            build(
                "- pack: {name: a, type: u8, value: 300, wrap: true}\n- send: {source: '$a'}\n- match: {eq: {left: 1, right: 1}}\n",
                "{type: tcp}",
            )
            .is_ok()
        );
    }

    #[test]
    fn tls_requires_explicit_opt_in_to_skipped_verification() {
        let error = build(
            "- recv_exact: {bytes: 4, save_as: r}\n- match: {eq: {left: 1, right: 1}}\n",
            "{type: tls}",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("insecure_tls: true"), "{error}");
        assert!(
            build(
                "- recv_exact: {bytes: 4, save_as: r}\n- match: {eq: {left: 1, right: 1}}\n",
                "{type: tls, insecure_tls: true}",
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_probe_buffer_budget_overrun() {
        let steps = (0..5)
            .map(|i| format!("- recv_exact: {{bytes: 1048576, save_as: r{i}}}\n"))
            .collect::<String>();
        let error = build(
            &format!("{steps}- match: {{eq: {{left: 1, right: 1}}}}\n"),
            "{type: tcp}",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("probe buffers exceed"), "{error}");
    }

    #[test]
    fn compiles_pack_concat_and_buffer_send() {
        let y = "dsl_version: 1\nname: x\nmetadata: {}\ntransport: {type: tcp}\nsteps:\n- pack: {name: a, type: u16le, value: 4660}\n- pack: {name: b, type: u8, value: 86}\n- concat: {name: request, sources: ['$a', '$b']}\n- send: {source: '$request'}\n- match: {eq: {left: 1, right: 1}}\nresult: {family: x, protocol: x}";
        let d: ProbeDocument = serde_yaml::from_str(y).unwrap();
        let p = compile(d, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        assert!(matches!(p.ops[0], Op::Pack { .. }));
        assert!(matches!(p.ops[2], Op::Concat { .. }));
        assert!(matches!(p.ops[3], Op::SendBuffer(_)));
    }
}
