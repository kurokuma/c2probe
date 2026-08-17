use super::transport::{self, ProbeFailure, ProbeResult};
use crate::dsl::{
    BoolExpr, CompiledProbe, FieldTemplate, MatchClass, NumberKind, Op, TransformKind, ValueExpr,
};
use base64::Engine;
use flate2::read::GzDecoder;
use serde_json::{Map, Value};
use std::{io::Read, net::IpAddr, time::Instant};

#[derive(Debug)]
pub struct ProbeExecution {
    pub confirmed: bool,
    pub probable: bool,
    pub observed: bool,
    pub responsive: bool,
    pub confidence: f64,
    pub status: String,
    pub duration_ms: u64,
    pub fields: Map<String, Value>,
}

struct Outcome {
    matched: bool,
    rejected: bool,
    responsive: bool,
    confidence: f64,
    status: String,
    registers: Vec<u64>,
    buffers: Vec<Vec<u8>>,
}

pub async fn execute(ip: IpAddr, port: u16, p: &CompiledProbe) -> ProbeExecution {
    let started = Instant::now();
    let mut fields = Map::new();
    match run(ip, port, p).await {
        Ok(outcome) => {
            for (name, t) in &p.result.fields {
                let value = match t {
                    FieldTemplate::Register(i) => {
                        Value::from(outcome.registers.get(*i).copied().unwrap_or(0))
                    }
                    FieldTemplate::BufferHex(i) => {
                        Value::from(outcome.buffers.get(*i).map(hex::encode).unwrap_or_default())
                    }
                    FieldTemplate::BufferText(i) => Value::from(
                        outcome
                            .buffers
                            .get(*i)
                            .map(|buffer| String::from_utf8_lossy(buffer).into_owned())
                            .unwrap_or_default(),
                    ),
                    FieldTemplate::Rejected => Value::from(outcome.rejected),
                    FieldTemplate::Literal(v) => v.clone(),
                };
                fields.insert(name.clone(), value);
            }
            ProbeExecution {
                confirmed: outcome.matched && p.result.classification == MatchClass::Confirmed,
                probable: outcome.matched && p.result.classification == MatchClass::Probable,
                observed: outcome.matched && p.result.classification == MatchClass::Observation,
                responsive: outcome.responsive,
                confidence: outcome.confidence,
                status: outcome.status,
                duration_ms: started.elapsed().as_millis() as u64,
                fields,
            }
        }
        Err(failure) => ProbeExecution {
            confirmed: false,
            probable: false,
            observed: false,
            responsive: false,
            confidence: 0.0,
            status: failure.status().into(),
            duration_ms: started.elapsed().as_millis() as u64,
            fields,
        },
    }
}

async fn run(ip: IpAddr, port: u16, p: &CompiledProbe) -> ProbeResult<Outcome> {
    let mut io = transport::connect(ip, port, p).await?;
    let mut bufs: Vec<Vec<u8>> = Vec::new();
    let mut regs: Vec<u64> = Vec::new();
    let mut matched = false;
    let mut responsive = false;
    let mut override_conf = None;
    let mut override_status = None;
    for op in p.ops.iter() {
        match op {
            Op::SendLiteral(data) => io.send_all(data).await?,
            Op::SendBuffer(src) => {
                let data = bufs.get(*src).ok_or(ProbeFailure::InternalError)?;
                io.send_all(data).await?
            }
            Op::Literal { data, dst } => set(&mut bufs, *dst, data.to_vec()),
            Op::Pack {
                expr,
                kind,
                wrap,
                dst,
            } => {
                let value = eval(expr, &regs);
                if !wrap && value > kind.max_value() {
                    // Silently truncating here would send a frame the probe never
                    // described; the compiler allows this only with wrap: true.
                    return Err(ProbeFailure::InternalError);
                }
                set(&mut bufs, *dst, pack_num(value, *kind));
            }
            Op::Concat { sources, dst } => {
                let length = sources.iter().try_fold(0usize, |total, src| {
                    let len = bufs.get(*src).ok_or(ProbeFailure::InternalError)?.len();
                    total.checked_add(len).ok_or(ProbeFailure::InternalError)
                })?;
                if length > 1024 * 1024 {
                    return Err(ProbeFailure::InternalError);
                }
                let mut combined = Vec::with_capacity(length);
                for src in sources.iter() {
                    combined.extend_from_slice(&bufs[*src]);
                }
                set(&mut bufs, *dst, combined);
            }
            Op::RecvExact { length, dst } => {
                let b = io.recv_exact(*length, p.read_timeout).await?;
                responsive = true;
                set(&mut bufs, *dst, b);
            }
            Op::RecvUpTo { min, max, dst } => {
                let b = io.recv_up_to(*min, *max, p.read_timeout).await?;
                responsive = true;
                set(&mut bufs, *dst, b);
            }
            Op::RecvUntil {
                delimiter,
                max,
                dst,
            } => {
                let b = io.recv_until(delimiter, *max, p.read_timeout).await?;
                responsive = true;
                set(&mut bufs, *dst, b);
            }
            Op::RecvFrame {
                kind,
                min,
                max,
                dst,
                length_dst,
            } => {
                let header = io.recv_exact(kind.size(), p.read_timeout).await?;
                let length = read_number(&header, *kind)? as usize;
                if length < *min || length > *max {
                    return Err(ProbeFailure::InvalidResponse);
                }
                let body = io.recv_exact(length, p.read_timeout).await?;
                responsive = true;
                set(&mut bufs, *dst, body);
                set(&mut regs, *length_dst, length as u64);
            }
            Op::RecvHttp {
                max_header,
                max_body,
                headers_only,
                header_dst,
                body_dst,
                status_dst,
                content_length_dst,
            } => {
                let header = io
                    .recv_until(b"\r\n\r\n", *max_header, p.read_timeout)
                    .await?;
                let parsed = parse_http_header(&header, *max_body)?;
                let body = if *headers_only {
                    Vec::new()
                } else if let Some(length) = parsed.content_length {
                    if length == 0 {
                        Vec::new()
                    } else {
                        io.recv_exact(length, p.read_timeout).await?
                    }
                } else if *max_body == 0 {
                    Vec::new()
                } else {
                    io.recv_up_to(1, *max_body, p.read_timeout).await?
                };
                responsive = true;
                set(&mut bufs, *header_dst, header);
                set(&mut bufs, *body_dst, body);
                set(&mut regs, *status_dst, u64::from(parsed.status));
                set(
                    &mut regs,
                    *content_length_dst,
                    parsed.content_length.unwrap_or(0) as u64,
                );
            }
            Op::SendHttp {
                method,
                path,
                headers,
                body_src,
            } => {
                let body = body_src
                    .map(|index| bufs.get(index).ok_or(ProbeFailure::InternalError))
                    .transpose()?
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let request = build_http_request(ip, method, path, headers, body)?;
                io.send_all(&request).await?;
            }
            Op::Reconnect => io = transport::connect(ip, port, p).await?,
            Op::PeerCertificateSha256 { dst } => {
                set(&mut bufs, *dst, io.peer_certificate_sha256()?.to_vec());
                responsive = true;
            }
            Op::Transform { src, dst, kind } => {
                let source = bufs.get(*src).ok_or(ProbeFailure::InternalError)?;
                let transformed = transform(source, kind)?;
                set(&mut bufs, *dst, transformed);
            }
            Op::RejectIf {
                condition,
                confidence,
                status,
            } => {
                if eval_bool(condition, &regs, &bufs) {
                    return Ok(Outcome {
                        matched: false,
                        rejected: true,
                        responsive,
                        confidence: *confidence,
                        status: status.to_string(),
                        registers: regs,
                        buffers: bufs,
                    });
                }
            }
            Op::Extract {
                src,
                offset,
                kind,
                dst,
            } => {
                let v = read_num(bufs.get(*src), *offset, *kind)?;
                set(&mut regs, *dst, v);
            }
            Op::Crc32 {
                src,
                offset,
                length,
                dst,
            } => {
                let b = slice(bufs.get(*src), *offset, *length)?;
                set(&mut regs, *dst, crc32fast::hash(b) as u64);
            }
            Op::BufferLen { src, dst } => {
                let length = bufs.get(*src).ok_or(ProbeFailure::InternalError)?.len();
                set(&mut regs, *dst, length as u64);
            }
            Op::AsciiDecimal {
                src,
                offset,
                length,
                dst,
            } => {
                let bytes = slice(bufs.get(*src), *offset, *length)?;
                if !bytes.iter().all(u8::is_ascii_digit) {
                    return Err(ProbeFailure::InvalidResponse);
                }
                let text = std::str::from_utf8(bytes).map_err(|_| ProbeFailure::InvalidResponse)?;
                let value = text
                    .parse::<u64>()
                    .map_err(|_| ProbeFailure::InvalidResponse)?;
                set(&mut regs, *dst, value);
            }
            Op::Compute { expr, dst } => {
                let v = eval(expr, &regs);
                set(&mut regs, *dst, v);
            }
            Op::Match {
                condition,
                confidence,
                status,
            } => {
                matched = eval_bool(condition, &regs, &bufs);
                // Reset unconditionally so an earlier true match cannot leave its
                // confidence attached to a later false one.
                override_conf = matched.then_some(*confidence).flatten();
                override_status = matched
                    .then(|| status.as_ref().map(|x| x.to_string()))
                    .flatten();
            }
        }
    }
    let confidence = override_conf.unwrap_or(if matched {
        p.result.confidence
    } else {
        p.result.unmatched_confidence
    });
    let status = override_status.unwrap_or_else(|| {
        let declared = if matched {
            &p.result.status
        } else {
            &p.result.unmatched_status
        };
        if declared.is_empty() && !matched {
            // The probe ran to completion but the protocol did not line up, which is
            // distinct from a transport failure (spec section 34).
            return "protocol_mismatch".to_string();
        }
        declared.to_string()
    });
    Ok(Outcome {
        matched,
        rejected: false,
        responsive,
        confidence,
        status,
        registers: regs,
        buffers: bufs,
    })
}
fn set<T: Default>(v: &mut Vec<T>, i: usize, x: T) {
    while v.len() <= i {
        v.push(T::default())
    }
    v[i] = x
}
fn slice(b: Option<&Vec<u8>>, o: usize, l: usize) -> ProbeResult<&[u8]> {
    b.and_then(|x| x.get(o..o.saturating_add(l)))
        .ok_or(ProbeFailure::InvalidResponse)
}
fn read_num(b: Option<&Vec<u8>>, o: usize, k: NumberKind) -> ProbeResult<u64> {
    let s = slice(b, o, k.size())?;
    Ok(match k {
        NumberKind::U8 => s[0] as u64,
        NumberKind::U16Le => u16::from_le_bytes(s.try_into().unwrap()) as u64,
        NumberKind::U16Be => u16::from_be_bytes(s.try_into().unwrap()) as u64,
        NumberKind::U32Le => u32::from_le_bytes(s.try_into().unwrap()) as u64,
        NumberKind::U32Be => u32::from_be_bytes(s.try_into().unwrap()) as u64,
        NumberKind::U64Le => u64::from_le_bytes(s.try_into().unwrap()),
        NumberKind::U64Be => u64::from_be_bytes(s.try_into().unwrap()),
    })
}
fn pack_num(value: u64, kind: NumberKind) -> Vec<u8> {
    match kind {
        NumberKind::U8 => vec![value as u8],
        NumberKind::U16Le => (value as u16).to_le_bytes().to_vec(),
        NumberKind::U16Be => (value as u16).to_be_bytes().to_vec(),
        NumberKind::U32Le => (value as u32).to_le_bytes().to_vec(),
        NumberKind::U32Be => (value as u32).to_be_bytes().to_vec(),
        NumberKind::U64Le => value.to_le_bytes().to_vec(),
        NumberKind::U64Be => value.to_be_bytes().to_vec(),
    }
}
fn eval(e: &ValueExpr, r: &[u64]) -> u64 {
    match e {
        ValueExpr::Literal(v) => *v,
        ValueExpr::Register(i) => r.get(*i).copied().unwrap_or(0),
        ValueExpr::Add(a, b) => eval(a, r).wrapping_add(eval(b, r)),
        ValueExpr::Sub(a, b) => eval(a, r).wrapping_sub(eval(b, r)),
        ValueExpr::Xor(a, b) => eval(a, r) ^ eval(b, r),
        ValueExpr::And(a, b) => eval(a, r) & eval(b, r),
        ValueExpr::Or(a, b) => eval(a, r) | eval(b, r),
        ValueExpr::ShiftLeft(a, b) => eval(a, r).wrapping_shl(eval(b, r) as u32),
        ValueExpr::ShiftRight(a, b) => eval(a, r).wrapping_shr(eval(b, r) as u32),
    }
}
fn eval_bool(e: &BoolExpr, r: &[u64], b: &[Vec<u8>]) -> bool {
    match e {
        BoolExpr::All(v) => v.iter().all(|x| eval_bool(x, r, b)),
        BoolExpr::Any(v) => v.iter().any(|x| eval_bool(x, r, b)),
        BoolExpr::Not(x) => !eval_bool(x, r, b),
        BoolExpr::Eq(a, c) => eval(a, r) == eval(c, r),
        BoolExpr::Ne(a, c) => eval(a, r) != eval(c, r),
        BoolExpr::Lt(a, c) => eval(a, r) < eval(c, r),
        BoolExpr::Gt(a, c) => eval(a, r) > eval(c, r),
        BoolExpr::BytesEq { src, offset, bytes } => b
            .get(*src)
            .and_then(|x| x.get(*offset..offset.saturating_add(bytes.len())))
            .is_some_and(|x| x == bytes.as_ref()),
        BoolExpr::BytesContains { src, bytes } => b.get(*src).is_some_and(|buffer| {
            buffer
                .windows(bytes.len())
                .any(|window| window == bytes.as_ref())
        }),
        BoolExpr::BytesRegex { src, regex } => {
            b.get(*src).is_some_and(|buffer| regex.is_match(buffer))
        }
        BoolExpr::BufferStartsWith { src, prefix } => b
            .get(*src)
            .zip(b.get(*prefix))
            .is_some_and(|(source, prefix)| source.starts_with(prefix)),
    }
}

fn read_number(bytes: &[u8], kind: NumberKind) -> ProbeResult<u64> {
    if bytes.len() != kind.size() {
        return Err(ProbeFailure::InternalError);
    }
    Ok(match kind {
        NumberKind::U8 => u64::from(bytes[0]),
        NumberKind::U16Le => u64::from(u16::from_le_bytes(bytes.try_into().unwrap())),
        NumberKind::U16Be => u64::from(u16::from_be_bytes(bytes.try_into().unwrap())),
        NumberKind::U32Le => u64::from(u32::from_le_bytes(bytes.try_into().unwrap())),
        NumberKind::U32Be => u64::from(u32::from_be_bytes(bytes.try_into().unwrap())),
        NumberKind::U64Le => u64::from_le_bytes(bytes.try_into().unwrap()),
        NumberKind::U64Be => u64::from_be_bytes(bytes.try_into().unwrap()),
    })
}

fn transform(source: &[u8], kind: &TransformKind) -> ProbeResult<Vec<u8>> {
    match kind {
        TransformKind::AsciiHexDecode => {
            hex::decode(source).map_err(|_| ProbeFailure::InvalidResponse)
        }
        TransformKind::Base64Decode => base64::engine::general_purpose::STANDARD
            .decode(
                source
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| ProbeFailure::InvalidResponse),
        TransformKind::Base64Encode => Ok(base64::engine::general_purpose::STANDARD
            .encode(source)
            .into_bytes()),
        TransformKind::Rc4(key) => Ok(rc4(source, key)),
        TransformKind::GzipDecompress { offset, max } => {
            let compressed = source.get(*offset..).ok_or(ProbeFailure::InvalidResponse)?;
            let mut decoder = GzDecoder::new(compressed).take((*max as u64) + 1);
            let mut output = Vec::new();
            decoder
                .read_to_end(&mut output)
                .map_err(|_| ProbeFailure::InvalidResponse)?;
            if output.len() > *max {
                return Err(ProbeFailure::InvalidResponse);
            }
            Ok(output)
        }
        TransformKind::MsgpackString { key } => msgpack_string(source, key.as_bytes())
            .map(Vec::from)
            .ok_or(ProbeFailure::InvalidResponse),
    }
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
            let index = (usize::from(state[left]) + usize::from(state[right])) & 0xff;
            byte ^ state[index]
        })
        .collect()
}

struct HttpHeader {
    status: u16,
    content_length: Option<usize>,
}

fn parse_http_header(header: &[u8], max_body: usize) -> ProbeResult<HttpHeader> {
    let text = std::str::from_utf8(header).map_err(|_| ProbeFailure::InvalidResponse)?;
    if !text.ends_with("\r\n\r\n") {
        return Err(ProbeFailure::InvalidResponse);
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let status_line = lines.next().ok_or(ProbeFailure::InvalidResponse)?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().ok_or(ProbeFailure::InvalidResponse)?;
    let status = parts
        .next()
        .ok_or(ProbeFailure::InvalidResponse)?
        .parse::<u16>()
        .map_err(|_| ProbeFailure::InvalidResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || !(100..=599).contains(&status) {
        return Err(ProbeFailure::InvalidResponse);
    }
    let mut seen = std::collections::HashSet::new();
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ProbeFailure::InvalidResponse)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(ProbeFailure::InvalidResponse);
        }
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return Err(ProbeFailure::InvalidResponse);
        }
        let value = value.trim();
        if name == "transfer-encoding" {
            return Err(ProbeFailure::InvalidResponse);
        }
        if name == "content-length" {
            let length = value
                .parse::<usize>()
                .map_err(|_| ProbeFailure::InvalidResponse)?;
            if length > max_body {
                return Err(ProbeFailure::InvalidResponse);
            }
            content_length = Some(length);
        }
    }
    Ok(HttpHeader {
        status,
        content_length,
    })
}

fn build_http_request(
    ip: IpAddr,
    method: &str,
    path: &str,
    headers: &[(std::sync::Arc<str>, std::sync::Arc<str>)],
    body: &[u8],
) -> ProbeResult<Vec<u8>> {
    let mut request = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    let has_length = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    for (name, value) in headers {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        if value.as_ref() == "$target_ip" {
            request.extend_from_slice(ip.to_string().as_bytes());
        } else {
            request.extend_from_slice(value.as_bytes());
        }
        request.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() && !has_length {
        request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(body);
    if request.len() > 1024 * 1024 {
        return Err(ProbeFailure::InternalError);
    }
    Ok(request)
}

fn msgpack_string<'a>(data: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    let count = match *data.first()? {
        value @ 0x81..=0x8f => usize::from(value & 0x0f),
        _ => return None,
    };
    let mut offset = 1usize;
    let mut found = None;
    for _ in 0..count {
        let (key, next) = read_msgpack_string(data, offset)?;
        let (value, end) = read_msgpack_string(data, next)?;
        if key == wanted {
            found = Some(value);
        }
        offset = end;
    }
    (offset == data.len()).then_some(found).flatten()
}

fn read_msgpack_string(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let prefix = *data.get(offset)?;
    let (length, start) = if (0xa0..=0xbf).contains(&prefix) {
        (usize::from(prefix & 0x1f), offset + 1)
    } else if prefix == 0xd9 {
        (usize::from(*data.get(offset + 1)?), offset + 2)
    } else {
        return None;
    };
    let end = start.checked_add(length)?;
    Some((data.get(start..end)?, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arithmetic_wraps() {
        let e = ValueExpr::Xor(
            Box::new(ValueExpr::Literal(0xc9)),
            Box::new(ValueExpr::Add(
                Box::new(ValueExpr::Literal(0x78)),
                Box::new(ValueExpr::Literal(0x36)),
            )),
        );
        assert_eq!(eval(&e, &[]), 0x67);
    }

    #[test]
    fn packs_numbers_in_requested_endianness() {
        assert_eq!(pack_num(0x1234, NumberKind::U16Le), [0x34, 0x12]);
        assert_eq!(pack_num(0x1234, NumberKind::U16Be), [0x12, 0x34]);
    }

    #[test]
    fn byte_comparison_past_the_buffer_is_false_not_a_panic() {
        let buffers = vec![vec![1u8, 2, 3]];
        let expression = BoolExpr::BytesEq {
            src: 0,
            offset: usize::MAX,
            bytes: vec![1u8].into(),
        };
        assert!(!eval_bool(&expression, &[], &buffers));
    }
}
