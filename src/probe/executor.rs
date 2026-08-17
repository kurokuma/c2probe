use super::transport::{self, ProbeFailure, ProbeResult};
use crate::dsl::{BoolExpr, CompiledProbe, FieldTemplate, NumberKind, Op, ValueExpr};
use serde_json::{Map, Value};
use std::{net::IpAddr, time::Instant};

#[derive(Debug)]
pub struct ProbeExecution {
    pub confirmed: bool,
    pub responsive: bool,
    pub confidence: f64,
    pub status: String,
    pub duration_ms: u64,
    pub fields: Map<String, Value>,
}

struct Outcome {
    matched: bool,
    responsive: bool,
    confidence: f64,
    status: String,
    registers: Vec<u64>,
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
                    FieldTemplate::Literal(v) => v.clone(),
                };
                fields.insert(name.clone(), value);
            }
            ProbeExecution {
                confirmed: outcome.matched,
                responsive: outcome.responsive,
                confidence: outcome.confidence,
                status: outcome.status,
                duration_ms: started.elapsed().as_millis() as u64,
                fields,
            }
        }
        Err(failure) => ProbeExecution {
            confirmed: false,
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
        responsive,
        confidence,
        status,
        registers: regs,
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
    }
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
