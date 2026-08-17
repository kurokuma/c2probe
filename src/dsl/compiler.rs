use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::fs;

use super::{
    BinaryExpr, BoolExpr, CompiledProbe, CompiledResult, Condition, Expr, ExtractType,
    FieldTemplate, NumberKind, Op, PackType, ProbeDocument, ValueExpr,
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
    let mut files = paths.to_vec();
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
        let doc: ProbeDocument =
            serde_yaml::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
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
    if matches!(doc.transport.kind, crate::dsl::TransportType::Tls) && !doc.transport.insecure_tls {
        bail!(
            "transport.type: tls requires insecure_tls: true; this build performs no \
             certificate validation, and a probe must opt into that explicitly"
        );
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
            + usize::from(step.pack.is_some())
            + usize::from(step.concat.is_some())
            + usize::from(step.recv_exact.is_some())
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
            buffers.insert(s.name, next_buf);
            sizes.push(kind.size());
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
            buffers.insert(s.name, next_buf);
            sizes.push(length);
            ops.push(Op::Concat {
                sources: sources.into(),
                dst: next_buf,
            });
            next_buf += 1;
        } else if let Some(s) = step.recv_exact {
            if s.bytes == 0 || s.bytes > MAX_BUFFER_BYTES {
                bail!("recv_exact bytes must be 1..=1048576");
            }
            if buffers.insert(s.save_as.clone(), next_buf).is_some() {
                bail!("duplicate buffer {}", s.save_as);
            }
            sizes.push(s.bytes);
            ops.push(Op::RecvExact {
                length: s.bytes,
                dst: next_buf,
            });
            next_buf += 1;
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
        ops: ops.into(),
        result: CompiledResult {
            confidence: doc.result.confidence,
            unmatched_confidence: doc.result.unmatched_confidence,
            status: doc.result.status.into(),
            unmatched_status: doc.result.unmatched_status.into(),
            fields,
        },
    })
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
        ExtractType::Crc32 => unreachable!(),
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
    } else {
        let x = c.bytes_eq.as_ref().unwrap();
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
