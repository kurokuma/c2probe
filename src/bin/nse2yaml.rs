use anyhow::{Context, Result, bail};
use c2probe::{
    dsl::{ProbeDocument, compile},
    nse,
};
use clap::Parser;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(
    name = "nse2yaml",
    version,
    about = "Strict, non-executing NSE to c2probe YAML converter"
)]
struct Args {
    /// Reviewed NSE source file.
    input: PathBuf,
    /// Directory that receives one YAML file per detected mode.
    #[arg(short = 'o', long, default_value = "generated-probes")]
    output_dir: PathBuf,
    /// JSON conversion/equivalence report path (defaults inside output-dir).
    #[arg(long)]
    report: Option<PathBuf>,
    /// Replace existing generated YAML and report files.
    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let source = fs::read_to_string(&args.input)
        .with_context(|| format!("read {}", args.input.display()))?;
    let mut bundle = nse::convert_valleyrat(&source)
        .with_context(|| format!("convert {}", args.input.display()))?;
    bundle.report.source = args.input.display().to_string();

    // Parse and compile every generated document before creating output files.
    for probe in &bundle.probes {
        let document: ProbeDocument = serde_yaml::from_str(&probe.yaml)
            .with_context(|| format!("parse generated {}", probe.filename))?;
        compile(
            document,
            Duration::from_millis(750),
            Duration::from_millis(1000),
        )
        .with_context(|| format!("compile generated {}", probe.filename))?;
    }
    bundle.report.safety.generated_yaml_compiled = true;

    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("create {}", args.output_dir.display()))?;
    let report_path = args
        .report
        .unwrap_or_else(|| args.output_dir.join("conversion-report.json"));
    if !args.force {
        for path in bundle
            .probes
            .iter()
            .map(|probe| args.output_dir.join(&probe.filename))
            .chain(std::iter::once(report_path.clone()))
        {
            if path.exists() {
                bail!(
                    "output already exists: {} (use --force to replace it)",
                    path.display()
                );
            }
        }
    }
    for probe in &bundle.probes {
        write_new_or_replace(
            &args.output_dir.join(&probe.filename),
            probe.yaml.as_bytes(),
            args.force,
        )?;
    }
    let report = serde_json::to_vec_pretty(&bundle.report)?;
    write_new_or_replace(&report_path, &report, args.force)?;

    println!(
        "generated={} profile={} report={}",
        bundle.probes.len(),
        bundle.report.profile,
        report_path.display()
    );
    for rule in &bundle.report.generated_rules {
        println!("{} -> {} ({})", rule.mode, rule.file, rule.equivalence);
    }
    Ok(())
}

fn write_new_or_replace(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write {} (use --force to replace it)", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if bytes.is_empty() {
        bail!("refusing to keep empty generated file {}", path.display());
    }
    Ok(())
}
