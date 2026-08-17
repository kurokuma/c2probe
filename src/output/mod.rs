use anyhow::{Context, Result};
use serde::Serialize;
use std::{io, path::Path};
use tokio::{
    fs::File,
    io::{AsyncWrite, AsyncWriteExt, BufWriter},
};

use crate::cli::OutputFormat;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub target: TargetResult,
    pub discovery: DiscoveryResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeResult>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetResult {
    pub ip: std::net::IpAddr,
    pub port: u16,
    pub transport: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryResult {
    pub port_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syn_rtt_ms: Option<u64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub name: String,
    pub family: String,
    pub protocol: String,
    pub confirmed: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub probable: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub observed: bool,
    pub confidence: f64,
    pub status: String,
    pub duration_ms: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub struct OutputWriter {
    format: OutputFormat,
    writer: BufWriter<Box<dyn AsyncWrite + Unpin + Send>>,
    sync_file: Option<File>,
    csv_header: bool,
}

impl OutputWriter {
    pub async fn new(format: OutputFormat, path: Option<&Path>) -> Result<Self> {
        let (writer, sync_file): (Box<dyn AsyncWrite + Unpin + Send>, Option<File>) = match path {
            Some(p) => {
                let file = File::create(p)
                    .await
                    .with_context(|| format!("create {}", p.display()))?;
                let sync_file = file
                    .try_clone()
                    .await
                    .with_context(|| format!("clone output handle {}", p.display()))?;
                (Box::new(file), Some(sync_file))
            }
            None => (Box::new(tokio::io::stdout()), None),
        };
        Ok(Self {
            format,
            writer: BufWriter::new(writer),
            sync_file,
            csv_header: false,
        })
    }
    pub async fn write(&mut self, result: &ScanResult) -> Result<()> {
        let bytes = match self.format {
            OutputFormat::Jsonl => {
                let mut v = serde_json::to_vec(result)?;
                v.push(b'\n');
                v
            }
            OutputFormat::Csv => self.csv_row(result)?,
        };
        self.writer.write_all(&bytes).await?;
        // Make every complete JSONL/CSV record visible even if another task fails
        // before the periodic durability sync runs.
        self.writer.flush().await?;
        Ok(())
    }

    /// Streaming output is only streaming if it reaches the file before the buffer
    /// fills, so the caller flushes on a timer as well as at shutdown.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.writer.flush().await?;
        if let Some(file) = &self.sync_file {
            file.sync_data().await?;
        }
        Ok(())
    }
    fn csv_row(&mut self, r: &ScanResult) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        {
            let mut w = csv::WriterBuilder::new()
                .has_headers(false)
                .from_writer(&mut out);
            if !self.csv_header {
                w.write_record([
                    "timestamp",
                    "ip",
                    "port",
                    "port_state",
                    "probe",
                    "family",
                    "protocol",
                    "confirmed",
                    "probable",
                    "observed",
                    "confidence",
                    "status",
                    "duration_ms",
                    "extra_json",
                ])?;
                self.csv_header = true;
            }
            let p = r.probe.as_ref();
            w.write_record([
                r.timestamp.to_rfc3339(),
                r.target.ip.to_string(),
                r.target.port.to_string(),
                r.discovery.port_state.clone(),
                p.map(|x| x.name.clone()).unwrap_or_default(),
                p.map(|x| x.family.clone()).unwrap_or_default(),
                p.map(|x| x.protocol.clone()).unwrap_or_default(),
                p.map(|x| x.confirmed.to_string()).unwrap_or_default(),
                p.map(|x| x.probable.to_string()).unwrap_or_default(),
                p.map(|x| x.observed.to_string()).unwrap_or_default(),
                p.map(|x| x.confidence.to_string()).unwrap_or_default(),
                p.map(|x| x.status.clone()).unwrap_or_default(),
                p.map(|x| x.duration_ms.to_string()).unwrap_or_default(),
                serde_json::to_string(&r.fields)?,
            ])?;
            w.flush()?;
        }
        Ok(out)
    }
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serializes_json() {
        let r = ScanResult {
            timestamp: chrono::Utc::now(),
            target: TargetResult {
                ip: "127.0.0.1".parse().unwrap(),
                port: 1,
                transport: "tcp".into(),
            },
            discovery: DiscoveryResult {
                port_state: "open".into(),
                syn_rtt_ms: None,
            },
            probe: None,
            fields: Default::default(),
        };
        assert!(serde_json::to_string(&r).unwrap().contains("port_state"));
    }

    #[tokio::test]
    async fn file_record_is_visible_before_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stream.jsonl");
        let mut writer = OutputWriter::new(OutputFormat::Jsonl, Some(&path))
            .await
            .unwrap();
        let result = ScanResult {
            timestamp: chrono::Utc::now(),
            target: TargetResult {
                ip: "127.0.0.1".parse().unwrap(),
                port: 80,
                transport: "tcp".into(),
            },
            discovery: DiscoveryResult {
                port_state: "open".into(),
                syn_rtt_ms: None,
            },
            probe: None,
            fields: Default::default(),
        };
        writer.write(&result).await.unwrap();
        let text = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(text.lines().count(), 1);
        writer.shutdown().await.unwrap();
    }
}
