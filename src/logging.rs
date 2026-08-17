use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use tracing_subscriber::{EnvFilter, filter::LevelFilter, fmt::MakeWriter};

use crate::cli::LogLevel;

#[derive(Clone)]
struct TeeMakeWriter {
    file: Arc<Mutex<File>>,
}

struct TeeWriter {
    file: Arc<Mutex<File>>,
}

impl<'a> MakeWriter<'a> for TeeMakeWriter {
    type Writer = TeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TeeWriter {
            file: self.file.clone(),
        }
    }
}

impl Write for TeeWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        io::stderr().write_all(buffer)?;
        self.file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .write_all(buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()?;
        self.file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .flush()
    }
}

pub fn init(level: LogLevel, path: Option<&Path>) -> Result<()> {
    let default_level = match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Off => LevelFilter::OFF,
    };
    let filter = || {
        EnvFilter::builder()
            .with_default_directive(default_level.into())
            .from_env_lossy()
    };

    if let Some(path) = path {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file {}", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_writer(TeeMakeWriter {
                file: Arc::new(Mutex::new(file)),
            })
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize logging: {error}"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_writer(io::stderr)
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize logging: {error}"))?;
    }
    Ok(())
}
