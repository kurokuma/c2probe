use anyhow::{Context, Result, bail};

pub fn parse_cpu_set(value: &str) -> Result<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Some((start, end)) = part.split_once('-') {
            let start = start
                .parse::<usize>()
                .with_context(|| format!("invalid CPU {start}"))?;
            let end = end
                .parse::<usize>()
                .with_context(|| format!("invalid CPU {end}"))?;
            if start > end || end - start > 4096 {
                bail!("invalid CPU range {part}");
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(
                part.parse::<usize>()
                    .with_context(|| format!("invalid CPU {part}"))?,
            );
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    if cpus.is_empty() {
        bail!("CPU set is empty");
    }
    #[cfg(target_os = "linux")]
    if cpus.iter().any(|cpu| *cpu >= libc::CPU_SETSIZE as usize) {
        bail!("CPU ID exceeds Linux CPU_SETSIZE");
    }
    Ok(cpus)
}

pub fn format_cpu_set(cpus: &[usize]) -> String {
    cpus.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(target_os = "linux")]
pub fn pin_current(cpu: usize) -> Result<()> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("set CPU affinity to CPU {cpu}"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn validate_available(cpus: &[usize]) -> Result<()> {
    unsafe {
        let mut available: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut available) != 0 {
            return Err(std::io::Error::last_os_error()).context("read available CPU affinity");
        }
        for cpu in cpus {
            if !libc::CPU_ISSET(*cpu, &available) {
                bail!("CPU {cpu} is not available in the current cpuset");
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current(_: usize) -> Result<()> {
    bail!("--cpu-affinity is currently supported on Linux only")
}

#[cfg(not(target_os = "linux"))]
pub fn validate_available(_: &[usize]) -> Result<()> {
    bail!("--cpu-affinity is currently supported on Linux only")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_deduplicates() {
        assert_eq!(parse_cpu_set("3,1-2,2").unwrap(), vec![1, 2, 3]);
        assert_eq!(format_cpu_set(&[1, 2, 3]), "1,2,3");
    }

    #[test]
    fn rejects_backwards_range() {
        assert!(parse_cpu_set("4-2").is_err());
    }
}
