use std::{collections::HashSet, net::IpAddr, str::FromStr};

use ipnet::IpNet;

use crate::{cli::parse_socket_target, error::C2ProbeError};

#[derive(Debug, Clone)]
pub struct TargetSet {
    nets: Vec<IpNet>,
    sockets: Vec<(IpAddr, u16)>,
    excludes: Vec<IpNet>,
}

impl TargetSet {
    pub fn parse(
        lines: &[String],
        exclusions: &[String],
        probe_mode: bool,
    ) -> Result<Self, C2ProbeError> {
        let mut nets = Vec::new();
        let mut sockets = Vec::new();
        for raw in lines {
            let value = clean(raw);
            if value.is_empty() {
                continue;
            }
            if probe_mode && let Some(socket) = parse_socket_target(value) {
                sockets.push(socket);
                continue;
            }
            nets.push(parse_net(value)?);
        }
        let excludes = exclusions
            .iter()
            .map(|v| clean(v))
            .filter(|v| !v.is_empty())
            .map(parse_net)
            .collect::<Result<Vec<_>, _>>()?;
        if nets.is_empty() && sockets.is_empty() {
            return Err(C2ProbeError::InvalidTarget("empty target set".into()));
        }
        Ok(Self {
            nets,
            sockets,
            // Overlapping exclusions would otherwise be subtracted twice by host_count.
            excludes: IpNet::aggregate(&excludes),
        })
    }

    fn is_excluded(&self, ip: &IpAddr) -> bool {
        self.excludes.iter().any(|n| n.contains(ip))
    }

    pub fn iter_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.nets
            .iter()
            .flat_map(IpNet::hosts)
            .filter(|ip| !self.is_excluded(ip))
    }

    /// Explicit `IP:PORT` targets that survive `--exclude` / `--exclude-file`.
    pub fn iter_sockets(&self) -> impl Iterator<Item = (IpAddr, u16)> + '_ {
        self.sockets
            .iter()
            .copied()
            .filter(|(ip, _)| !self.is_excluded(ip))
    }

    pub fn socket_targets<'a>(
        &'a self,
        ports: &'a PortSet,
    ) -> impl Iterator<Item = (IpAddr, u16)> + 'a {
        let expanded = self
            .iter_ips()
            .flat_map(move |ip| ports.iter().map(move |p| (ip, p)));
        self.iter_sockets().chain(expanded)
    }

    pub fn socket_targets_shard<'a>(
        &'a self,
        ports: &'a PortSet,
        worker_id: usize,
        worker_count: usize,
    ) -> impl Iterator<Item = (IpAddr, u16)> + 'a {
        assert!(worker_count > 0 && worker_id < worker_count);
        let explicit = self
            .iter_sockets()
            .filter(move |(_, port)| ports.shard_for_port(*port, worker_count) == worker_id);
        let expanded = self.iter_ips().flat_map(move |ip| {
            ports
                .iter()
                .skip(worker_id)
                .step_by(worker_count)
                .map(move |port| (ip, port))
        });
        explicit.chain(expanded)
    }

    /// Addresses produced by [`Self::iter_ips`], with exclusions already subtracted.
    pub fn host_count(&self) -> u128 {
        let total = self.nets.iter().map(net_size).sum::<u128>();
        let excluded = self
            .nets
            .iter()
            .map(|net| excluded_hosts(net, &self.excludes))
            .sum::<u128>();
        total.saturating_sub(excluded)
    }

    /// Distinct addresses touched by the scan, including explicit `IP:PORT` targets.
    pub fn target_count(&self) -> u128 {
        let explicit = self
            .iter_sockets()
            .map(|(ip, _)| ip)
            .collect::<HashSet<_>>()
            .len() as u128;
        self.host_count().saturating_add(explicit)
    }

    /// Jobs produced by [`Self::socket_targets`]; used for metrics and capacity planning.
    pub fn job_count(&self, ports: &PortSet) -> u128 {
        let explicit = self.iter_sockets().count() as u128;
        self.host_count()
            .saturating_mul(u128::from(ports.len()))
            .saturating_add(explicit)
    }

    pub fn has_ipv6_nets(&self) -> bool {
        self.nets.iter().any(|net| net.addr().is_ipv6())
    }
}

fn clean(value: &str) -> &str {
    value.split('#').next().unwrap_or("").trim()
}

fn parse_net(value: &str) -> Result<IpNet, C2ProbeError> {
    if let Ok(net) = value.parse() {
        return Ok(net);
    }
    let ip: IpAddr = value
        .parse()
        .map_err(|_| C2ProbeError::InvalidTarget(value.into()))?;
    Ok(IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).expect("valid prefix"))
}

fn address_count(net: &IpNet) -> u128 {
    let bits = if net.addr().is_ipv4() { 32 } else { 128 };
    if net.prefix_len() == 0 && bits == 128 {
        u128::MAX
    } else {
        1u128 << (bits - net.prefix_len())
    }
}

fn net_size(net: &IpNet) -> u128 {
    let total = address_count(net);
    match net {
        IpNet::V4(v) if v.prefix_len() <= 30 => total.saturating_sub(2),
        _ => total,
    }
}

/// Addresses of `net` that [`TargetSet::iter_ips`] skips because of `excludes`.
///
/// `excludes` must be disjoint (see `IpNet::aggregate` in `TargetSet::parse`), so the
/// per-exclusion counts can simply be summed.
fn excluded_hosts(net: &IpNet, excludes: &[IpNet]) -> u128 {
    excludes
        .iter()
        .map(|exclude| overlap_hosts(net, exclude))
        .sum()
}

fn overlap_hosts(net: &IpNet, exclude: &IpNet) -> u128 {
    // Two CIDRs are either disjoint or nested, so the intersection is one of them.
    let intersection = if net.contains(exclude) {
        *exclude
    } else if exclude.contains(net) {
        *net
    } else {
        return 0;
    };
    let mut count = address_count(&intersection);
    // hosts() already skips network/broadcast for IPv4 prefixes <= 30, so an exclusion
    // covering them must not be counted a second time.
    if let IpNet::V4(v) = net
        && v.prefix_len() <= 30
    {
        for edge in [v.network(), v.broadcast()] {
            if intersection.contains(&IpAddr::V4(edge)) {
                count = count.saturating_sub(1);
            }
        }
    }
    count
}

#[derive(Debug, Clone)]
pub struct PortSet(Vec<(u16, u16)>);

impl FromStr for PortSet {
    type Err = C2ProbeError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim();
        if raw.eq_ignore_ascii_case("all") {
            return Ok(Self(vec![(1, 65535)]));
        }
        let mut ports = HashSet::new();
        for part in raw.split(',') {
            if let Some((a, b)) = part.split_once('-') {
                let start = parse_port(a, raw)?;
                let end = parse_port(b, raw)?;
                if start > end {
                    return Err(C2ProbeError::InvalidPorts(raw.into()));
                }
                ports.extend(start..=end);
            } else {
                ports.insert(parse_port(part, raw)?);
            }
        }
        if ports.is_empty() {
            return Err(C2ProbeError::InvalidPorts(raw.into()));
        }
        let mut sorted: Vec<_> = ports.into_iter().collect();
        sorted.sort_unstable();
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        for p in sorted {
            match ranges.last_mut() {
                Some((_, end)) if end.saturating_add(1) == p => *end = p,
                _ => ranges.push((p, p)),
            }
        }
        Ok(Self(ranges))
    }
}

fn parse_port(v: &str, original: &str) -> Result<u16, C2ProbeError> {
    let p: u16 = v
        .trim()
        .parse()
        .map_err(|_| C2ProbeError::InvalidPorts(original.into()))?;
    if p == 0 {
        Err(C2ProbeError::InvalidPorts(original.into()))
    } else {
        Ok(p)
    }
}

impl PortSet {
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.0.iter().flat_map(|(a, b)| *a..=*b)
    }
    pub fn len(&self) -> u64 {
        self.0
            .iter()
            .map(|(a, b)| u64::from(*b) - u64::from(*a) + 1)
            .sum()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn shard_for_port(&self, port: u16, worker_count: usize) -> usize {
        let mut ordinal = 0u64;
        for (start, end) in &self.0 {
            if (*start..=*end).contains(&port) {
                ordinal += u64::from(port - *start);
                return ordinal as usize % worker_count;
            }
            ordinal += u64::from(*end) - u64::from(*start) + 1;
        }
        usize::from(port) % worker_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_merges_ports() {
        let p: PortSet = "443,80,81-82,81".parse().unwrap();
        assert_eq!(p.iter().collect::<Vec<_>>(), vec![80, 81, 82, 443]);
    }
    #[test]
    fn excludes_cidr() {
        let t = TargetSet::parse(&["192.0.2.0/30".into()], &["192.0.2.1".into()], false).unwrap();
        assert_eq!(
            t.iter_ips().collect::<Vec<_>>(),
            vec!["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn excludes_apply_to_explicit_socket_targets() {
        let targets = TargetSet::parse(
            &["192.0.2.1:8443".into(), "192.0.2.2:8443".into()],
            &["192.0.2.1".into()],
            true,
        )
        .unwrap();
        let ports: PortSet = "80".parse().unwrap();
        assert_eq!(
            targets.socket_targets(&ports).collect::<Vec<_>>(),
            vec![("192.0.2.2".parse::<IpAddr>().unwrap(), 8443)]
        );
        assert_eq!(targets.job_count(&ports), 1);
    }

    #[test]
    fn counts_match_iteration() {
        let ports: PortSet = "80,443".parse().unwrap();
        for (lines, exclusions, probe_mode) in [
            (vec!["192.0.2.0/24".to_string()], vec![], false),
            (
                vec!["192.0.2.0/24".to_string()],
                vec!["192.0.2.128/25".to_string()],
                false,
            ),
            (
                vec!["192.0.2.0/24".to_string()],
                vec!["192.0.2.0/25".to_string(), "192.0.2.64/26".to_string()],
                false,
            ),
            (
                vec!["192.0.2.0/30".to_string()],
                vec!["192.0.2.0/30".to_string()],
                false,
            ),
            (
                vec!["192.0.2.0/24".to_string()],
                vec!["192.0.2.255".to_string(), "192.0.2.0".to_string()],
                false,
            ),
            (vec!["192.0.2.0/31".to_string()], vec![], false),
            (vec!["2001:db8::/126".to_string()], vec![], false),
            (
                vec!["192.0.2.7:9001".to_string(), "192.0.2.0/29".to_string()],
                vec!["192.0.2.1".to_string()],
                true,
            ),
        ] {
            let targets = TargetSet::parse(&lines, &exclusions, probe_mode).unwrap();
            assert_eq!(
                targets.host_count(),
                targets.iter_ips().count() as u128,
                "host_count for {lines:?} minus {exclusions:?}"
            );
            assert_eq!(
                targets.job_count(&ports),
                targets.socket_targets(&ports).count() as u128,
                "job_count for {lines:?} minus {exclusions:?}"
            );
        }
    }

    #[test]
    fn shards_are_disjoint_and_complete() {
        let targets = TargetSet::parse(&["192.0.2.1".into()], &[], false).unwrap();
        let ports: PortSet = "80-89".parse().unwrap();
        let first = targets
            .socket_targets_shard(&ports, 0, 3)
            .collect::<Vec<_>>();
        let second = targets
            .socket_targets_shard(&ports, 1, 3)
            .collect::<Vec<_>>();
        let third = targets
            .socket_targets_shard(&ports, 2, 3)
            .collect::<Vec<_>>();
        let mut combined = first
            .iter()
            .chain(&second)
            .chain(&third)
            .copied()
            .collect::<Vec<_>>();
        combined.sort_unstable();
        assert_eq!(combined, targets.socket_targets(&ports).collect::<Vec<_>>());
        assert!(
            first
                .iter()
                .all(|item| !second.contains(item) && !third.contains(item))
        );
    }

    #[test]
    fn explicit_and_expanded_duplicate_land_on_same_shard() {
        let targets =
            TargetSet::parse(&["192.0.2.1:83".into(), "192.0.2.1".into()], &[], true).unwrap();
        let ports: PortSet = "80-89".parse().unwrap();
        let expected = ("192.0.2.1".parse().unwrap(), 83);
        let owners = (0..3)
            .filter(|worker| {
                targets
                    .socket_targets_shard(&ports, *worker, 3)
                    .any(|item| item == expected)
            })
            .collect::<Vec<_>>();
        assert_eq!(owners, vec![0]);
    }
}
