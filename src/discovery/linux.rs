use super::cookie::{elapsed_since_tick, matches as cookie_matches, reports_rtt, sequence};
use crate::{affinity, metrics::Metrics, probe::OpenPort};
use anyhow::{Context, Result, bail};
use pnet::{
    packet::{
        Packet,
        ip::IpNextHeaderProtocols,
        ipv4::{MutableIpv4Packet, checksum as ipv4_checksum},
        tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum as tcp_checksum},
    },
    transport::{TransportChannelType::Layer3, ipv4_packet_iter, transport_channel},
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, UdpSocket},
    os::fd::RawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

pub async fn syn_scan(
    jobs: mpsc::Receiver<(IpAddr, u16)>,
    rate: u64,
    batch_size: usize,
    wait: Duration,
    cpu_ids: Option<Arc<[usize]>>,
    metrics: Arc<Metrics>,
    out: mpsc::Sender<OpenPort>,
) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        if let Some(cpus) = &cpu_ids {
            affinity::pin_current(cpus[0])?;
        }
        run(jobs, rate, batch_size, wait, cpu_ids, metrics, out)
    })
    .await??;
    Ok(())
}

fn run(
    mut jobs: mpsc::Receiver<(IpAddr, u16)>,
    rate: u64,
    batch_size: usize,
    wait: Duration,
    cpu_ids: Option<Arc<[usize]>>,
    metrics: Arc<Metrics>,
    out: mpsc::Sender<OpenPort>,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        tracing::info!("not running as root; CAP_NET_RAW on the binary is sufficient");
    }
    let socket = RawIpv4Socket::open().context("open raw sender (CAP_NET_RAW required)")?;
    let protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (_, mut rx) = transport_channel(1 << 20, protocol).context("open raw receiver")?;
    let done = Arc::new(AtomicBool::new(false));
    let done_rx = done.clone();
    let m = metrics.clone();
    let source_port = source_port();
    // A per-run secret keeps the SYN/ACK correlation from being forgeable off-path.
    let secret = random_secret();
    let report_rtt = reports_rtt(wait);
    tracing::info!(source_port, report_rtt, "raw SYN scanner ready");
    let started = Instant::now();
    let sender = out.clone();
    let receiver_cpu = cpu_ids.as_ref().map(|cpus| cpus[1 % cpus.len()]);
    let receiver = std::thread::spawn(move || -> Result<()> {
        if let Some(cpu) = receiver_cpu {
            affinity::pin_current(cpu)?;
        }
        let mut iter = ipv4_packet_iter(&mut rx);
        while !done_rx.load(Ordering::Relaxed) {
            if let Some((packet, _)) = iter.next_with_timeout(Duration::from_millis(100))? {
                if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    continue;
                }
                let Some(tcp) = TcpPacket::new(packet.payload()) else {
                    continue;
                };
                if tcp.get_destination() != source_port {
                    continue;
                }
                let ip = packet.get_source();
                let port = tcp.get_source();
                let flags = tcp.get_flags();
                let syn_ack =
                    flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK);
                let reset = flags & TcpFlags::RST != 0;
                if !syn_ack && !reset {
                    continue;
                }
                // Both SYN/ACK and RST echo our sequence number, so the same cookie
                // check tells open and closed ports apart.
                let sequence = tcp.get_acknowledgement().wrapping_sub(1);
                if !cookie_matches(sequence, ip, port, secret) {
                    continue;
                }
                Metrics::inc(&m.syn_responses);
                if reset {
                    Metrics::inc(&m.ports_closed);
                    continue;
                }
                Metrics::inc(&m.ports_open);
                m.queue_enqueued();
                if sender
                    .blocking_send(OpenPort {
                        ip: IpAddr::V4(ip),
                        port,
                        syn_rtt_ms: report_rtt.then(|| elapsed_since_tick(started, sequence)),
                    })
                    .is_err()
                {
                    // Nothing downstream is consuming open ports any more.
                    m.queue_dequeued();
                    break;
                }
            }
        }
        Ok(())
    });

    let mut batch = PacketBatch::new(batch_size);
    let mut routes = RouteResolver::new()?;
    let mut next = Instant::now();
    let mut disconnected = false;
    loop {
        batch.clear();
        match jobs.blocking_recv() {
            Some(job) => {
                metrics.queue_dequeued();
                add_job(
                    &mut batch,
                    &mut routes,
                    job,
                    source_port,
                    secret,
                    started,
                    &metrics,
                )?
            }
            None => break,
        }
        while batch.len() < batch_size {
            match jobs.try_recv() {
                Ok(job) => {
                    metrics.queue_dequeued();
                    add_job(
                        &mut batch,
                        &mut routes,
                        job,
                        source_port,
                        secret,
                        started,
                        &metrics,
                    )?
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if batch.is_empty() {
            if disconnected {
                break;
            }
            continue;
        }
        // Idle time must not accumulate into send credit, or --max-rate could be
        // exceeded by a burst as soon as jobs arrive again.
        next = next.max(Instant::now());
        let outcome = batch.send_all(socket.0);
        metrics
            .syn_packets_sent
            .fetch_add(outcome.sent as u64, Ordering::Relaxed);
        metrics
            .send_errors
            .fetch_add(outcome.skipped as u64, Ordering::Relaxed);
        metrics
            .targets_skipped
            .fetch_add(outcome.skipped as u64, Ordering::Relaxed);
        tracing::debug!(
            batch = outcome.sent + outcome.skipped,
            sent = outcome.sent,
            skipped = outcome.skipped,
            "raw SYN batch processed"
        );
        next += Duration::from_secs_f64((outcome.sent + outcome.skipped) as f64 / rate as f64);
        if let Some(delay) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(delay);
        }
        if disconnected {
            break;
        }
    }
    std::thread::sleep(wait);
    done.store(true, Ordering::Relaxed);
    receiver
        .join()
        .map_err(|_| anyhow::anyhow!("receiver panicked"))??;
    drop(out);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_job(
    batch: &mut PacketBatch,
    routes: &mut RouteResolver,
    job: (IpAddr, u16),
    source_port: u16,
    secret: u32,
    started: Instant,
    metrics: &Metrics,
) -> Result<()> {
    let (ip, port) = job;
    let IpAddr::V4(dst) = ip else {
        Metrics::inc(&metrics.targets_skipped);
        return Ok(());
    };
    // A single unroutable destination must not abort the whole scan.
    let src = match routes.source_for(dst) {
        Ok(src) => src,
        Err(error) => {
            tracing::debug!(%dst, %error, "no route to destination; skipping");
            Metrics::inc(&metrics.targets_skipped);
            return Ok(());
        }
    };
    batch.push(
        src,
        dst,
        source_port,
        port,
        sequence(dst, port, secret, started),
    )?;
    tracing::trace!(%src, %dst, port, "queued raw SYN packet");
    Ok(())
}

struct RawIpv4Socket(RawFd);
impl RawIpv4Socket {
    fn open() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }
        Ok(Self(fd))
    }
}
impl Drop for RawIpv4Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

struct PacketSlot {
    bytes: [u8; 40],
    destination: libc::sockaddr_in,
    destination_ip: Ipv4Addr,
    destination_port: u16,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SendOutcome {
    sent: usize,
    skipped: usize,
}
struct PacketBatch {
    slots: Vec<PacketSlot>,
    iovecs: Vec<libc::iovec>,
    messages: Vec<libc::mmsghdr>,
    capacity: usize,
}
impl PacketBatch {
    fn new(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            iovecs: Vec::with_capacity(capacity),
            messages: Vec::with_capacity(capacity),
            capacity,
        }
    }
    fn clear(&mut self) {
        self.slots.clear();
        self.iovecs.clear();
        self.messages.clear();
    }
    fn len(&self) -> usize {
        self.slots.len()
    }
    fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
    fn push(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        source_port: u16,
        port: u16,
        sequence: u32,
    ) -> Result<()> {
        if self.slots.len() == self.capacity {
            bail!("packet batch is full");
        }
        let mut bytes = [0u8; 40];
        build_syn_packet(&mut bytes, src, dst, source_port, port, sequence)?;
        let mut destination: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        destination.sin_family = libc::AF_INET as libc::sa_family_t;
        destination.sin_port = port.to_be();
        destination.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
        self.slots.push(PacketSlot {
            bytes,
            destination,
            destination_ip: dst,
            destination_port: port,
        });
        Ok(())
    }
    fn send_all(&mut self, fd: RawFd) -> SendOutcome {
        for slot in &mut self.slots {
            self.iovecs.push(libc::iovec {
                iov_base: slot.bytes.as_mut_ptr().cast(),
                iov_len: slot.bytes.len(),
            });
        }
        for (slot, iovec) in self.slots.iter_mut().zip(self.iovecs.iter_mut()) {
            let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
            header.msg_name = (&mut slot.destination as *mut libc::sockaddr_in).cast();
            header.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            header.msg_iov = iovec;
            header.msg_iovlen = 1;
            self.messages.push(libc::mmsghdr {
                msg_hdr: header,
                msg_len: 0,
            });
        }
        let mut cursor = 0;
        let mut outcome = SendOutcome::default();
        while cursor < self.messages.len() {
            let result = unsafe {
                libc::sendmmsg(
                    fd,
                    self.messages.as_mut_ptr().add(cursor),
                    (self.messages.len() - cursor) as libc::c_uint,
                    0,
                )
            };
            if result > 0 {
                cursor += result as usize;
                outcome.sent += result as usize;
                continue;
            }
            let error = if result < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::new(io::ErrorKind::WriteZero, "sendmmsg sent no packets")
            };
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            let slot = &self.slots[cursor];
            tracing::warn!(
                ip = %slot.destination_ip,
                port = slot.destination_port,
                %error,
                "raw SYN send failed; skipping target"
            );
            cursor += 1;
            outcome.skipped += 1;
        }
        outcome
    }
}

fn build_syn_packet(
    bytes: &mut [u8; 40],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    source_port: u16,
    port: u16,
    sequence: u32,
) -> Result<()> {
    {
        let mut tcp = MutableTcpPacket::new(&mut bytes[20..]).context("TCP packet")?;
        tcp.set_source(source_port);
        tcp.set_destination(port);
        tcp.set_sequence(sequence);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_checksum(tcp_checksum(&tcp.to_immutable(), &src, &dst));
    }
    {
        let mut ip = MutableIpv4Packet::new(bytes).context("IPv4 packet")?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    }
    Ok(())
}

struct RouteResolver {
    socket: UdpSocket,
    cached: Option<(Ipv4Addr, Ipv4Addr)>,
}
impl RouteResolver {
    fn new() -> Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind("0.0.0.0:0")?,
            cached: None,
        })
    }
    fn source_for(&mut self, dst: Ipv4Addr) -> Result<Ipv4Addr> {
        if let Some((previous, source)) = self.cached
            && previous == dst
        {
            return Ok(source);
        }
        self.socket.connect((dst, 9))?;
        let IpAddr::V4(source) = self.socket.local_addr()?.ip() else {
            bail!("no IPv4 source route");
        };
        self.cached = Some((dst, source));
        Ok(source)
    }
}
/// Best-effort per-run randomness. `getrandom(2)` is not exposed by `libc` on every
/// supported target, so fall back to `/dev/urandom` and then to process state.
fn random_secret() -> u32 {
    // `/dev/urandom` never reaches EOF, so read a fixed number of bytes.
    let mut bytes = [0u8; 4];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom")
        && io::Read::read_exact(&mut file, &mut bytes).is_ok()
    {
        return u32::from_ne_bytes(bytes);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos
        .rotate_left(11)
        .wrapping_mul(2_654_435_761)
        .wrapping_add(std::process::id().rotate_left(19))
}

/// Pick a source port outside the kernel's ephemeral range so a local connection can
/// never be assigned the port the scanner correlates responses on.
fn source_port() -> u16 {
    let (low, high) = local_port_range();
    let offset = (random_secret() % 4096) as u16;
    if high < u16::MAX - 1 {
        let span = u16::MAX - high;
        return high + 1 + offset % span;
    }
    if low > 2048 {
        let span = low - 1025;
        return 1024 + offset % span;
    }
    // No room outside the ephemeral range; stay deterministic rather than colliding
    // with whatever the kernel hands out next.
    61000 + offset % 4000
}

fn local_port_range() -> (u16, u16) {
    let default = (32768u16, 60999u16);
    let Ok(text) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") else {
        return default;
    };
    let mut values = text
        .split_whitespace()
        .filter_map(|v| v.parse::<u16>().ok());
    match (values.next(), values.next()) {
        (Some(low), Some(high)) if low <= high => (low, high),
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_port_avoids_the_ephemeral_range() {
        let (low, high) = local_port_range();
        for _ in 0..64 {
            let port = source_port();
            assert!(
                port < low || port > high || low <= 2048,
                "source port {port} lands inside the ephemeral range {low}-{high}"
            );
        }
    }

    #[test]
    fn packet_contains_expected_endpoints() {
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let mut bytes = [0; 40];
        build_syn_packet(&mut bytes, src, dst, 45000, 8080, 123).unwrap();
        let ip = pnet::packet::ipv4::Ipv4Packet::new(&bytes).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(ip.get_source(), src);
        assert_eq!(ip.get_destination(), dst);
        assert_eq!(tcp.get_source(), 45000);
        assert_eq!(tcp.get_destination(), 8080);
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
    }

    #[test]
    fn syscall_failure_skips_only_the_current_packet() {
        let mut batch = PacketBatch::new(1);
        batch
            .push(
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(198, 51, 100, 20),
                45000,
                8080,
                123,
            )
            .unwrap();
        let outcome = batch.send_all(-1);
        assert_eq!(
            outcome,
            SendOutcome {
                sent: 0,
                skipped: 1
            }
        );
    }
}
