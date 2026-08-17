//! Stateless SYN/ACK correlation.
//!
//! The only field a SYN/ACK or RST echoes back is the acknowledgement number, so both
//! the correlation cookie and the send timestamp have to fit in the 32-bit sequence
//! number we choose. The low bits carry a coarse timestamp for RTT, the rest is a
//! keyed cookie over the destination.
//!
//! This module is platform independent so the arithmetic stays testable on hosts that
//! cannot build the Linux raw socket path.

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

pub const TIMESTAMP_BITS: u32 = 8;
pub const TIMESTAMP_TICK_MS: u64 = 4;
/// How long the timestamp runs before it wraps and RTT becomes ambiguous.
pub const TIMESTAMP_SPAN_MS: u64 = (1 << TIMESTAMP_BITS) * TIMESTAMP_TICK_MS;

/// Width left for the cookie once the timestamp has taken its bits.
const COOKIE_BITS: u32 = 32 - TIMESTAMP_BITS;

/// Rotate-and-xor mixing would let whole input bits fall outside the retained window,
/// so the destination is run through an avalanche mix before being truncated.
pub fn cookie(ip: Ipv4Addr, port: u16, secret: u32) -> u32 {
    let mut x = (u64::from(u32::from(ip)) << 32) ^ (u64::from(port) << 16) ^ u64::from(secret);
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    (x >> (64 - COOKIE_BITS)) as u32
}

fn tick(elapsed: Duration) -> u32 {
    ((elapsed.as_millis() as u64 / TIMESTAMP_TICK_MS) % (1 << TIMESTAMP_BITS)) as u32
}

pub fn sequence(ip: Ipv4Addr, port: u16, secret: u32, started: Instant) -> u32 {
    (cookie(ip, port, secret) << TIMESTAMP_BITS) | tick(started.elapsed())
}

/// True when `sequence` was produced by [`sequence`] for this destination.
pub fn matches(sequence: u32, ip: Ipv4Addr, port: u16, secret: u32) -> bool {
    sequence >> TIMESTAMP_BITS == cookie(ip, port, secret)
}

/// Milliseconds since the packet carrying `sequence` was sent, rounded to a tick.
pub fn elapsed_since_tick(started: Instant, sequence: u32) -> u64 {
    let sent = sequence & ((1 << TIMESTAMP_BITS) - 1);
    let now = tick(started.elapsed());
    u64::from(now.wrapping_sub(sent) % (1 << TIMESTAMP_BITS)) * TIMESTAMP_TICK_MS
}

/// RTT is only unambiguous while the wait stays inside one wrap of the timestamp.
pub fn reports_rtt(wait: Duration) -> bool {
    wait <= Duration::from_millis(TIMESTAMP_SPAN_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

    #[test]
    fn a_syn_ack_acknowledgement_recovers_the_cookie() {
        let secret = 0x1234_5678;
        let started = Instant::now();
        let sent = sequence(IP, 8080, secret, started);
        // A SYN/ACK acknowledges seq + 1; the receiver undoes that first.
        let recovered = sent.wrapping_add(1).wrapping_sub(1);
        assert!(matches(recovered, IP, 8080, secret));
        assert!(!matches(recovered, IP, 8081, secret));
        assert!(!matches(
            recovered,
            Ipv4Addr::new(198, 51, 100, 21),
            8080,
            secret
        ));
        assert!(!matches(recovered, IP, 8080, secret ^ 1));
    }

    #[test]
    fn cookie_leaves_room_for_the_timestamp() {
        // The cookie must not occupy the timestamp bits, or the two would collide.
        assert_eq!(cookie(IP, 8080, 0xffff_ffff) >> COOKIE_BITS, 0);
        let sent = sequence(IP, 8080, 0xffff_ffff, Instant::now());
        assert!(matches(sent, IP, 8080, 0xffff_ffff));
    }

    #[test]
    fn neighbouring_destinations_do_not_share_a_cookie() {
        // Every input bit has to survive the truncation, including the lowest bit of
        // the address and of the port.
        let secret = 0xdead_beef;
        let mut seen = std::collections::HashSet::new();
        let mut collisions = 0;
        for last in 0..=255u8 {
            for port in [1u16, 80, 443, 8080, 65535] {
                let ip = Ipv4Addr::new(198, 51, 100, last);
                if !seen.insert(cookie(ip, port, secret)) {
                    collisions += 1;
                }
                assert!(!matches(
                    sequence(ip, port, secret, Instant::now()),
                    ip,
                    port.wrapping_add(1),
                    secret
                ));
            }
        }
        // 1280 destinations over a 24-bit space; a handful of birthday collisions is
        // expected, a systematic loss of input bits is not.
        assert!(collisions < 4, "{collisions} cookie collisions");
    }

    #[test]
    fn round_trip_time_is_measured_from_the_encoded_tick() {
        let started = Instant::now();
        let sent = sequence(IP, 443, 7, started);
        assert!(elapsed_since_tick(started, sent) <= TIMESTAMP_TICK_MS * 2);
    }

    #[test]
    fn timestamp_wrap_never_panics_or_exceeds_its_span() {
        for offset in [0u64, 1, TIMESTAMP_SPAN_MS - 1, TIMESTAMP_SPAN_MS + 3] {
            let started = Instant::now();
            let sent = (cookie(IP, 1, 0) << TIMESTAMP_BITS) | tick(Duration::from_millis(offset));
            assert!(elapsed_since_tick(started, sent) < TIMESTAMP_SPAN_MS);
        }
    }

    #[test]
    fn rtt_is_only_reported_inside_one_wrap() {
        assert!(reports_rtt(Duration::from_millis(1000)));
        assert!(!reports_rtt(Duration::from_millis(TIMESTAMP_SPAN_MS + 1)));
    }
}
