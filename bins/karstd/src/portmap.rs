// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Explicit NAT port mapping on the daemon side.
//!
//! `karst-portmap` is deliberately sans-io: it encodes and decodes PCP and
//! NAT-PMP, and it tells the caller when a granted mapping should be renewed.
//! This module owns the rest of the problem in `karstd`: finding the gateway,
//! binding a socket on the correct local address, retrying transient failures,
//! and feeding a live mapping into discovery.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use karst_portmap::{natpmp, pcp, Error, Mapping, Protocol, ResultCode, Transport, SERVER_PORT};

use crate::disco::Disco;
use crate::run::Shutdown;

const RETRY_DELAY: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

/// The longest this backs off to — RFC 6887 §8.1.1's `MRT`, 1024 seconds.
///
/// Taken from PCP's own retransmission schedule rather than chosen, because the
/// question it answers is the same one: how often to keep asking a gateway that
/// is not helping. The RFC pairs `MRT` with `MRC = 0` and `MRD = 0` —
/// **retry forever, never give up** — which is the half already implemented
/// here and the half that made this a defect on its own.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1024);

/// How long to wait before asking a gateway that just refused.
///
/// **The classification was never wrong; the schedule was** (FINDINGS.md 38).
/// RFC 6887 §7.4 makes `NO_RESOURCES` transient and `ResultCode::is_transient`
/// agrees deliberately: a node that gave up on it would never recover when a
/// gateway's table drained. But a flat five seconds turns "transient" into
/// 17,280 requests a day that cannot succeed — and the node this hurts most is
/// not the exotic one behind a carrier-grade NAT. It is **any node whose
/// network has no port-mapping service at all**, which is most of them.
///
/// Doubling from [`RETRY_DELAY`] to [`MAX_RETRY_DELAY`] costs a gateway that
/// recovers at most seventeen minutes of delay, against a daily request count
/// that falls from 17,280 to about 90.
#[derive(Debug)]
struct Backoff {
    delay: Duration,
}

impl Backoff {
    const fn new() -> Self {
        Self { delay: RETRY_DELAY }
    }

    /// Progress of any kind starts the schedule over.
    ///
    /// Including progress that is not yet a mapping — a PCP gateway that
    /// answers "use NAT-PMP" is a gateway that answered. Backing off through
    /// the fallback would make the second protocol look slow to establish when
    /// nothing had failed.
    fn reset(&mut self) {
        self.delay = RETRY_DELAY;
    }

    /// The wait before the next attempt, then double it.
    ///
    /// `jitter` is a byte of randomness spread across RFC 6887 §8.1.1's `RAND`
    /// range of ±0.1. **Not decoration:** every node behind one carrier-grade
    /// NAT starts its daemon when the link comes up, so an undithered schedule
    /// has them all asking the same gateway at the same instants, and the
    /// doubling makes the collisions rarer but larger.
    fn next(&mut self, jitter: u8) -> Duration {
        let base = self.delay;
        self.delay = self.delay.saturating_mul(2).min(MAX_RETRY_DELAY);

        // ±10% of the base, from a byte: 0 → -10%, 255 → +10%.
        let span = base.as_millis() / 5; // 20% of base
        let offset = span * u128::from(jitter) / 255;
        let millis = (base.as_millis() + offset).saturating_sub(span / 2);
        Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }

    /// What the current wait is, for the status line.
    const fn current(&self) -> Duration {
        self.delay
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub enabled: bool,
    pub gateway: Option<SocketAddr>,
    pub protocol: Option<Protocol>,
    pub internal: Option<SocketAddr>,
    pub external: Option<SocketAddr>,
    pub next_renew: Option<Instant>,
    pub state: &'static str,
    pub reason: Option<String>,
    /// The current wait between attempts, while retrying.
    ///
    /// Published so a stretching schedule is visible. A status line identical
    /// every five seconds for an hour is what let finding 38 read as normal
    /// operation for as long as it did.
    pub retry_in: Option<Duration>,
}

impl Snapshot {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            gateway: None,
            protocol: None,
            internal: None,
            external: None,
            next_renew: None,
            state: if enabled { "starting" } else { "disabled" },
            reason: (!enabled).then_some("disabled by config".to_owned()),
            retry_in: None,
        }
    }

    #[must_use]
    pub fn renews_in_seconds(&self) -> Option<u64> {
        let at = self.next_renew?;
        let now = Instant::now();
        if at <= now {
            return Some(0);
        }
        Some(at.duration_since(now).as_secs())
    }
}

#[derive(Debug)]
pub struct Shared {
    snapshot: Mutex<Snapshot>,
}

impl Shared {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            snapshot: Mutex::new(Snapshot::new(enabled)),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn update(&self, f: impl FnOnce(&mut Snapshot)) {
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut snapshot);
    }
}

enum Mode {
    Pcp {
        last_epoch: Option<(u32, Instant)>,
    },
    NatPmp {
        last_epoch: Option<u32>,
        public_address: Option<IpAddr>,
        next: NatPmpRequest,
    },
}

#[derive(Clone, Copy)]
enum NatPmpRequest {
    PublicAddress,
    Map,
}

/// Keep a port mapping alive until shutdown, or until the gateway answers that
/// the request can never succeed.
#[allow(clippy::too_many_lines)]
pub fn run(
    shared: &Shared,
    disco: &Mutex<Disco>,
    shutdown: &Shutdown,
    listen: SocketAddr,
    internal_port: u16,
) {
    if !shared.snapshot().enabled {
        return;
    }

    let Some(gateway_ip) = default_gateway(shared, disco) else {
        return;
    };
    let gateway = SocketAddr::new(gateway_ip, SERVER_PORT);

    let client_ip = match client_ip(listen, gateway) {
        Ok(ip) => ip,
        Err(reason) => {
            shared.update(|snapshot| {
                snapshot.gateway = Some(gateway);
                snapshot.state = "failed";
                snapshot.reason = Some(reason);
            });
            return;
        }
    };
    let bind = SocketAddr::new(client_ip, 0);
    let Ok(sock) = UdpSocket::bind(bind) else {
        shared.update(|snapshot| {
            snapshot.gateway = Some(gateway);
            snapshot.internal = Some(SocketAddr::new(client_ip, internal_port));
            snapshot.state = "failed";
            snapshot.reason = Some(format!("cannot bind a port-mapping socket on {bind}"));
        });
        return;
    };
    let _ = sock.set_read_timeout(Some(RESPONSE_TIMEOUT));

    shared.update(|snapshot| {
        snapshot.gateway = Some(gateway);
        snapshot.internal = Some(SocketAddr::new(client_ip, internal_port));
        snapshot.state = "starting";
        snapshot.reason = None;
    });

    let mut mode = Mode::Pcp { last_epoch: None };
    let mut external_hint = 0u16;
    let mut next_attempt = Instant::now();
    let mut backoff = Backoff::new();

    while !shutdown.requested() {
        if let Some(wait) = next_attempt.checked_duration_since(Instant::now()) {
            if !wait.is_zero() {
                std::thread::sleep(wait.min(Duration::from_millis(250)));
                continue;
            }
        }

        let outcome = match &mut mode {
            Mode::Pcp { last_epoch } => request_pcp(
                &sock,
                gateway,
                client_ip,
                internal_port,
                external_hint,
                last_epoch,
            ),
            Mode::NatPmp {
                last_epoch,
                public_address,
                next,
            } => request_natpmp(
                &sock,
                gateway,
                internal_port,
                external_hint,
                last_epoch,
                public_address,
                next,
            ),
        };

        match outcome {
            Ok(Outcome::Mapped { mapping, protocol }) => {
                let Some(external_addr) = mapping.external_address else {
                    continue;
                };
                if natpmp::is_unusable_external(external_addr) {
                    clear_mapping(
                        shared,
                        disco,
                        "gateway reported an unusable external address",
                    );
                    return;
                }
                let external = SocketAddr::new(external_addr, mapping.external_port);
                external_hint = mapping.external_port;
                let next_renew = mapping.renew_after().map(|d| Instant::now() + d);
                shared.update(|snapshot| {
                    snapshot.protocol = Some(protocol);
                    snapshot.external = Some(external);
                    snapshot.next_renew = next_renew;
                    snapshot.state = "mapped";
                    snapshot.reason = None;
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(Some(external));
                backoff.reset();
                next_attempt = next_renew.unwrap_or_else(|| Instant::now() + RETRY_DELAY);
            }
            Ok(Outcome::NeedNatPmp) => {
                mode = Mode::NatPmp {
                    last_epoch: None,
                    public_address: None,
                    next: NatPmpRequest::PublicAddress,
                };
                shared.update(|snapshot| {
                    snapshot.protocol = Some(Protocol::NatPmp);
                    snapshot.external = None;
                    snapshot.next_renew = None;
                    snapshot.state = "retrying";
                    snapshot.reason =
                        Some("PCP is unsupported here; falling back to NAT-PMP".to_owned());
                    snapshot.retry_in = None;
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(None);
                backoff.reset();
                next_attempt = Instant::now();
            }
            Ok(Outcome::Continue) => {
                backoff.reset();
                next_attempt = Instant::now();
            }
            Ok(Outcome::Retry { protocol, reason }) => {
                let wait = backoff.next(crate::random_seed()[0]);
                let current = backoff.current();
                shared.update(|snapshot| {
                    snapshot.protocol = Some(protocol);
                    snapshot.external = None;
                    snapshot.next_renew = None;
                    snapshot.state = "retrying";
                    snapshot.reason = Some(reason);
                    // Published so an operator can see the schedule stretching.
                    // A status line that reads identically every five seconds
                    // for an hour is what made finding 38 look like normal
                    // operation.
                    snapshot.retry_in = Some(current);
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(None);
                next_attempt = Instant::now() + wait;
            }
            Ok(Outcome::RestartNatPmp) => {
                mode = Mode::NatPmp {
                    last_epoch: None,
                    public_address: None,
                    next: NatPmpRequest::PublicAddress,
                };
                shared.update(|snapshot| {
                    snapshot.protocol = Some(Protocol::NatPmp);
                    snapshot.external = None;
                    snapshot.next_renew = None;
                    snapshot.state = "retrying";
                    snapshot.reason =
                        Some("the gateway restarted and lost the mapping; retrying".to_owned());
                    snapshot.retry_in = None;
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(None);
                backoff.reset();
                next_attempt = Instant::now();
            }
            Err(Fatal { protocol, reason }) => {
                shared.update(|snapshot| {
                    snapshot.protocol = Some(protocol);
                    snapshot.external = None;
                    snapshot.next_renew = None;
                    snapshot.state = "failed";
                    snapshot.reason = Some(reason);
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(None);
                return;
            }
        }
    }
}

enum Outcome {
    Mapped {
        mapping: Mapping,
        protocol: Protocol,
    },
    NeedNatPmp,
    Continue,
    Retry {
        protocol: Protocol,
        reason: String,
    },
    RestartNatPmp,
}

struct Fatal {
    protocol: Protocol,
    reason: String,
}

#[allow(clippy::match_same_arms)]
fn request_pcp(
    sock: &UdpSocket,
    gateway: SocketAddr,
    client_ip: IpAddr,
    internal_port: u16,
    external_hint: u16,
    last_epoch: &mut Option<(u32, Instant)>,
) -> Result<Outcome, Fatal> {
    let nonce = {
        let seed = crate::random_seed();
        let mut nonce = [0u8; pcp::NONCE_LEN];
        nonce.copy_from_slice(&seed[..pcp::NONCE_LEN]);
        pcp::Nonce(nonce)
    };
    let req = pcp::encode_map(
        nonce,
        Transport::Udp,
        internal_port,
        external_hint,
        client_ip,
        pcp::DEFAULT_LIFETIME,
    );
    match transact(sock, gateway, &req, |reply| {
        match pcp::decode_map(reply, nonce) {
            Ok(mapping) => {
                if let Some(epoch) = pcp::epoch(reply) {
                    let now = Instant::now();
                    if let Some((previous, seen_at)) = *last_epoch {
                        let _ = pcp::gateway_lost_state(previous, epoch, seen_at.elapsed());
                    }
                    *last_epoch = Some((epoch, now));
                }
                Ok(Some(Outcome::Mapped {
                    mapping,
                    protocol: Protocol::Pcp,
                }))
            }
            Err(Error::BadVersion(_) | Error::Refused(ResultCode::Pcp(1))) => {
                Ok(Some(Outcome::NeedNatPmp))
            }
            Err(Error::Refused(code)) if code.is_transient() => Ok(Some(Outcome::Retry {
                protocol: Protocol::Pcp,
                reason: format!("PCP failed transiently ({code}); retrying"),
            })),
            Err(Error::Refused(code)) => Err(Fatal {
                protocol: Protocol::Pcp,
                reason: format!("PCP refused the mapping permanently ({code})"),
            }),
            Err(
                Error::TooShort { .. }
                | Error::TooLong(_)
                | Error::NotAResponse(_)
                | Error::OpcodeMismatch { .. }
                | Error::Malformed
                | Error::NonceMismatch,
            ) => Ok(None),
            Err(_) => Ok(None),
        }
    })? {
        Some(outcome) => Ok(outcome),
        None => Ok(Outcome::Retry {
            protocol: Protocol::Pcp,
            reason: "the gateway did not answer PCP".to_owned(),
        }),
    }
}

#[allow(clippy::match_same_arms, clippy::too_many_lines)]
fn request_natpmp(
    sock: &UdpSocket,
    gateway: SocketAddr,
    internal_port: u16,
    external_hint: u16,
    last_epoch: &mut Option<u32>,
    public_address: &mut Option<IpAddr>,
    next: &mut NatPmpRequest,
) -> Result<Outcome, Fatal> {
    match next {
        NatPmpRequest::PublicAddress => {
            let req = natpmp::encode_public_address();
            match transact(sock, gateway, &req, |reply| {
                if let Some(epoch) = natpmp::epoch(reply) {
                    if let Some(previous) = *last_epoch {
                        let _ = natpmp::gateway_restarted(previous, epoch);
                    }
                }
                match natpmp::decode(reply, natpmp::OP_PUBLIC_ADDRESS) {
                    Ok(natpmp::Response::PublicAddress { address, epoch }) => {
                        if natpmp::is_unusable_external(IpAddr::V4(address)) {
                            return Err(Fatal {
                                protocol: Protocol::NatPmp,
                                reason: format!(
                                    "the gateway reports an unusable external address ({address})"
                                ),
                            });
                        }
                        *last_epoch = Some(epoch);
                        *public_address = Some(IpAddr::V4(address));
                        *next = NatPmpRequest::Map;
                        Ok(Some(Outcome::Continue))
                    }
                    Ok(natpmp::Response::Mapped(_))
                    | Err(
                        Error::TooShort { .. }
                        | Error::TooLong(_)
                        | Error::BadVersion(_)
                        | Error::NotAResponse(_)
                        | Error::OpcodeMismatch { .. }
                        | Error::Malformed
                        | Error::NonceMismatch,
                    ) => Ok(None),
                    Err(Error::Refused(code)) if code.is_transient() => Ok(Some(Outcome::Retry {
                        protocol: Protocol::NatPmp,
                        reason: format!(
                            "NAT-PMP address lookup failed transiently ({code}); retrying"
                        ),
                    })),
                    Err(Error::Refused(code)) => Err(Fatal {
                        protocol: Protocol::NatPmp,
                        reason: format!("NAT-PMP address lookup was refused permanently ({code})"),
                    }),
                    Err(_) => Ok(None),
                }
            })? {
                Some(outcome) => Ok(outcome),
                None => Ok(Outcome::Retry {
                    protocol: Protocol::NatPmp,
                    reason: "the gateway did not answer NAT-PMP address lookup".to_owned(),
                }),
            }
        }
        NatPmpRequest::Map => {
            let req = natpmp::encode_map(
                Transport::Udp,
                internal_port,
                external_hint,
                natpmp::DEFAULT_LIFETIME,
            );
            match transact(sock, gateway, &req, |reply| {
                if let Some(epoch) = natpmp::epoch(reply) {
                    if let Some(previous) = *last_epoch {
                        if natpmp::gateway_restarted(previous, epoch) {
                            *last_epoch = Some(epoch);
                            *public_address = None;
                            *next = NatPmpRequest::PublicAddress;
                            return Ok(Some(Outcome::RestartNatPmp));
                        }
                    }
                    *last_epoch = Some(epoch);
                }
                match natpmp::decode(reply, natpmp::OP_MAP_UDP) {
                    Ok(natpmp::Response::Mapped(mut mapping)) => {
                        mapping.external_address = *public_address;
                        Ok(Some(Outcome::Mapped {
                            mapping,
                            protocol: Protocol::NatPmp,
                        }))
                    }
                    Ok(natpmp::Response::PublicAddress { .. })
                    | Err(
                        Error::TooShort { .. }
                        | Error::TooLong(_)
                        | Error::BadVersion(_)
                        | Error::NotAResponse(_)
                        | Error::OpcodeMismatch { .. }
                        | Error::Malformed
                        | Error::NonceMismatch,
                    ) => Ok(None),
                    Err(Error::Refused(code)) if code.is_transient() => Ok(Some(Outcome::Retry {
                        protocol: Protocol::NatPmp,
                        reason: format!("NAT-PMP mapping failed transiently ({code}); retrying"),
                    })),
                    Err(Error::Refused(code)) => Err(Fatal {
                        protocol: Protocol::NatPmp,
                        reason: format!("NAT-PMP refused the mapping permanently ({code})"),
                    }),
                    Err(_) => Ok(None),
                }
            })? {
                Some(outcome) => Ok(outcome),
                None => Ok(Outcome::Retry {
                    protocol: Protocol::NatPmp,
                    reason: "the gateway did not answer the NAT-PMP mapping request".to_owned(),
                }),
            }
        }
    }
}

fn transact(
    sock: &UdpSocket,
    gateway: SocketAddr,
    request: &[u8],
    mut parse: impl FnMut(&[u8]) -> Result<Option<Outcome>, Fatal>,
) -> Result<Option<Outcome>, Fatal> {
    sock.send_to(request, gateway).map_err(|e| Fatal {
        protocol: Protocol::Pcp,
        reason: format!("cannot send to the port-mapping gateway ({e})"),
    })?;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    let mut buf = [0u8; 1500];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if from.ip() != gateway.ip() {
                    continue;
                }
                if let Some(outcome) = parse(buf.get(..n).unwrap_or_default())? {
                    return Ok(Some(outcome));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => {
                return Err(Fatal {
                    protocol: Protocol::Pcp,
                    reason: format!("error reading from the port-mapping gateway ({e})"),
                });
            }
        }
    }
    Ok(None)
}

fn default_gateway(shared: &Shared, disco: &Mutex<Disco>) -> Option<IpAddr> {
    match karst_tun::default_gateway() {
        Ok(Some(gateway)) => Some(gateway),
        Ok(None) => {
            clear_mapping(shared, disco, "this host has no default gateway");
            None
        }
        Err(e) => {
            clear_mapping(
                shared,
                disco,
                &format!("cannot discover the default gateway ({e})"),
            );
            None
        }
    }
}

fn client_ip(listen: SocketAddr, gateway: SocketAddr) -> Result<IpAddr, String> {
    let configured = listen.ip();
    if !configured.is_unspecified() {
        if configured.is_ipv4() != gateway.is_ipv4() {
            return Err(format!(
                "listen address {configured} is not on the same family as the gateway {gateway}"
            ));
        }
        return Ok(configured);
    }

    let wildcard = match gateway.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = UdpSocket::bind(wildcard)
        .map_err(|e| format!("cannot probe the gateway route from {wildcard} ({e})"))?;
    sock.connect(gateway).map_err(|e| {
        format!("cannot resolve the socket address toward the gateway {gateway} ({e})")
    })?;
    sock.local_addr()
        .map(|addr| addr.ip())
        .map_err(|e| format!("cannot read the socket address toward the gateway {gateway} ({e})"))
}

fn clear_mapping(shared: &Shared, disco: &Mutex<Disco>, reason: &str) {
    shared.update(|snapshot| {
        snapshot.external = None;
        snapshot.next_renew = None;
        snapshot.state = "failed";
        snapshot.reason = Some(reason.to_owned());
    });
    disco
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_explicit_mapping(None);
}

#[cfg(test)]
mod backoff_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::{Backoff, MAX_RETRY_DELAY, RETRY_DELAY};

    /// Jitter that lands exactly on the base, so the schedule is readable.
    const MID: u8 = 128;

    #[test]
    fn the_first_wait_is_the_old_flat_delay() {
        // The fix must not make the *first* retry slower. A gateway that is
        // briefly busy — the case `is_transient` exists for — should still be
        // asked again promptly; it is repetition that was wrong, not the
        // initial delay.
        let mut b = Backoff::new();
        let first = b.next(MID);
        assert!(
            first.abs_diff(RETRY_DELAY) <= RETRY_DELAY / 5,
            "first wait {first:?} is not about {RETRY_DELAY:?}"
        );
    }

    #[test]
    fn waiting_doubles_and_stops_doubling() {
        let mut b = Backoff::new();
        let mut seen = Vec::new();
        for _ in 0..20 {
            seen.push(b.next(MID).as_secs());
        }
        // Doubling from 5s, and then pinned: 5, 10, 20, ... 640, 1024, 1024...
        assert_eq!(&seen[..5], &[5, 10, 20, 40, 80], "not a doubling schedule");
        assert_eq!(
            *seen.last().expect("samples"),
            MAX_RETRY_DELAY.as_secs(),
            "the schedule grew past RFC 6887 §8.1.1's MRT"
        );

        // **Never gives up.** RFC 6887 pairs MRT with MRC = 0 and MRD = 0, and
        // a node that stopped asking would never recover when a gateway's
        // table drained — which is the reason `NO_RESOURCES` is transient.
        assert!(seen.iter().all(|s| *s > 0), "the schedule stopped retrying");
    }

    #[test]
    fn a_day_of_refusals_costs_about_ninety_requests() {
        // The finding's number, checked rather than asserted in prose: a flat
        // five seconds is 17,280 requests a day.
        let mut b = Backoff::new();
        let mut elapsed = 0u64;
        let mut requests = 0u64;
        while elapsed < 86_400 {
            elapsed += b.next(MID).as_secs();
            requests += 1;
        }
        assert!(
            (80..=100).contains(&requests),
            "a day of refusals costs {requests} requests, not about 90"
        );
    }

    #[test]
    fn progress_starts_the_schedule_over() {
        // A gateway that recovers must not inherit the wait accumulated while
        // it was refusing — otherwise the first success after a long outage is
        // followed by a seventeen-minute gap before the next renewal attempt.
        let mut b = Backoff::new();
        for _ in 0..8 {
            b.next(MID);
        }
        assert!(b.current() > RETRY_DELAY);
        b.reset();
        assert_eq!(b.current(), RETRY_DELAY, "reset did not clear the schedule");
    }

    #[test]
    fn jitter_stays_inside_rfc_6887s_range() {
        // ±10% of the base. Wider would let one node's schedule drift into
        // another's; absent would have every node behind one carrier-grade NAT
        // asking at the same instants, since they all start when the link does.
        for jitter in [0u8, 1, 64, 128, 200, 255] {
            let mut b = Backoff::new();
            for _ in 0..4 {
                b.next(MID);
            }
            let base = b.current();
            let got = b.next(jitter);
            let tenth = base / 10;
            assert!(
                got >= base - tenth && got <= base + tenth,
                "jitter {jitter} put the wait at {got:?}, outside {base:?} ±10%"
            );
        }
    }

    #[test]
    fn the_extremes_of_the_jitter_byte_actually_differ() {
        // Guards against a jitter that computes to zero and looks correct
        // because every assertion above is a range.
        let mut low = Backoff::new();
        let mut high = Backoff::new();
        for _ in 0..4 {
            low.next(MID);
            high.next(MID);
        }
        assert_ne!(
            low.next(0),
            high.next(255),
            "the jitter byte has no effect; every node retries in lockstep"
        );
    }
}
