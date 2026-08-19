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
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(None);
                next_attempt = Instant::now();
            }
            Ok(Outcome::Continue) => {
                next_attempt = Instant::now();
            }
            Ok(Outcome::Retry { protocol, reason }) => {
                shared.update(|snapshot| {
                    snapshot.protocol = Some(protocol);
                    snapshot.external = None;
                    snapshot.next_renew = None;
                    snapshot.state = "retrying";
                    snapshot.reason = Some(reason);
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(None);
                next_attempt = Instant::now() + RETRY_DELAY;
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
                });
                disco
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .set_explicit_mapping(None);
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
