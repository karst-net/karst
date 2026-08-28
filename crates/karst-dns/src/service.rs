// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Conversion between KarstDNS policy and DNS wire messages.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{Name, RData, Record as WireRecord, RecordType as WireRecordType};

use crate::{Record, RecordType, Resolution, Resolver, Response, ResponseKind};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed DNS request: {0}")]
    Request(String),
    #[error("could not encode DNS response: {0}")]
    Response(String),
    #[error(transparent)]
    Forward(#[from] crate::forward::Error),
}

/// A decoded client request either has a local response or must be sent only to
/// the named upstream set. A split failure is represented separately so callers
/// cannot accidentally fall back to global DNS.
#[derive(Debug)]
pub enum Decision {
    Respond(Message),
    Forward {
        resolvers: Vec<SocketAddr>,
        split: bool,
    },
}

/// Decode a wire query and apply KarstDNS policy without selecting a transport.
/// Userspace mode uses this to forward only through its overlay UDP stack.
pub fn decide_wire(resolver: &Resolver, request: &[u8]) -> Result<Decision, Error> {
    let request = crate::message::decode(request).map_err(Error::Request)?;
    Ok(decide(resolver, &request))
}

/// Whether a candidate upstream packet is a response to this DNS wire query.
#[must_use]
pub fn matching_response(request: &[u8], candidate: &[u8]) -> bool {
    let Ok(request) = crate::message::decode(request) else {
        return false;
    };
    let Ok(candidate) = crate::message::decode(candidate) else {
        return false;
    };
    candidate.metadata.id == request.metadata.id
        && candidate.metadata.message_type == MessageType::Response
}

/// Handle one complete DNS wire request. This is the common execution path for
/// UDP, TCP, and the userspace stack: mesh policy is decided before any socket
/// for an upstream is opened.
pub fn handle_wire(resolver: &Resolver, request: &[u8]) -> Result<Vec<u8>, Error> {
    let request = crate::message::decode(request).map_err(Error::Request)?;
    match decide(resolver, &request) {
        Decision::Respond(response) => response
            .to_vec()
            .map_err(|error| Error::Response(error.to_string())),
        Decision::Forward {
            resolvers,
            split: _,
        } => forward(resolver, &request, &resolvers),
    }
}

fn forward(
    resolver: &Resolver,
    request: &Message,
    resolvers: &[SocketAddr],
) -> Result<Vec<u8>, Error> {
    let Some(question) = request.queries.first() else {
        return response(request, ResponseCode::FormErr, false, None)
            .to_vec()
            .map_err(|error| Error::Response(error.to_string()));
    };
    let key = crate::cache::Key {
        name: question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase(),
        record_type: u16::from(question.query_type()),
    };
    if let Some(cached) = resolver.cache_get(&key) {
        if let Ok(mut cached) = crate::message::decode(&cached) {
            // IDs and the question section are per-client.  Rebuild both on a
            // cache hit so 0x20 randomisation remains effective.
            cached.metadata.id = request.metadata.id;
            cached.queries.clone_from(&request.queries);
            return cached
                .to_vec()
                .map_err(|error| Error::Response(error.to_string()));
        }
    }
    let wire = request
        .to_vec()
        .map_err(|error| Error::Response(error.to_string()))?;
    let response = match crate::forward::udp(&wire, resolvers) {
        Ok(response) => response,
        Err(error) => {
            resolver.record_failure(&key.name, &error);
            return Err(Error::Forward(error));
        }
    };
    if let Ok(message) = crate::message::decode(&response) {
        if matches!(
            message.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            if let Some(ttl) = cache_ttl(&message) {
                resolver.cache_insert(key, response.clone(), ttl);
            }
        }
    }
    Ok(response)
}

fn cache_ttl(message: &Message) -> Option<Duration> {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .map(|record| Duration::from_secs(u64::from(record.ttl)))
        .min()
        .filter(|ttl| !ttl.is_zero())
}

/// Produce the RFC-visible failure response for a parsed request. Socket
/// adapters use this for exhausted upstreams; dropping the packet would make a
/// split-DNS outage indistinguishable from a transport hang.
#[must_use]
pub fn servfail_wire(request: &[u8]) -> Option<Vec<u8>> {
    let request = crate::message::decode(request).ok()?;
    response(&request, ResponseCode::ServFail, false, None)
        .to_vec()
        .ok()
}

/// Apply resolver policy to one DNS request.
#[must_use]
pub fn decide(resolver: &Resolver, request: &Message) -> Decision {
    let Some(question) = request.queries.first() else {
        return Decision::Respond(response(request, ResponseCode::FormErr, false, None));
    };
    let record_type = match question.query_type() {
        WireRecordType::A => RecordType::A,
        WireRecordType::AAAA => RecordType::Aaaa,
        WireRecordType::PTR => RecordType::Ptr,
        _ => RecordType::Other,
    };
    match resolver.resolve(
        &question.name().to_ascii(),
        record_type,
        request.metadata.recursion_desired,
    ) {
        Ok(Resolution::Authoritative(answer)) => {
            Decision::Respond(authoritative_response(request, answer))
        }
        Ok(Resolution::Refused) => {
            Decision::Respond(response(request, ResponseCode::Refused, false, None))
        }
        Ok(Resolution::Forward {
            resolvers,
            split: _,
        }) if resolvers.is_empty() => {
            // With no pre-existing host upstream available, failure is explicit
            // rather than a silent recursive loop or a packet to nowhere.
            Decision::Respond(response(request, ResponseCode::ServFail, false, None))
        }
        Ok(Resolution::Forward { resolvers, split }) => Decision::Forward { resolvers, split },
        Err(_) => Decision::Respond(response(request, ResponseCode::FormErr, false, None)),
    }
}

fn response(
    request: &Message,
    code: ResponseCode,
    authoritative: bool,
    answer: Option<Response>,
) -> Message {
    let mut out = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    out.metadata.recursion_desired = request.metadata.recursion_desired;
    out.metadata.recursion_available = true;
    out.metadata.authoritative = authoritative;
    out.metadata.response_code = code;
    out.add_queries(request.queries.iter().cloned());
    if let Some(answer) = answer {
        let name = request
            .queries
            .first()
            .map_or_else(Name::root, |query| query.name().clone());
        for record in answer.records {
            match record {
                Record::A(address) => {
                    out.add_answer(WireRecord::from_rdata(
                        name.clone(),
                        answer.ttl,
                        RData::A(A(address)),
                    ));
                }
                Record::Aaaa(address) => {
                    out.add_answer(WireRecord::from_rdata(
                        name.clone(),
                        answer.ttl,
                        RData::AAAA(AAAA(address)),
                    ));
                }
                Record::Ptr(target) => {
                    if let Ok(target) = Name::from_ascii(target) {
                        out.add_answer(WireRecord::from_rdata(
                            name.clone(),
                            answer.ttl,
                            RData::PTR(PTR(target)),
                        ));
                    }
                }
            }
        }
    }
    out
}

fn authoritative_response(request: &Message, answer: Response) -> Message {
    let code = match answer.kind {
        ResponseKind::NxDomain => ResponseCode::NXDomain,
        ResponseKind::Answer | ResponseKind::NoData => ResponseCode::NoError,
    };
    response(request, code, true, Some(answer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, MeshPeer};
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::RData;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn request(name: &str, kind: WireRecordType) -> Message {
        let mut request = Message::new(9, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(Name::from_ascii(name).expect("name"), kind));
        request
    }

    #[test]
    fn unknown_mesh_name_never_becomes_a_forward() {
        let config = Config::new(
            vec!["192.0.2.53:53".parse().expect("upstream")],
            vec![],
            vec![],
            "aquifer.karst",
            true,
        )
        .expect("config");
        let resolver = Resolver::new(
            config,
            [MeshPeer::new("alpha", [Ipv4Addr::new(100, 64, 0, 2)], [])],
        );
        let Decision::Respond(response) = decide(
            &resolver,
            &request("missing.aquifer.karst.", WireRecordType::A),
        ) else {
            panic!("mesh name was forwarded");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.metadata.authoritative);
    }

    #[test]
    fn split_route_cannot_fall_back_to_global() {
        let config = Config::new(
            vec!["192.0.2.53:53".parse().expect("upstream")],
            vec![],
            vec![crate::Route {
                match_domain: "internal.example".to_owned(),
                resolvers: vec!["100.64.0.53:53".parse().expect("route")],
            }],
            "aquifer.karst",
            true,
        )
        .expect("config");
        let resolver = Resolver::new(config, []);
        let Decision::Forward { resolvers, split } = decide(
            &resolver,
            &request("db.internal.example.", WireRecordType::A),
        ) else {
            panic!("split query was not forwarded");
        };
        assert!(split);
        assert_eq!(resolvers, vec!["100.64.0.53:53".parse().expect("route")]);
    }

    #[test]
    fn mesh_wire_request_does_not_contact_a_hostile_upstream() {
        use std::net::UdpSocket;
        let hostile = UdpSocket::bind("127.0.0.1:0").expect("hostile upstream");
        hostile
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .expect("timeout");
        let config = Config::new(
            vec![hostile.local_addr().expect("address")],
            vec![],
            vec![],
            "aquifer.karst",
            true,
        )
        .expect("config");
        let resolver = Resolver::new(config, []);
        let wire = request("secret.aquifer.karst.", WireRecordType::A)
            .to_vec()
            .expect("wire");
        let response = handle_wire(&resolver, &wire).expect("response");
        assert_eq!(
            crate::message::decode(&response)
                .expect("decode")
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
        let mut buffer = [0u8; 512];
        assert!(
            hostile.recv_from(&mut buffer).is_err(),
            "mesh query leaked upstream"
        );
    }

    #[test]
    fn forwarded_answers_are_cached_without_reusing_client_metadata() {
        use std::net::UdpSocket;

        let upstream = UdpSocket::bind("127.0.0.1:0").expect("upstream");
        let address = upstream.local_addr().expect("address");
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&requests);
        let worker = thread::spawn(move || {
            let mut input = [0u8; 512];
            let (length, client) = upstream.recv_from(&mut input).expect("query");
            seen.fetch_add(1, Ordering::Relaxed);
            let request = crate::message::decode(&input[..length]).expect("decode request");
            let mut response = response(&request, ResponseCode::NoError, false, None);
            response.add_answer(WireRecord::from_rdata(
                request.queries.first().expect("question").name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
            ));
            upstream
                .send_to(&response.to_vec().expect("wire response"), client)
                .expect("respond");
        });
        let resolver = Resolver::new(
            Config::new(vec![address], vec![], vec![], "aquifer.karst", true).expect("config"),
            [],
        );
        let first = request("www.example.test.", WireRecordType::A);
        let first_wire = first.to_vec().expect("first wire");
        let first_response = handle_wire(&resolver, &first_wire).expect("first response");
        assert_eq!(
            crate::message::decode(&first_response)
                .expect("decode first")
                .metadata
                .id,
            first.metadata.id
        );
        worker.join().expect("upstream worker");

        let mut second = request("WWW.EXAMPLE.TEST.", WireRecordType::A);
        second.metadata.id = 47;
        let second_response = handle_wire(&resolver, &second.to_vec().expect("second wire"))
            .expect("cached response");
        let decoded = crate::message::decode(&second_response).expect("decode cached");
        assert_eq!(decoded.metadata.id, 47);
        assert_eq!(
            decoded.queries.first().expect("question").name().to_ascii(),
            "WWW.EXAMPLE.TEST."
        );
        assert_eq!(
            requests.load(Ordering::Relaxed),
            1,
            "cache contacted upstream"
        );
        assert_eq!(resolver.cache_stats().hits, 1);
    }

    #[test]
    fn retains_only_the_five_most_recent_upstream_failures() {
        let resolver = Resolver::new(
            Config::new(
                vec!["127.0.0.1:9".parse().expect("unavailable upstream")],
                vec![],
                vec![],
                "aquifer.karst",
                true,
            )
            .expect("config"),
            [],
        );
        for number in 0..6 {
            let name = format!("{number}.example.test.");
            let _ = handle_wire(
                &resolver,
                &request(&name, WireRecordType::A).to_vec().expect("wire"),
            );
        }
        let failures = resolver.recent_failures();
        assert_eq!(failures.len(), 5);
        assert!(failures
            .first()
            .expect("first failure")
            .starts_with("1.example.test:"));
        assert!(failures
            .last()
            .expect("last failure")
            .starts_with("5.example.test:"));
    }
}
