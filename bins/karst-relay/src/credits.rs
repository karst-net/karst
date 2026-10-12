// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Asynchronous account-wide relay credit acquisition and the packet-path
//! reservation gate. HTTP and signatures stay on worker tasks; the hub only
//! subtracts from a local allowance before queueing a destination write.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

use crate::hub::CreditGate;
use crate::roster::UsageMapping;
use crate::sign::{credit_request_signing_input, Identity, CREDIT_REQUEST_PATH};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_DELAY: Duration = Duration::from_secs(2);
const REFRESH_BEFORE: Duration = Duration::from_secs(5);
const MAX_RESPONSE_HEADERS: usize = 16 * 1024;
const MAX_RESPONSE_BODY: usize = 8 * 1024;
const MAX_OUTSTANDING_MAPPINGS: usize = 4096;
const UNCAPPED_LEASE_MILLIS: u64 = 15_000;
type MappingKey = (String, String);

#[derive(Debug)]
enum Allowance {
    Uncapped { valid_until: Instant },
    Capped { grants: VecDeque<CreditGrant> },
}

#[derive(Debug)]
struct CreditGrant {
    remaining: u64,
    valid_until: Instant,
}

/// Thread-safe local check used by the synchronous forwarding core.
#[derive(Debug)]
pub struct Controller {
    relay_id: String,
    generation: String,
    requested_bytes: u64,
    states: Mutex<HashMap<MappingKey, Allowance>>,
    pending: Mutex<HashSet<MappingKey>>,
    requests: mpsc::Sender<UsageMapping>,
}

impl Controller {
    fn enqueue(&self, mapping: &UsageMapping) {
        let mapping_key = key(mapping);
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.contains(&mapping_key) || pending.len() >= MAX_OUTSTANDING_MAPPINGS {
            return;
        }
        pending.insert(mapping_key.clone());
        if self.requests.try_send(mapping.clone()).is_err() {
            pending.remove(&mapping_key);
        }
    }

    fn finish_request(&self, mapping: &UsageMapping) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key(mapping));
    }

    fn install_uncapped(&self, mapping: &UsageMapping, valid_until: Instant) {
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key(mapping), Allowance::Uncapped { valid_until });
        self.finish_request(mapping);
    }

    fn install_grant(&self, mapping: &UsageMapping, valid_until: Instant, bytes: u64) {
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut grants = match states.remove(&key(mapping)) {
            Some(Allowance::Capped { grants }) => grants,
            _ => VecDeque::new(),
        };
        if valid_until > Instant::now() {
            grants.push_back(CreditGrant {
                remaining: bytes,
                valid_until,
            });
        }
        states.insert(key(mapping), Allowance::Capped { grants });
        drop(states);
        self.finish_request(mapping);
    }
}

impl CreditGate for Controller {
    fn reserve(&self, mapping: &UsageMapping, bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        let now = Instant::now();
        let mapping_key = key(mapping);
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut refresh = false;
        let admitted = match states.get_mut(&mapping_key) {
            Some(Allowance::Uncapped { valid_until }) if *valid_until > now => {
                refresh = valid_until.saturating_duration_since(now) <= REFRESH_BEFORE;
                true
            }
            Some(Allowance::Capped { grants }) => {
                grants.retain(|grant| grant.valid_until > now && grant.remaining > 0);
                let admitted = grants
                    .iter_mut()
                    .find(|grant| grant.remaining >= bytes)
                    .is_some_and(|grant| {
                        grant.remaining -= bytes;
                        true
                    });
                let available = grants
                    .iter()
                    .map(|grant| grant.remaining)
                    .fold(0_u64, u64::saturating_add);
                refresh = available <= self.requested_bytes / 4;
                admitted
            }
            _ => {
                states.remove(&mapping_key);
                false
            }
        };
        drop(states);
        if refresh || !admitted {
            self.enqueue(mapping);
        }
        admitted
    }
}

/// Background credit worker; the controller itself stays on the packet path.
#[derive(Debug)]
pub struct Runtime {
    controller: Arc<Controller>,
    cancel: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Runtime {
    /// Start opt-in credit acquisition for managed mappings.
    /// # Errors
    /// Returns invalid configuration, entropy, or TLS-root errors before the
    /// relay starts accepting traffic.
    pub fn start(origin: &str, identity: Arc<Identity>, requested_bytes: u64) -> io::Result<Self> {
        if requested_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cap grant size must be positive",
            ));
        }
        let (host, port) = crate::config::parse_https_origin(origin)
            .map(|(host, port)| (host.to_owned(), port))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid HTTPS control-plane origin",
                )
            })?;
        let tls = crate::tls::webpki_client_config()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut generation = [0_u8; 16];
        getrandom::fill(&mut generation)
            .map_err(|error| io::Error::other(format!("no entropy for cap generation: {error}")))?;
        let generation = hex_lower(&generation);
        let relay_id = Base64UrlUnpadded::encode_string(&identity.relay_id());
        let (requests, receiver) = mpsc::channel(1024);
        let controller = Arc::new(Controller {
            relay_id,
            generation,
            requested_bytes,
            states: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
            requests,
        });
        let (cancel, cancel_rx) = watch::channel(false);
        let task = tokio::spawn(run(
            host,
            port,
            tls,
            identity,
            Arc::clone(&controller),
            receiver,
            cancel_rx,
        ));
        Ok(Self {
            controller,
            cancel,
            task: Some(task),
        })
    }

    #[must_use]
    pub fn controller(&self) -> Arc<Controller> {
        Arc::clone(&self.controller)
    }

    /// Stop the worker after the caller has detached the gate from the hub.
    /// # Errors
    /// Returns a panic from the worker task.
    pub async fn finish(mut self) -> Result<(), tokio::task::JoinError> {
        let _ = self.cancel.send(true);
        if let Some(task) = self.task.take() {
            task.await
        } else {
            Ok(())
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
    }
}

async fn run(
    host: String,
    port: u16,
    tls: Arc<rustls::ClientConfig>,
    identity: Arc<Identity>,
    controller: Arc<Controller>,
    mut requests: mpsc::Receiver<UsageMapping>,
    mut cancel: watch::Receiver<bool>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        tokio::select! {
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() { return; }
            }
            mapping = requests.recv() => {
                let Some(mapping) = mapping else { return };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    controller.finish_request(&mapping);
                    continue;
                };
                let task_host = host.clone();
                let task_tls = Arc::clone(&tls);
                let task_identity = Arc::clone(&identity);
                let task_controller = Arc::clone(&controller);
                let task_cancel = cancel.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    request_until_ready(&task_host, port, &task_tls, &task_identity,
                        &task_controller, &mapping, task_cancel).await;
                });
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn request_until_ready(
    host: &str,
    port: u16,
    tls: &Arc<rustls::ClientConfig>,
    identity: &Identity,
    controller: &Controller,
    mapping: &UsageMapping,
    mut cancel: watch::Receiver<bool>,
) {
    let mut request_id = [0_u8; 16];
    if getrandom::fill(&mut request_id).is_err() {
        controller.finish_request(mapping);
        return;
    }
    let request_id = hex_lower(&request_id);
    let body = match signed_request(identity, controller, mapping, &request_id) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("karst-relay: cap credit request: {error}");
            controller.finish_request(mapping);
            return;
        }
    };
    loop {
        if *cancel.borrow() {
            controller.finish_request(mapping);
            return;
        }
        let started = Instant::now();
        let result =
            tokio::time::timeout(REQUEST_TIMEOUT, post_credit(host, port, tls, &body)).await;
        match result {
            Ok(Ok(response)) if response.status == 204 => {
                let valid_ms = response
                    .headers
                    .get("x-karst-relay-cap-lease-millis")
                    .and_then(|value| value.parse::<u64>().ok());
                if response
                    .headers
                    .get("x-karst-relay-cap-mode")
                    .map(String::as_str)
                    != Some("uncapped")
                    || valid_ms != Some(UNCAPPED_LEASE_MILLIS)
                {
                    eprintln!("karst-relay: cap credit request: invalid uncapped lease response");
                    controller.finish_request(mapping);
                    return;
                }
                controller.install_uncapped(
                    mapping,
                    started + Duration::from_millis(UNCAPPED_LEASE_MILLIS),
                );
                return;
            }
            Ok(Ok(response)) if response.status == 200 => {
                let valid_ms = response
                    .headers
                    .get("x-karst-relay-cap-grant-valid-millis")
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|millis| *millis > 0 && *millis <= 31 * 24 * 60 * 60 * 1000);
                let Some(valid_ms) = valid_ms else {
                    eprintln!("karst-relay: cap credit request: invalid grant validity");
                    controller.finish_request(mapping);
                    return;
                };
                match parse_grant(&response.body, controller, mapping) {
                    Ok(bytes) => {
                        controller.install_grant(
                            mapping,
                            started + Duration::from_millis(valid_ms),
                            bytes,
                        );
                        return;
                    }
                    Err(error) => {
                        eprintln!("karst-relay: cap credit request: {error}");
                        controller.finish_request(mapping);
                        return;
                    }
                }
            }
            Ok(Ok(response)) if response.status == 425 || response.status == 429 => {
                if !delay_or_cancel(&mut cancel).await {
                    controller.finish_request(mapping);
                    return;
                }
            }
            Ok(Ok(response)) => {
                eprintln!(
                    "karst-relay: cap credit request: control plane returned HTTP {}",
                    response.status
                );
                if !delay_or_cancel(&mut cancel).await {
                    controller.finish_request(mapping);
                    return;
                }
            }
            Ok(Err(error)) => {
                eprintln!("karst-relay: cap credit request: {error}");
                if !delay_or_cancel(&mut cancel).await {
                    controller.finish_request(mapping);
                    return;
                }
            }
            Err(_) => {
                eprintln!("karst-relay: cap credit request: timed out");
                if !delay_or_cancel(&mut cancel).await {
                    controller.finish_request(mapping);
                    return;
                }
            }
        }
    }
}

async fn delay_or_cancel(cancel: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(RETRY_DELAY) => true,
        changed = cancel.changed() => changed.is_ok() && !*cancel.borrow(),
    }
}

#[derive(Debug, Serialize)]
struct CreditRequest<'a> {
    relay_id: &'a str,
    deployment_id: &'a str,
    mapping_version: &'a str,
    generation: &'a str,
    request_id: &'a str,
    requested_bytes: String,
    signature: String,
}

fn signed_request(
    identity: &Identity,
    controller: &Controller,
    mapping: &UsageMapping,
    request_id: &str,
) -> Result<Vec<u8>, String> {
    let transcript = credit_request_signing_input(
        &controller.relay_id,
        &mapping.deployment,
        &mapping.version,
        &controller.generation,
        request_id,
        controller.requested_bytes,
    );
    let signature = identity
        .sign_credit_request(&transcript)
        .map_err(|error| error.to_string())?;
    serde_json::to_vec(&CreditRequest {
        relay_id: &controller.relay_id,
        deployment_id: &mapping.deployment,
        mapping_version: &mapping.version,
        generation: &controller.generation,
        request_id,
        requested_bytes: controller.requested_bytes.to_string(),
        signature: Base64::encode_string(&signature),
    })
    .map_err(|error| error.to_string())
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn post_credit(
    host: &str,
    port: u16,
    tls: &Arc<rustls::ClientConfig>,
    body: &[u8],
) -> Result<HttpResponse, String> {
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|error| format!("connect: {error}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|error| format!("server name: {error}"))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("TLS: {error}"))?;
    let host_header = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let host_header = if port == 443 {
        host_header
    } else {
        format!("{host_header}:{port}")
    };
    let request = format!(
        "POST {CREDIT_REQUEST_PATH} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("write headers: {error}"))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| format!("write request: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush: {error}"))?;
    read_response(stream).await
}

async fn read_response(
    stream: tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<HttpResponse, String> {
    let mut reader = tokio::io::BufReader::new(stream);
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .await
        .map_err(|error| format!("read status: {error}"))?;
    if line.len() > 1024 || !line.ends_with(b"\r\n") {
        return Err("invalid control-plane status line".to_owned());
    }
    let status_line =
        std::str::from_utf8(&line).map_err(|_| "non-ASCII control-plane status".to_owned())?;
    if !(status_line.starts_with("HTTP/1.1 ") || status_line.starts_with("HTTP/1.0 ")) {
        return Err("invalid control-plane protocol version".to_owned());
    }
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "invalid control-plane status".to_owned())?;
    let mut headers = HashMap::new();
    let mut total = line.len();
    loop {
        line.clear();
        reader
            .read_until(b'\n', &mut line)
            .await
            .map_err(|error| format!("read headers: {error}"))?;
        total = total.saturating_add(line.len());
        if total > MAX_RESPONSE_HEADERS || !line.ends_with(b"\r\n") {
            return Err("invalid or oversized control-plane headers".to_owned());
        }
        if line == b"\r\n" {
            break;
        }
        let text =
            std::str::from_utf8(&line).map_err(|_| "non-ASCII control-plane header".to_owned())?;
        let (name, value) = text
            .trim_end_matches("\r\n")
            .split_once(':')
            .ok_or_else(|| "malformed control-plane header".to_owned())?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || headers.insert(name, value.trim().to_owned()).is_some() {
            return Err("duplicate or empty control-plane header".to_owned());
        }
    }
    let body = if status == 204 {
        Vec::new()
    } else {
        let length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|length| *length <= MAX_RESPONSE_BODY)
            .ok_or_else(|| "missing or oversized control-plane response body".to_owned())?;
        let mut body = vec![0; length];
        reader
            .read_exact(&mut body)
            .await
            .map_err(|error| format!("read body: {error}"))?;
        body
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[derive(Debug, Deserialize)]
struct GrantResponse {
    grant_id: String,
    relay_id: String,
    generation: String,
    mapping_version: String,
    requested_bytes: String,
    granted_bytes: String,
    period_start: String,
    period_end: String,
}

fn parse_grant(
    body: &[u8],
    controller: &Controller,
    mapping: &UsageMapping,
) -> Result<u64, String> {
    if body.len() > MAX_RESPONSE_BODY {
        return Err("oversized credit grant".to_owned());
    }
    let grant: GrantResponse =
        serde_json::from_slice(body).map_err(|_| "malformed credit grant".to_owned())?;
    if grant.grant_id.len() != 32
        || !grant
            .grant_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || grant.relay_id != controller.relay_id
        || grant.generation != controller.generation
        || grant.mapping_version != mapping.version
        || grant.requested_bytes != controller.requested_bytes.to_string()
        || grant.period_start.is_empty()
        || grant.period_end.is_empty()
    {
        return Err("credit grant is not bound to this relay mapping and generation".to_owned());
    }
    let bytes = grant
        .granted_bytes
        .parse::<u64>()
        .map_err(|_| "invalid granted byte count".to_owned())?;
    if bytes == 0 || bytes > controller.requested_bytes || bytes.to_string() != grant.granted_bytes
    {
        return Err("credit grant exceeds or conflicts with the requested byte count".to_owned());
    }
    Ok(bytes)
}

fn key(mapping: &UsageMapping) -> MappingKey {
    (mapping.deployment.clone(), mapping.version.clone())
}

fn hex_lower(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        _ => char::from(b'a' + nibble - 10),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture(requested_bytes: u64) -> (Arc<Controller>, mpsc::Receiver<UsageMapping>) {
        let (requests, receiver) = mpsc::channel(8);
        let controller = Arc::new(Controller {
            relay_id: "relay-id".to_owned(),
            generation: "01".repeat(16),
            requested_bytes,
            states: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
            requests,
        });
        (controller, receiver)
    }

    fn mapping() -> UsageMapping {
        UsageMapping {
            deployment: "deployment".to_owned(),
            version: "a".repeat(64),
            aquifer: "tenant".to_owned(),
        }
    }

    #[test]
    fn missing_or_expired_state_fails_closed_and_queues_only_one_refresh() {
        let (controller, mut receiver) = fixture(1024);
        let mapping = mapping();
        assert!(!controller.reserve(&mapping, 100));
        assert!(!controller.reserve(&mapping, 100));
        assert_eq!(
            receiver.try_recv().expect("one refresh").version,
            mapping.version
        );
        assert!(receiver.try_recv().is_err());

        controller.install_uncapped(
            &mapping,
            Instant::now()
                .checked_sub(Duration::from_millis(1))
                .expect("nonzero instant"),
        );
        assert!(!controller.reserve(&mapping, 100));
        assert_eq!(
            receiver
                .try_recv()
                .expect("expired lease refresh")
                .deployment,
            mapping.deployment
        );
    }

    #[test]
    fn concurrent_reservations_never_exceed_the_installed_grant() {
        let (controller, _receiver) = fixture(100);
        let mapping = mapping();
        controller.install_grant(&mapping, Instant::now() + Duration::from_secs(60), 100);
        let count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let controller = Arc::clone(&controller);
            let mapping = mapping.clone();
            let count = Arc::clone(&count);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..50 {
                    if controller.reserve(&mapping, 1) {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().expect("reservation worker");
        }
        assert_eq!(count.load(Ordering::Relaxed), 100);
        assert!(!controller.reserve(&mapping, 1));
    }

    #[test]
    fn capped_and_uncapped_responses_are_bound_to_the_current_mapping() {
        let (controller, _) = fixture(4096);
        let mapping = mapping();
        let body = serde_json::json!({
            "grant_id": "0123456789abcdef0123456789abcdef",
            "account_id": "account",
            "period_start": "2026-10-01T00:00:00Z",
            "period_end": "2026-11-01T00:00:00Z",
            "relay_id": controller.relay_id,
            "generation": controller.generation,
            "mapping_version": mapping.version,
            "schedule_version": "schedule",
            "cap_revision": 1,
            "requested_bytes": "4096",
            "granted_bytes": "2048",
            "created_at": "2026-10-12T00:00:00Z"
        });
        let bytes = serde_json::to_vec(&body).expect("JSON body");
        assert_eq!(
            parse_grant(&bytes, &controller, &mapping).expect("valid grant"),
            2048
        );

        let wrong_mapping = UsageMapping {
            version: "b".repeat(64),
            ..mapping.clone()
        };
        assert!(parse_grant(&bytes, &controller, &wrong_mapping).is_err());

        let mut bad = body;
        *bad.get_mut("granted_bytes").expect("granted byte field") =
            serde_json::Value::String("4097".to_owned());
        let bytes = serde_json::to_vec(&bad).expect("JSON body");
        assert!(parse_grant(&bytes, &controller, &mapping).is_err());
    }
}
