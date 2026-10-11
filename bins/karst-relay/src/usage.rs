// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Bounded aggregation of successful destination writes (ADR-0050).
//! No packet contents or device identifiers enter this accumulator. Persistence
//! and producer coverage are separate: a complete window here alone does not
//! prove that all observations reached it or survived a process failure.

#[cfg(unix)]
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(unix)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::hub::DeliveryUsage;
use crate::roster::UsageMapping;

#[cfg(unix)]
pub mod spool;

/// Signed batch envelope. Its identity metadata and digest are signed with a
/// context separate from Ponor and advisory telemetry.
#[cfg(unix)]
#[derive(Debug)]
pub struct SignedBatch {
    pub id: spool::BatchId,
    pub digest: [u8; 32],
    pub signature: Vec<u8>,
    pub encoded: Vec<u8>,
}

#[cfg(unix)]
impl SignedBatch {
    /// Sign the exact bytes stored in the spool. Upload retries must reuse this
    /// envelope unchanged; never create a new signature or batch ID on retry.
    /// # Errors
    /// Returns oversize payloads or signing entropy failures.
    pub fn create(
        identity: &crate::sign::Identity,
        id: spool::BatchId,
        payload: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let payload_len = u32::try_from(payload.len()).map_err(|_| "usage batch too large")?;
        if payload.is_empty() || payload.len() > MAX_BATCH_BYTES {
            return Err("invalid usage batch size".into());
        }
        let digest: [u8; 32] = sha2::Sha256::digest(payload).into();
        let message = Self::signing_input(id, payload, &digest, payload_len);
        let signature = identity.sign_usage(&message)?;

        let mut encoded = Vec::with_capacity(68 + signature.len() + payload.len());
        encoded.extend_from_slice(b"KRUS");
        encoded.extend_from_slice(&1u16.to_be_bytes());
        encoded.extend_from_slice(&id.epoch);
        encoded.extend_from_slice(&id.sequence.to_be_bytes());
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&digest);
        encoded.extend_from_slice(&u16::try_from(signature.len())?.to_be_bytes());
        encoded.extend_from_slice(&signature);
        encoded.extend_from_slice(payload);
        Ok(Self {
            id,
            digest,
            signature,
            encoded,
        })
    }

    fn signing_input(
        id: spool::BatchId,
        payload: &[u8],
        digest: &[u8; 32],
        payload_len: u32,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(70 + payload.len());
        message.extend_from_slice(b"karst-relay-usage-batch-v1\0");
        message.extend_from_slice(&id.epoch);
        message.extend_from_slice(&id.sequence.to_be_bytes());
        message.extend_from_slice(&payload_len.to_be_bytes());
        message.extend_from_slice(digest);
        message.extend_from_slice(payload);
        message
    }
}

#[cfg(unix)]
const OBSERVATION_QUEUE: usize = 4096;

#[derive(Debug)]
struct Observation {
    completed_us: u64,
    delivery: DeliveryUsage,
}

/// Nonblocking handoff used after a complete transport write. A full or closed
/// queue sets a sticky gap flag; it never delays destination forwarding.
#[derive(Debug, Clone)]
pub struct Observer {
    sender: tokio::sync::mpsc::Sender<Observation>,
    lost: Arc<AtomicBool>,
}

impl Observer {
    pub fn record(&self, completed_us: u64, delivery: DeliveryUsage) {
        if self
            .sender
            .try_send(Observation {
                completed_us,
                delivery,
            })
            .is_err()
        {
            self.lost.store(true, Ordering::Release);
        }
    }
}

/// Live, explicitly enabled relay usage collection.
#[derive(Debug)]
pub struct Runtime {
    observer: Observer,
    task: tokio::task::JoinHandle<()>,
}

impl Runtime {
    /// Open the durable spool and start minute aggregation.
    /// # Errors
    /// Returns spool, locking, or filesystem errors before the listener starts.
    #[cfg(unix)]
    pub fn start(path: &Path, identity: Arc<crate::sign::Identity>) -> std::io::Result<Self> {
        let mut spool = spool::Spool::open(path)?;
        let unclean = spool.recovered_unclean();
        let lost = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = tokio::sync::mpsc::channel(OBSERVATION_QUEUE);
        let task_lost = Arc::clone(&lost);
        let task = tokio::spawn(async move {
            consume(receiver, task_lost, &mut spool, unclean, &identity).await;
        });
        Ok(Self {
            observer: Observer { sender, lost },
            task,
        })
    }

    /// # Errors
    /// Relay usage spooling currently requires a Unix filesystem.
    #[cfg(not(unix))]
    pub fn start(_path: &Path, _identity: Arc<crate::sign::Identity>) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "relay usage spool requires Unix",
        ))
    }

    #[must_use]
    pub fn observer(&self) -> Observer {
        self.observer.clone()
    }

    /// Join after dropping every observer; the consumer seals its last window.
    /// # Errors
    /// Returns a panic from the background consumer task.
    pub async fn finish(self) -> Result<(), tokio::task::JoinError> {
        let Self { observer, task } = self;
        drop(observer);
        task.await
    }
}

#[cfg(unix)]
async fn consume(
    mut receiver: tokio::sync::mpsc::Receiver<Observation>,
    lost: Arc<AtomicBool>,
    spool: &mut spool::Spool,
    unclean: bool,
    identity: &crate::sign::Identity,
) {
    let now = now_micros();
    let bucket = now / BUCKET_MICROS * BUCKET_MICROS;
    let Some(mut window) = Accumulator::new(bucket) else {
        return;
    };
    if unclean {
        window.mark_gap(Gap::ObservationLost);
    }
    let mut storage_lost = false;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let observation = tokio::select! {
            item = receiver.recv() => item,
            _ = ticker.tick() => {
                let now = now_micros();
                let target = now / BUCKET_MICROS * BUCKET_MICROS;
                advance(&mut window, target, lost.load(Ordering::Acquire), &mut storage_lost, spool, identity);
                continue;
            }
        };
        let Some(observation) = observation else {
            break;
        };
        let target = observation.completed_us / BUCKET_MICROS * BUCKET_MICROS;
        advance(
            &mut window,
            target,
            lost.load(Ordering::Acquire),
            &mut storage_lost,
            spool,
            identity,
        );
        if lost.swap(false, Ordering::AcqRel) {
            window.mark_gap(Gap::ObservationLost);
        }
        if storage_lost {
            window.mark_gap(Gap::ObservationLost);
        }
        window.record(observation.completed_us, observation.delivery);
    }
    let now = now_micros();
    let target = now / BUCKET_MICROS * BUCKET_MICROS;
    advance(
        &mut window,
        target,
        lost.load(Ordering::Acquire),
        &mut storage_lost,
        spool,
        identity,
    );
    if lost.load(Ordering::Acquire) || storage_lost {
        window.mark_gap(Gap::ObservationLost);
    }
    let sealed = spool.seal_signed(&window.seal(), identity).is_ok();
    if sealed {
        let _ = spool.clean_shutdown();
    }
}

#[cfg(unix)]
fn advance(
    window: &mut Accumulator,
    target: u64,
    loss: bool,
    storage_lost: &mut bool,
    spool: &mut spool::Spool,
    identity: &crate::sign::Identity,
) {
    if target.saturating_sub(window.start_us) / BUCKET_MICROS > 5 {
        window.mark_gap(Gap::Clock);
        if loss || *storage_lost {
            window.mark_gap(Gap::ObservationLost);
        }
        let Some(next) = Accumulator::new(target) else {
            return;
        };
        let completed = std::mem::replace(window, next).seal();
        *storage_lost = spool.seal_signed(&completed, identity).is_err();
        return;
    }
    while window.start_us < target {
        if loss || *storage_lost {
            window.mark_gap(Gap::ObservationLost);
        }
        let next_start = window.end_us;
        let Some(next) = Accumulator::new(next_start) else {
            return;
        };
        let completed = std::mem::replace(window, next).seal();
        *storage_lost = spool.seal_signed(&completed, identity).is_err();
    }
}

#[cfg(unix)]
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros().try_into().unwrap_or(u64::MAX))
}

pub const BUCKET_MICROS: u64 = 60_000_000;
pub const MAX_MAPPINGS: usize = 4096;
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Reasons observed bytes cannot establish complete coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Gap {
    UnresolvedMapping,
    Capacity,
    Overflow,
    Clock,
    ObservationLost,
}

/// One mapping's observed payload bytes. No money or estimated bytes.
#[derive(Debug)]
pub struct Total {
    pub mapping: UsageMapping,
    pub bytes: u64,
}

/// A sealed observation window, ready for durable batch construction.
#[derive(Debug)]
pub struct Window {
    pub start_us: u64,
    pub end_us: u64,
    pub totals: Vec<Total>,
    pub gaps: BTreeSet<Gap>,
}

impl Window {
    /// Canonical versioned encoding for a sealed aggregate, placed inside a
    /// signed spool envelope. Fields are length-prefixed UTF-8 and sorted by
    /// mapping; packet payloads and device IDs are absent.
    /// # Errors
    /// Rejects out-of-bound windows or metadata before allocating a batch.
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.end_us <= self.start_us
            || self.end_us - self.start_us != BUCKET_MICROS
            || self.totals.len() > MAX_MAPPINGS
            || self.gaps.len() > 8
        {
            return Err("invalid usage window");
        }
        let mut out = Vec::with_capacity(64 + self.totals.len() * 64);
        out.extend_from_slice(b"KRUM");
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&self.start_us.to_be_bytes());
        out.extend_from_slice(&self.end_us.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(self.totals.len())
                .map_err(|_| "too many mappings")?
                .to_be_bytes(),
        );
        let mut previous: Option<(&str, &str, &str)> = None;
        for total in &self.totals {
            let mapping = &total.mapping;
            if mapping.deployment.is_empty()
                || mapping.deployment.len() > 128
                || mapping.version.is_empty()
                || mapping.version.len() > 64
                || mapping.aquifer.is_empty()
                || mapping.aquifer.len() > 1024
            {
                return Err("invalid usage mapping");
            }
            let current = (
                mapping.deployment.as_str(),
                mapping.version.as_str(),
                mapping.aquifer.as_str(),
            );
            if previous.is_some_and(|p| p >= current) {
                return Err("unsorted or duplicate usage mapping");
            }
            previous = Some(current);
            for field in [current.0, current.1, current.2] {
                out.extend_from_slice(
                    &u16::try_from(field.len())
                        .map_err(|_| "mapping field too long")?
                        .to_be_bytes(),
                );
                out.extend_from_slice(field.as_bytes());
            }
            out.extend_from_slice(&total.bytes.to_be_bytes());
        }
        let mut gap_bits = 0u8;
        for gap in &self.gaps {
            gap_bits |= 1 << (*gap as u8);
        }
        out.push(gap_bits);
        if out.len() > MAX_BATCH_BYTES {
            return Err("usage batch too large");
        }
        Ok(out)
    }
}

#[derive(Debug)]
pub struct Accumulator {
    start_us: u64,
    end_us: u64,
    totals: BTreeMap<(String, String, String), u64>,
    gaps: BTreeSet<Gap>,
}

impl Accumulator {
    /// Open a UTC minute. Invalid or overflowing bounds are rejected.
    #[must_use]
    pub fn new(start_us: u64) -> Option<Self> {
        if !start_us.is_multiple_of(BUCKET_MICROS) {
            return None;
        }
        Some(Self {
            start_us,
            end_us: start_us.checked_add(BUCKET_MICROS)?,
            totals: BTreeMap::new(),
            gaps: BTreeSet::new(),
        })
    }

    /// Add one complete write at its completion timestamp. The caller routes
    /// it to the correct minute. Out-of-window observations mark uncertainty
    /// without silently assigning bytes to another time interval.
    pub fn record(&mut self, completed_us: u64, delivery: DeliveryUsage) {
        if completed_us < self.start_us || completed_us >= self.end_us {
            self.mark_gap(Gap::Clock);
            return;
        }
        let Some(mapping) = delivery.mapping else {
            self.mark_gap(Gap::UnresolvedMapping);
            return;
        };
        // Bound retained bytes as well as entry count, even if a future caller
        // constructs metadata without the roster parser's validation.
        if mapping.deployment.is_empty()
            || mapping.deployment.len() > 128
            || mapping.version.is_empty()
            || mapping.version.len() > 64
            || mapping.aquifer.is_empty()
            || mapping.aquifer.len() > 1024
        {
            self.mark_gap(Gap::UnresolvedMapping);
            return;
        }
        let key = (mapping.deployment, mapping.version, mapping.aquifer);
        if let Some(bytes) = self.totals.get_mut(&key) {
            if let Some(total) = bytes.checked_add(delivery.payload_bytes) {
                *bytes = total;
            } else {
                self.mark_gap(Gap::Overflow);
            }
        } else if self.totals.len() < MAX_MAPPINGS {
            self.totals.insert(key, delivery.payload_bytes);
        } else {
            self.mark_gap(Gap::Capacity);
        }
    }

    /// A producer must call this when its bounded observation queue loses data.
    pub fn mark_gap(&mut self, gap: Gap) {
        self.gaps.insert(gap);
    }

    /// Consumes the accumulator; persisting/retrying this window must not add
    /// its totals a second time. Empty windows remain explicit heartbeats.
    #[must_use]
    pub fn seal(self) -> Window {
        Window {
            start_us: self.start_us,
            end_us: self.end_us,
            totals: self
                .totals
                .into_iter()
                .map(|((deployment, version, aquifer), bytes)| Total {
                    mapping: UsageMapping {
                        deployment,
                        version,
                        aquifer,
                    },
                    bytes,
                })
                .collect(),
            gaps: self.gaps,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    fn delivery(version: &str, bytes: u64) -> DeliveryUsage {
        DeliveryUsage {
            mapping: Some(UsageMapping {
                deployment: "deployment".into(),
                version: version.into(),
                aquifer: "aquifer".into(),
            }),
            payload_bytes: bytes,
        }
    }

    #[test]
    fn mapping_changes_remain_separate_and_repeated_deliveries_add() {
        let mut acc = Accumulator::new(0).expect("minute");
        acc.record(1, delivery("old", 10));
        acc.record(2, delivery("old", 10));
        acc.record(3, delivery("new", 30));
        let window = acc.seal();
        assert!(window.gaps.is_empty());
        assert_eq!(window.totals.len(), 2);
        assert_eq!(window.totals[0].bytes, 30);
        assert_eq!(window.totals[1].bytes, 20);
    }

    #[test]
    fn failures_preserve_observed_totals_without_wrapping_or_inventing_bytes() {
        let mut acc = Accumulator::new(0).expect("minute");
        acc.record(0, delivery("version", u64::MAX));
        acc.record(1, delivery("version", 1));
        acc.record(
            2,
            DeliveryUsage {
                mapping: None,
                payload_bytes: 100,
            },
        );
        acc.record(BUCKET_MICROS, delivery("version", 100));
        acc.mark_gap(Gap::ObservationLost);
        let window = acc.seal();
        assert_eq!(window.totals[0].bytes, u64::MAX);
        assert_eq!(
            window.gaps,
            BTreeSet::from([
                Gap::Overflow,
                Gap::UnresolvedMapping,
                Gap::Clock,
                Gap::ObservationLost
            ])
        );
    }

    #[test]
    fn cardinality_is_bounded_and_existing_mappings_continue() {
        let mut acc = Accumulator::new(0).expect("minute");
        for i in 0..=MAX_MAPPINGS {
            acc.record(1, delivery(&i.to_string(), 1));
        }
        acc.record(2, delivery("0", 5));
        let window = acc.seal();
        assert_eq!(window.totals.len(), MAX_MAPPINGS);
        assert_eq!(window.totals[0].bytes, 6);
        assert!(window.gaps.contains(&Gap::Capacity));
    }

    #[test]
    fn empty_heartbeats_and_invalid_bounds_are_explicit() {
        let window = Accumulator::new(0).expect("minute").seal();
        assert!(window.totals.is_empty());
        assert!(window.gaps.is_empty());
        assert_eq!(window.end_us, BUCKET_MICROS);
        assert!(Accumulator::new(1).is_none());
        assert!(Accumulator::new(u64::MAX - u64::MAX % BUCKET_MICROS).is_none());
    }

    #[test]
    fn batch_encoding_is_stable_versioned_and_contains_only_aggregate_metadata() {
        let mut acc = Accumulator::new(0).expect("minute");
        acc.record(1, delivery("version", 100));
        let window = acc.seal();
        let first = window.encode().expect("encode");
        assert_eq!(first, window.encode().expect("repeatable"));
        assert_eq!(&first[..6], b"KRUM\x00\x01");
        assert_eq!(
            u64::from_be_bytes(first[6..14].try_into().expect("start")),
            0
        );
        assert_eq!(
            u64::from_be_bytes(first[14..22].try_into().expect("end")),
            BUCKET_MICROS
        );
    }

    #[cfg(unix)]
    #[test]
    fn signed_batch_binds_its_identity_and_exact_aggregate_payload() {
        let identity = crate::sign::Identity::from_seed(&[3; crate::sign::SEED_LEN]);
        let mut acc = Accumulator::new(0).expect("minute");
        acc.record(1, delivery("version", 100));
        let payload = acc.seal().encode().expect("payload");
        let id = spool::BatchId {
            epoch: [7; 16],
            sequence: 9,
        };
        let batch = SignedBatch::create(&identity, id, &payload).expect("signed batch");
        assert_eq!(batch.encoded.get(..6).expect("header"), b"KRUS\0\x01");
        assert_eq!(batch.id, id);
        let expected_digest: [u8; 32] = sha2::Sha256::digest(&payload).into();
        assert_eq!(batch.digest, expected_digest);

        let signature_len = u16::from_be_bytes(batch.encoded[66..68].try_into().expect("sig len"));
        let signature_end = 68 + usize::from(signature_len);
        let payload_len = u32::try_from(payload.len()).expect("payload length");
        let message = SignedBatch::signing_input(id, &payload, &batch.digest, payload_len);
        assert!(crate::sign::verify_usage(
            identity.public_key(),
            &message,
            &batch.encoded[68..signature_end]
        ));

        let changed_id = spool::BatchId { sequence: 10, ..id };
        let changed_message =
            SignedBatch::signing_input(changed_id, &payload, &batch.digest, payload_len);
        assert!(!crate::sign::verify_usage(
            identity.public_key(),
            &changed_message,
            &batch.encoded[68..signature_end]
        ));
        let mut changed_payload = payload.clone();
        *changed_payload.last_mut().expect("payload is nonempty") ^= 1;
        let changed_digest: [u8; 32] = sha2::Sha256::digest(&changed_payload).into();
        let changed_message = SignedBatch::signing_input(
            id,
            &changed_payload,
            &changed_digest,
            u32::try_from(changed_payload.len()).expect("payload length"),
        );
        assert!(!crate::sign::verify_usage(
            identity.public_key(),
            &changed_message,
            &batch.encoded[68..signature_end]
        ));
    }

    #[cfg(unix)]
    #[test]
    fn shared_go_signing_vector_matches_the_relay_envelope() {
        #[derive(serde::Deserialize)]
        struct Vector {
            #[serde(rename = "EpochHex")]
            epoch_hex: String,
            #[serde(rename = "Sequence")]
            sequence: u64,
            #[serde(rename = "PayloadHex")]
            payload_hex: String,
            #[serde(rename = "PayloadSHA256Hex")]
            payload_sha256_hex: String,
            #[serde(rename = "SigningInputHex")]
            signing_input_hex: String,
        }

        fn decode_hex(text: &str) -> Vec<u8> {
            text.as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    u8::from_str_radix(std::str::from_utf8(pair).expect("hex is UTF-8"), 16)
                        .expect("valid hex pair")
                })
                .collect()
        }

        fn encode_hex(bytes: &[u8]) -> String {
            use std::fmt::Write as _;
            let mut text = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
            }
            text
        }

        let vector: Vector = serde_json::from_str(include_str!(
            "../../../spec/vectors/relay-usage-batch-v1.json"
        ))
        .expect("valid shared usage vector");
        let mut epoch = [0; 16];
        epoch.copy_from_slice(&decode_hex(&vector.epoch_hex));
        let id = spool::BatchId {
            epoch,
            sequence: vector.sequence,
        };
        let payload = Accumulator::new(0)
            .expect("minute")
            .seal()
            .encode()
            .expect("payload");
        assert_eq!(encode_hex(&payload), vector.payload_hex);
        let digest: [u8; 32] = sha2::Sha256::digest(&payload).into();
        assert_eq!(encode_hex(&digest), vector.payload_sha256_hex);
        let message = SignedBatch::signing_input(
            id,
            &payload,
            &digest,
            u32::try_from(payload.len()).expect("payload length"),
        );
        assert_eq!(encode_hex(&message), vector.signing_input_hex);
    }

    #[test]
    fn unrepresentable_windows_are_rejected_before_sealing() {
        let mut acc = Accumulator::new(0).expect("minute");
        acc.record(1, delivery("version", 1));
        let mut window = acc.seal();
        window.end_us -= 1;
        assert!(window.encode().is_err());
        let mut acc = Accumulator::new(0).expect("minute");
        acc.record(1, delivery("z-version", 1));
        acc.record(2, delivery("a-version", 2));
        let mut window = acc.seal();
        window.totals.reverse();
        assert!(window.encode().is_err());
    }
}
