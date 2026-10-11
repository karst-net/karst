// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Bounded aggregation of successful destination writes (ADR-0050).
//! No packet contents or device identifiers enter this accumulator. Persistence
//! and producer coverage are separate: a complete window here alone does not
//! prove that all observations reached it or survived a process failure.

use std::collections::{BTreeMap, BTreeSet};

use crate::hub::DeliveryUsage;
use crate::roster::UsageMapping;

#[cfg(unix)]
pub mod spool;

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
    /// Canonical versioned encoding for a sealed spool batch. Fields are
    /// length-prefixed UTF-8 and sorted by mapping; payload and device IDs are
    /// absent. This representation is the input for future signing/upload.
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
