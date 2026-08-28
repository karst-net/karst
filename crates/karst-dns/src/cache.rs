// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Small bounded DNS response cache with TTL clamping.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const MAX_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub name: String,
    /// The wire QTYPE, rather than KarstDNS's policy grouping.  In particular,
    /// CNAME and TXT must never share a cache entry merely because both are
    /// non-address mesh queries.
    pub record_type: u16,
}

/// Observable cache activity for the daemon status command.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub hits: u64,
    pub misses: u64,
    pub entries: usize,
}

#[derive(Clone, Debug)]
struct Entry {
    response: Vec<u8>,
    expires: Instant,
}

/// A deterministic, bounded response cache. The caller supplies the TTL from
/// the validated upstream response; zero is never cached and positive values
/// are capped to prevent one bad upstream from pinning stale data for days.
#[derive(Debug)]
pub struct Cache {
    capacity: usize,
    entries: BTreeMap<Key, Entry>,
    hits: u64,
    misses: u64,
}

impl Cache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    pub fn get(&mut self, key: &Key) -> Option<Vec<u8>> {
        let Some(entry) = self.entries.get(key) else {
            self.misses = self.misses.saturating_add(1);
            return None;
        };
        if entry.expires <= Instant::now() {
            self.entries.remove(key);
            self.misses = self.misses.saturating_add(1);
            return None;
        }
        self.hits = self.hits.saturating_add(1);
        Some(entry.response.clone())
    }

    #[must_use]
    pub fn stats(&self) -> Stats {
        Stats {
            hits: self.hits,
            misses: self.misses,
            entries: self.entries.len(),
        }
    }

    pub fn insert(&mut self, key: Key, response: Vec<u8>, ttl: Duration) {
        let ttl = ttl.min(MAX_TTL);
        if self.capacity == 0 || ttl.is_zero() {
            return;
        }
        while self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            // BTreeMap's stable first key makes eviction deterministic. This
            // cache is a performance feature, never a source of policy.
            if let Some(oldest) = self.entries.keys().next().cloned() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            Entry {
                response,
                expires: Instant::now() + ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_ttl_is_not_cached() {
        let mut cache = Cache::new(2);
        let key = Key {
            name: "example.test".to_owned(),
            record_type: 1,
        };
        cache.insert(key.clone(), vec![1], Duration::ZERO);
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn capacity_is_bounded() {
        let mut cache = Cache::new(1);
        let first = Key {
            name: "a.test".to_owned(),
            record_type: 1,
        };
        let second = Key {
            name: "b.test".to_owned(),
            record_type: 1,
        };
        cache.insert(first.clone(), vec![1], Duration::from_secs(1));
        cache.insert(second.clone(), vec![2], Duration::from_secs(1));
        assert_eq!(cache.get(&first), None);
        assert_eq!(cache.get(&second), Some(vec![2]));
    }

    #[test]
    fn statistics_distinguish_hits_and_misses() {
        let mut cache = Cache::new(1);
        let key = Key {
            name: "a.test".to_owned(),
            record_type: 1,
        };
        assert_eq!(cache.get(&key), None);
        cache.insert(key.clone(), vec![1], Duration::from_secs(1));
        assert_eq!(cache.get(&key), Some(vec![1]));
        assert_eq!(
            cache.stats(),
            Stats {
                hits: 1,
                misses: 1,
                entries: 1,
            }
        );
    }
}
