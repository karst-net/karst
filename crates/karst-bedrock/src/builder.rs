// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Building a log, in the three steps the offline workflow actually has.
//!
//! The split into prepare / sign / commit is not ceremony for its own sake: it
//! is the shape of the real deployment. The console *prepares* an entry and
//! exports its signing input; an admin carries it to a machine with no network
//! interface and signs it there; the console *commits* the result. A one-call
//! `append` that took private keys would only ever be usable by a server that
//! holds authority keys, which is the arrangement Bedrock exists to avoid.
//!
//! This mirrors `builder.go` on the Go side.

use crate::log::{Entry, Op, Signature};
use crate::verify::{verify_log, State};
use crate::Error;

/// Accumulates a log, tracking the chain so a caller never computes a previous
/// hash by hand.
#[derive(Debug, Default)]
pub struct Builder {
    entries: Vec<Entry>,
    prev: Vec<u8>,
}

impl Builder {
    /// Start an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resume building on top of an already verified log.
    ///
    /// Re-verifies rather than trusting the caller's entries: this is the path
    /// a rebuilt server takes when re-seeded from a node's replicated copy
    /// (spec §7), and that copy arrived over a network.
    ///
    /// # Errors
    ///
    /// Whatever [`verify_log`] returns for the given entries.
    pub fn resume(entries: Vec<Entry>) -> Result<Self, Error> {
        let st = verify_log(&entries)?;
        Ok(Self {
            entries,
            prev: st.head,
        })
    }

    /// The next sequence number this builder will assign.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        (self.entries.len() as u64).saturating_add(1)
    }

    /// Build the next entry and return it with the hash its signers must sign.
    ///
    /// Nothing is appended until [`Builder::commit`].
    #[must_use]
    pub fn prepare(&self, time: i64, op: Op, body: Vec<u8>) -> (Entry, Vec<u8>) {
        let e = Entry {
            seq: self.next_seq(),
            time,
            op,
            body,
            sigs: Vec::new(),
        };
        let input = e.signing_input(&self.prev);
        (e, input)
    }

    /// Append a prepared entry with the signatures collected for it.
    ///
    /// The chain position comes from this builder's own state, not from the
    /// entry, so a caller who mutated the entry between prepare and commit gets
    /// a signature failure rather than a divergent chain.
    ///
    /// # Errors
    ///
    /// [`Error::Broken`] if the entry's sequence does not follow this log.
    pub fn commit(&mut self, mut entry: Entry, sigs: Vec<Signature>) -> Result<(), Error> {
        if entry.seq != self.next_seq() {
            return Err(Error::Broken {
                seq: entry.seq,
                why: format!("expected seq {}", self.next_seq()),
            });
        }
        entry.sigs = sigs;
        self.prev = entry.signing_input(&self.prev);
        self.entries.push(entry);
        Ok(())
    }

    /// The log built so far.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Consume the builder for its entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries
    }

    /// The current head hash, empty for an unstarted log.
    #[must_use]
    pub fn head(&self) -> &[u8] {
        &self.prev
    }

    /// Verify the log built so far.
    ///
    /// # Errors
    ///
    /// Whatever [`verify_log`] returns.
    pub fn verify(&self) -> Result<State, Error> {
        verify_log(&self.entries)
    }
}
