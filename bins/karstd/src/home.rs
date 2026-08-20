// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Choosing a home relay — `ponor-v1.md` §9.1, §9.2.
//!
//! A node keeps a connection to one relay for as long as it runs, so that peers
//! have somewhere to reach it before any direct path exists. Which relay that
//! is used to be "whichever the netmap listed first", which is a choice made by
//! the server's iteration order rather than by the network.
//!
//! **Sans-io and sans-clock**, like everything else that decides: round-trip
//! times arrive from the caller, and this says which relay to hold.
//!
//! # The hysteresis is AVEN's, deliberately
//!
//! §9.2 requires hysteresis and recommends 20 ms or 20%, sustained. That is
//! word for word `aven-v1.md` §8.2's rule for path selection, so this uses
//! `karst_disco`'s constants rather than restating them. Two copies of one
//! number are free to drift, and a reader who found them disagreeing would have
//! no way to tell which was intended.
//!
//! §9.2's reasoning is worth keeping in view because it is not the usual
//! stability argument: **the cost of flapping is not paid by the node that
//! flaps.** Every change must reach the coordination server and from there
//! every peer, so a node that tracks the instantaneous minimum spends the whole
//! aquifer's netmap churn on its own noise.

use std::collections::HashMap;

use karst_disco::consts::HYSTERESIS_SAMPLES;

/// A relay's 32-byte id.
pub type RelayId = [u8; 32];

/// Which relay to hold a connection to.
#[derive(Debug, Default)]
pub struct Selector {
    chosen: Option<RelayId>,
    /// Most recent round-trip time per relay.
    latest: HashMap<RelayId, u64>,
    /// Consecutive rounds a challenger has beaten the incumbent by the margin.
    streak: HashMap<RelayId, u32>,
}

impl Selector {
    /// Nothing measured yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a measurement.
    ///
    /// One value per relay per round; a later measurement replaces an earlier
    /// one rather than averaging, because §9.2's stability comes from the
    /// sustained-margin rule and an average would apply it twice.
    ///
    /// Measurements are consumed by [`Self::select`], so **a relay that does
    /// not answer a round is absent from it** rather than carrying its last
    /// good number forward. Retaining it would make a relay that had stopped
    /// responding keep looking as fast as the day it died, which is the one
    /// state a home relay must not be chosen in.
    pub fn observe(&mut self, relay: RelayId, rtt_ms: u64) {
        self.latest.insert(relay, rtt_ms);
    }

    /// Forget a relay the netmap no longer lists.
    ///
    /// Including the choice itself: holding a connection to a relay the
    /// coordination server has withdrawn is holding it to somewhere peers are
    /// no longer told to look.
    pub fn retain(&mut self, present: &[RelayId]) {
        self.latest.retain(|id, _| present.contains(id));
        self.streak.retain(|id, _| present.contains(id));
        if self.chosen.is_some_and(|c| !present.contains(&c)) {
            self.chosen = None;
        }
    }

    /// The relay currently held.
    #[must_use]
    pub fn chosen(&self) -> Option<RelayId> {
        self.chosen
    }

    /// Whether `challenger` beats `incumbent` by §9.2's margin.
    ///
    /// **"Whichever is larger" means the required improvement is the larger of
    /// the two, not that either one suffices.** Read the other way — as an
    /// `OR` — a 1 ms gain on a 3 ms path clears the 20% test and the node
    /// switches on jitter, which is precisely what §9.2 exists to stop. The
    /// first version of this function made that mistake and a test caught it.
    ///
    /// `karst_disco::margin` is the one implementation; AVEN §8.2 states the
    /// same rule for path selection and had it right already.
    #[must_use]
    pub fn beats(challenger: u64, incumbent: u64) -> bool {
        incumbent.saturating_sub(challenger) >= karst_disco::margin(incumbent)
    }

    /// Decide, given everything measured this round.
    ///
    /// Returns the relay to hold, and whether it changed.
    pub fn select(&mut self) -> (Option<RelayId>, bool) {
        let round = std::mem::take(&mut self.latest);
        let Some((&best, &best_rtt)) = round.iter().min_by_key(|(id, rtt)| (**rtt, **id)) else {
            return (self.chosen, false);
        };

        let Some(current) = self.chosen else {
            // Nothing held yet: take the fastest at once. Hysteresis defends an
            // existing choice, and there is nothing here to defend — making the
            // first selection wait three rounds would leave a starting node
            // with no relay at the moment it most needs one.
            self.chosen = Some(best);
            self.streak.clear();
            return (self.chosen, true);
        };

        // The incumbent may not have answered this round. Treating silence as
        // infinitely slow would switch away on one lost datagram, so it keeps
        // its place until something beats it on evidence.
        let Some(&current_rtt) = round.get(&current) else {
            self.streak.clear();
            return (self.chosen, false);
        };

        if best == current || !Self::beats(best_rtt, current_rtt) {
            self.streak.clear();
            return (self.chosen, false);
        }

        let streak = self.streak.entry(best).or_insert(0);
        *streak = streak.saturating_add(1);
        if *streak >= HYSTERESIS_SAMPLES {
            self.chosen = Some(best);
            self.streak.clear();
            return (self.chosen, true);
        }
        (self.chosen, false)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn id(n: u8) -> RelayId {
        [n; 32]
    }

    #[test]
    fn the_first_selection_is_immediate() {
        // Hysteresis defends an existing choice. Making the first one wait
        // three rounds leaves a starting node without a relay at the moment
        // peers most need somewhere to reach it.
        let mut s = Selector::new();
        s.observe(id(1), 40);
        s.observe(id(2), 12);
        assert_eq!(s.select(), (Some(id(2)), true));
    }

    #[test]
    fn a_faster_relay_must_win_for_several_rounds_before_it_is_taken() {
        let mut s = Selector::new();
        s.observe(id(1), 100);
        assert_eq!(s.select(), (Some(id(1)), true));

        for round in 1..HYSTERESIS_SAMPLES {
            s.observe(id(1), 100);
            s.observe(id(2), 10);
            assert_eq!(
                s.select(),
                (Some(id(1)), false),
                "switched after only {round} round(s)"
            );
        }
        s.observe(id(1), 100);
        s.observe(id(2), 10);
        assert_eq!(s.select(), (Some(id(2)), true), "never switched");
    }

    #[test]
    fn one_good_round_does_not_carry_over() {
        // The margin has to be *sustained*. A challenger that wins, loses, then
        // wins again has not shown it is better; it has shown the path is
        // noisy, which is the case §9.2 exists for.
        let mut s = Selector::new();
        s.observe(id(1), 100);
        let _ = s.select();
        for _ in 0..10 {
            s.observe(id(1), 100);
            s.observe(id(2), 10);
            assert!(!s.select().1, "switched on an alternating pattern");
            s.observe(id(1), 100);
            s.observe(id(2), 200);
            assert!(!s.select().1);
        }
        assert_eq!(s.chosen(), Some(id(1)));
    }

    #[test]
    fn a_margin_that_is_only_noise_never_wins() {
        // 20% of a 2 ms path is 0.4 ms. Without the absolute floor a node on a
        // fast network would rewrite the whole aquifer's netmap over jitter.
        let mut s = Selector::new();
        s.observe(id(1), 2);
        let _ = s.select();
        for _ in 0..20 {
            s.observe(id(1), 2);
            s.observe(id(2), 1);
            assert!(!s.select().1, "switched on sub-millisecond jitter");
        }
    }

    #[test]
    fn the_margin_is_the_larger_of_absolute_and_proportional() {
        // Both ends of the range, which is why §9.2 states two numbers.
        assert!(Selector::beats(10, 100), "80% faster");
        assert!(
            !Selector::beats(380, 400),
            "on a 400 ms path 20% is 80 ms, and that is the larger margin — \
             reading the rule as an OR is exactly the mistake §9.2 prevents"
        );
        assert!(Selector::beats(300, 400), "100 ms clears the 80 ms margin");
        assert!(!Selector::beats(99, 100), "1 ms and 1% is neither");
        assert!(!Selector::beats(2, 3), "1 ms on a fast path is noise");
    }

    #[test]
    fn a_silent_incumbent_keeps_its_place() {
        // Treating a missed measurement as infinitely slow would move the whole
        // aquifer's view of this node on one lost datagram.
        let mut s = Selector::new();
        s.observe(id(1), 50);
        let _ = s.select();
        for _ in 0..HYSTERESIS_SAMPLES + 2 {
            s.observe(id(2), 5); // the incumbent says nothing
            assert_eq!(s.select(), (Some(id(1)), false));
        }
    }

    #[test]
    fn a_withdrawn_relay_is_released_even_if_it_was_the_choice() {
        // Holding a connection to a relay the server has withdrawn is holding
        // it to somewhere peers are no longer told to look.
        let mut s = Selector::new();
        s.observe(id(1), 10);
        assert_eq!(s.select(), (Some(id(1)), true));
        s.retain(&[id(2)]);
        assert_eq!(s.chosen(), None);
        s.observe(id(2), 90);
        assert_eq!(s.select(), (Some(id(2)), true));
    }

    #[test]
    fn ties_are_broken_the_same_way_every_time() {
        // Two relays at the same RTT must not alternate: the choice is
        // published to every peer, so an arbitrary tie-break that moved would
        // be netmap churn with no benefit at all.
        let mut a = Selector::new();
        let mut b = Selector::new();
        for s in [&mut a, &mut b] {
            s.observe(id(9), 30);
            s.observe(id(3), 30);
        }
        assert_eq!(a.select().0, b.select().0);
    }
}
