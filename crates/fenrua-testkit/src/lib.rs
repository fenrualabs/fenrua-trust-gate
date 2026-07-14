//! Deterministic, test-only R1 foundations. These types are not an operational
//! replay service, clock source, or a substitute for a future replay design.

use std::collections::BTreeMap;

use fenrua_gate::{ReplayCheckpoint, ReplayKey, ReplayState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedClock {
    tick: u64,
}

impl FixedClock {
    pub const fn new(tick: u64) -> Self {
        Self { tick }
    }

    pub const fn now(&self) -> u64 {
        self.tick
    }

    pub fn advance(&mut self, ticks: u64) {
        self.tick = self.tick.saturating_add(ticks);
    }
}

/// A deterministic, single-process state map for tests. It never persists or
/// coordinates callers and must not be used as production replay protection.
#[derive(Clone, Debug, Default)]
pub struct MemoryReplayCheckpoint {
    states: BTreeMap<ReplayKey, ReplayState>,
    available: bool,
}

impl MemoryReplayCheckpoint {
    pub fn available() -> Self {
        Self {
            states: BTreeMap::new(),
            available: true,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            states: BTreeMap::new(),
            available: false,
        }
    }

    pub fn insert(&mut self, key: ReplayKey, state: ReplayState) {
        self.states.insert(key, state);
    }
}

impl ReplayCheckpoint for MemoryReplayCheckpoint {
    fn check(&self, key: &ReplayKey) -> ReplayState {
        if !self.available {
            return ReplayState::Unavailable;
        }
        self.states.get(key).copied().unwrap_or(ReplayState::Fresh)
    }
}

#[cfg(test)]
mod tests {
    use fenrua_gate::{ReplayCheckpoint, ReplayKey, ReplayState};

    use super::{FixedClock, MemoryReplayCheckpoint};

    #[test]
    fn fixed_clock_is_repeatable_and_explicitly_advanced() {
        let mut clock = FixedClock::new(11);
        assert_eq!(clock.now(), 11);
        clock.advance(9);
        assert_eq!(clock.now(), 20);
    }

    #[test]
    fn memory_checkpoint_is_deterministic_and_can_model_unavailability() {
        let key = match ReplayKey::new("test-key".to_owned()) {
            Ok(key) => key,
            Err(error) => panic!("test key must be valid: {error}"),
        };
        let mut checkpoint = MemoryReplayCheckpoint::available();
        assert_eq!(checkpoint.check(&key), ReplayState::Fresh);
        checkpoint.insert(key.clone(), ReplayState::Replayed);
        assert_eq!(checkpoint.check(&key), ReplayState::Replayed);
        assert_eq!(
            MemoryReplayCheckpoint::unavailable().check(&key),
            ReplayState::Unavailable
        );
    }
}
