//! Fail-closed evaluator-admission and replay interfaces for R1.
//!
//! There is no policy evaluator, decision schema, evidence generator, or
//! authorisation result in this crate yet. The only safe R1 response to an
//! evaluation request is that the feature is unavailable.

use fenrua_protocol::{Problem, ProblemCode};

/// An opaque, bounded test-facing replay identity. Future released contracts
/// will define the canonical tenant/audience/context/request binding.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReplayKey(String);

impl ReplayKey {
    pub fn new(value: String) -> Result<Self, Problem> {
        if value.is_empty() || value.len() > 512 {
            return Err(Problem::new(ProblemCode::InvalidArgument));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded replay checkpoint result. It does not itself authorise any work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayState {
    Fresh,
    ExistingIdempotent,
    Replayed,
    Unavailable,
}

/// A future evaluator accepts a caller-provided local checkpoint rather than a
/// hidden database or network dependency.
pub trait ReplayCheckpoint {
    fn check(&self, key: &ReplayKey) -> ReplayState;
}

/// R1 intentionally exposes no evaluation entrypoint. This prevents an
/// unfinished foundation from returning a misleading `ALLOW` or `DENY` record.
pub fn evaluation_unavailable() -> Problem {
    Problem::new(ProblemCode::FeatureUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{ReplayKey, evaluation_unavailable};
    use fenrua_protocol::ProblemCode;

    #[test]
    fn evaluation_is_explicitly_unavailable_at_r1() {
        assert_eq!(
            evaluation_unavailable().code(),
            ProblemCode::FeatureUnavailable
        );
    }

    #[test]
    fn opaque_replay_key_is_bounded() {
        let oversized = "x".repeat(513);
        let error = match ReplayKey::new(oversized) {
            Ok(_) => panic!("oversized key must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::InvalidArgument);
    }
}
