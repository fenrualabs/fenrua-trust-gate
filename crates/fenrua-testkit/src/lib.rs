//! Deterministic, test-only foundations. These types are not an operational
//! replay service, clock source, or a substitute for a production replay design.

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
    use fenrua_c14n::{
        DigestDomain, canonical_document_in_domain, canonical_document_without_top_level_member,
    };
    use fenrua_gate::{EvaluationInput, ReplayCheckpoint, ReplayKey, ReplayState, evaluate};
    use fenrua_protocol::{JsonValue, ParseLimits, R2DocumentKind, parse_json, parse_r2_document};
    use fenrua_verify::verify_local_evaluation;

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

    fn document(source: &str, kind: R2DocumentKind) -> fenrua_protocol::R2Document {
        match parse_r2_document(source.as_bytes(), kind) {
            Ok(document) => document,
            Err(error) => panic!("R2 fixture must parse: {error}"),
        }
    }

    fn signed_document(mut value: JsonValue, kind: R2DocumentKind) -> fenrua_protocol::R2Document {
        resign_local_unsigned(&mut value);
        let bytes =
            match canonical_document_in_domain(&value, DigestDomain::CanonicalJsonR2Prototype) {
                Ok(document) => document.bytes().to_vec(),
                Err(error) => panic!("test document must serialize: {error}"),
            };
        match parse_r2_document(&bytes, kind) {
            Ok(document) => document,
            Err(error) => panic!("test document must validate: {error}"),
        }
    }

    fn policy_with_expiry(expires_at: &str) -> fenrua_protocol::R2Document {
        let mut policy = match parse_json(
            include_str!("../../../fixtures/r2/policy-allow.json").as_bytes(),
            ParseLimits::R1_FOUNDATION,
        ) {
            Ok(value) => value,
            Err(error) => panic!("policy fixture must parse: {error}"),
        };
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        fields.insert(
            "expiresAt".to_owned(),
            JsonValue::String(expires_at.to_owned()),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn local_input(request: &str) -> EvaluationInput {
        match EvaluationInput::new(
            document(
                include_str!("../../../fixtures/r2/manifest.json"),
                R2DocumentKind::EntityManifest,
            ),
            document(
                include_str!("../../../fixtures/r2/policy-allow.json"),
                R2DocumentKind::AuthorityPolicy,
            ),
            document(request, R2DocumentKind::ToolCallRequest),
            document(
                include_str!("../../../fixtures/r2/revocations-current.json"),
                R2DocumentKind::RevocationSet,
            ),
            "2026-07-14T00:01:00.000Z".to_owned(),
        ) {
            Ok(input) => input,
            Err(error) => panic!("R2 input must construct: {error}"),
        }
    }

    fn local_input_with_policy_at(
        policy: fenrua_protocol::R2Document,
        evaluation_at: &str,
    ) -> EvaluationInput {
        match EvaluationInput::new(
            document(
                include_str!("../../../fixtures/r2/manifest.json"),
                R2DocumentKind::EntityManifest,
            ),
            policy,
            document(
                include_str!("../../../fixtures/r2/request-offline.json"),
                R2DocumentKind::ToolCallRequest,
            ),
            document(
                include_str!("../../../fixtures/r2/revocations-current.json"),
                R2DocumentKind::RevocationSet,
            ),
            evaluation_at.to_owned(),
        ) {
            Ok(input) => input,
            Err(error) => panic!("R2 input must construct: {error}"),
        }
    }

    fn decision(value: &JsonValue) -> String {
        let JsonValue::Object(envelope) = value else {
            panic!("evaluation artifact must be an object");
        };
        let Some(JsonValue::Object(document)) = envelope.get("decision") else {
            panic!("evaluation artifact must contain a decision object");
        };
        let Some(JsonValue::String(value)) = document.get("decision") else {
            panic!("decision value must be a string");
        };
        value.clone()
    }

    fn resign_local_unsigned(document: &mut JsonValue) {
        let digest = match canonical_document_without_top_level_member(
            document,
            "signature",
            DigestDomain::LocalUnsignedPayloadR2Prototype,
        ) {
            Ok(document) => document.digest(),
            Err(error) => panic!("tampered document must canonicalize: {error}"),
        };
        let JsonValue::Object(fields) = document else {
            panic!("tampered document must be an object");
        };
        let Some(JsonValue::Object(signature)) = fields.get_mut("signature") else {
            panic!("tampered document must have a signature object");
        };
        let Some(JsonValue::Object(payload_digest)) = signature.get_mut("payloadDigest") else {
            panic!("tampered document must have a payload digest object");
        };
        payload_digest.insert("value".to_owned(), JsonValue::String(digest.to_hex()));
    }

    #[test]
    fn independently_verifies_gate_output_and_detects_tampering() {
        let artifact = match evaluate(&local_input(include_str!(
            "../../../fixtures/r2/request-offline.json"
        ))) {
            Ok(artifact) => artifact,
            Err(error) => panic!("R2 allow fixture must evaluate: {error}"),
        };
        assert_eq!(decision(artifact.value()), "ALLOW");
        let report = match verify_local_evaluation(artifact.value()) {
            Ok(report) => report,
            Err(error) => panic!("separate verifier must inspect gate output: {error}"),
        };
        assert!(report.integrity_verified());

        let mut tampered = artifact.into_value();
        let JsonValue::Object(envelope) = &mut tampered else {
            panic!("evaluation artifact must be an object");
        };
        let Some(JsonValue::Object(document)) = envelope.get_mut("decision") else {
            panic!("evaluation artifact must contain a mutable decision object");
        };
        document.insert("decision".to_owned(), JsonValue::String("DENY".to_owned()));
        let report = match verify_local_evaluation(&tampered) {
            Ok(report) => report,
            Err(error) => {
                panic!("tampered structural envelope must still receive a report: {error}")
            }
        };
        assert!(!report.integrity_verified());
    }

    #[test]
    fn independently_verifies_an_expired_policy_denial_envelope() {
        let expires_at = "2026-07-14T00:00:30.000Z";
        let artifact = match evaluate(&local_input_with_policy_at(
            policy_with_expiry(expires_at),
            expires_at,
        )) {
            Ok(artifact) => artifact,
            Err(error) => panic!("expired policy must emit an R2 denial envelope: {error}"),
        };
        assert_eq!(decision(artifact.value()), "DENY");
        let report = match verify_local_evaluation(artifact.value()) {
            Ok(report) => report,
            Err(error) => panic!("separate verifier must inspect expired-policy denial: {error}"),
        };
        assert!(report.integrity_verified());
    }

    #[test]
    fn verifier_rejects_a_re_digested_receipt_that_conflicts_with_the_decision() {
        let artifact = match evaluate(&local_input(include_str!(
            "../../../fixtures/r2/request-offline.json"
        ))) {
            Ok(artifact) => artifact,
            Err(error) => panic!("R2 allow fixture must evaluate: {error}"),
        };
        let mut tampered = artifact.into_value();
        let JsonValue::Object(envelope) = &mut tampered else {
            panic!("evaluation artifact must be an object");
        };
        let Some(JsonValue::Object(receipt)) = envelope.get_mut("receipt") else {
            panic!("evaluation artifact must contain a mutable receipt object");
        };
        receipt.insert("decision".to_owned(), JsonValue::String("DENY".to_owned()));
        let mut receipt_value = JsonValue::Object(receipt.clone());
        resign_local_unsigned(&mut receipt_value);
        let JsonValue::Object(updated_receipt) = receipt_value else {
            panic!("re-signed receipt must remain an object");
        };
        *receipt = updated_receipt;
        let report = match verify_local_evaluation(&tampered) {
            Ok(report) => report,
            Err(error) => panic!("tampered envelope must receive a report: {error}"),
        };
        assert!(!report.integrity_verified());
    }

    #[test]
    fn closed_profile_rejects_a_foreign_decision_profile() {
        let artifact = match evaluate(&local_input(include_str!(
            "../../../fixtures/r2/request-offline.json"
        ))) {
            Ok(artifact) => artifact,
            Err(error) => panic!("R2 allow fixture must evaluate: {error}"),
        };
        let mut tampered = artifact.into_value();
        let JsonValue::Object(envelope) = &mut tampered else {
            panic!("evaluation artifact must be an object");
        };
        let Some(JsonValue::Object(decision)) = envelope.get_mut("decision") else {
            panic!("evaluation artifact must contain a mutable decision object");
        };
        decision.insert(
            "profileId".to_owned(),
            JsonValue::String("urn:fenrua:compatibility-profile:foreign".to_owned()),
        );
        let result = verify_local_evaluation(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn replay_sensitive_fixture_is_deterministically_denied() {
        let artifact = match evaluate(&local_input(include_str!(
            "../../../fixtures/r2/request-replay-required.json"
        ))) {
            Ok(artifact) => artifact,
            Err(error) => panic!("R2 replay fixture must evaluate: {error}"),
        };
        assert_eq!(decision(artifact.value()), "DENY");
        let report = match verify_local_evaluation(artifact.value()) {
            Ok(report) => report,
            Err(error) => panic!("separate verifier must inspect denial evidence: {error}"),
        };
        assert!(report.integrity_verified());
    }
}
