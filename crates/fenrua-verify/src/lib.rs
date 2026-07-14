//! Separate local evidence-verification boundary for R2.
//!
//! This crate deliberately has no dependency on `fenrua-gate`. It consumes a
//! strict R2 local evaluation envelope, recomputes its canonical digests and
//! relationships, and emits a structured verification result with explicit
//! local-unsigned limitations.

use std::collections::BTreeMap;

use fenrua_c14n::{
    Digest, DigestDomain, canonical_document, canonical_document_in_domain,
    canonical_document_without_top_level_member,
};
use fenrua_protocol::{
    JsonValue, LOCAL_UNSIGNED_KEY_ID, LOCAL_UNSIGNED_PROFILE, Problem, ProblemCode, R2DocumentKind,
    array_items, object_fields, required_field, string_value, validate_r2_document,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrityVerification {
    Match,
    Mismatch,
}

/// Compares a canonical JSON digest without interpreting a Trust Gate schema.
pub fn verify_canonical_digest(
    value: &JsonValue,
    expected: Digest,
) -> Result<IntegrityVerification, Problem> {
    let actual = canonical_document(value)?.digest();
    Ok(if actual == expected {
        IntegrityVerification::Match
    } else {
        IntegrityVerification::Mismatch
    })
}

/// Structured result from independently inspecting one R2 local envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    result: JsonValue,
    integrity_verified: bool,
}

impl VerificationReport {
    pub const fn result(&self) -> &JsonValue {
        &self.result
    }

    pub const fn integrity_verified(&self) -> bool {
        self.integrity_verified
    }

    pub fn into_result(self) -> JsonValue {
        self.result
    }
}

/// Verifies the evidence relationships and local payload digests in a strict
/// R2 evaluation envelope. The `checkedAt` value is the envelope's declared
/// deterministic evaluation instant, not a wall-clock observation claim.
pub fn verify_local_evaluation(value: &JsonValue) -> Result<VerificationReport, Problem> {
    validate_r2_document(R2DocumentKind::EvaluationEnvelope, value)?;
    let envelope = object_fields(value)?;
    let checked_at = field_string(envelope, "evaluationAt")?.to_owned();
    let decision = required_field(envelope, "decision")?;
    let evidence = required_field(envelope, "evidenceBundle")?;
    let receipt = required_field(envelope, "receipt")?;

    let envelope_digest = document_digest(value)?;
    let evidence_digest = document_digest(evidence)?;
    let mut findings = Vec::new();
    let mut verified = true;

    for (label, document) in [
        ("DECISION", decision),
        ("EVIDENCE_BUNDLE", evidence),
        ("RECEIPT", receipt),
    ] {
        if !local_unsigned_signature_matches(document)? {
            verified = false;
            findings.push(finding(
                "INTEGRITY_MISMATCH",
                "high",
                &format!("{label} local payload digest does not match canonical content."),
            ));
        }
    }

    if !links_match(decision, evidence, receipt, &checked_at, evidence_digest)? {
        verified = false;
        findings.push(finding(
            "EVIDENCE_LINK_MISMATCH",
            "high",
            "Decision, evidence, receipt, or timestamp references do not agree.",
        ));
    }

    if verified {
        findings.push(finding(
            "LOCAL_UNSIGNED_PROFILE",
            "info",
            "The local-unsigned profile provides no signer authentication.",
        ));
        findings.push(finding(
            "R2_PROTOTYPE_LIMITATION",
            "info",
            "This verification checks deterministic local evidence relationships only.",
        ));
    }

    let state = if verified {
        "PASS_WITH_LIMITATIONS"
    } else {
        "INTEGRITY_MISMATCH"
    };
    let limitations = if verified {
        vec![
            "The local-unsigned profile does not authenticate signer identity.".to_owned(),
            "This verifier does not claim independent assurance, key custody, or execution authority.".to_owned(),
        ]
    } else {
        vec![
            "Integrity verification failed; this result does not authorise execution.".to_owned(),
            "The local-unsigned profile does not authenticate signer identity.".to_owned(),
        ]
    };
    let result = signed_document(build_result(VerificationResultInput {
        decision,
        evidence,
        checked_at: &checked_at,
        envelope_digest,
        evidence_digest,
        verification_state: state,
        findings,
        limitations,
    })?)?;
    validate_r2_document(R2DocumentKind::VerificationResult, &result)?;
    Ok(VerificationReport {
        result,
        integrity_verified: verified,
    })
}

fn links_match(
    decision: &JsonValue,
    evidence: &JsonValue,
    receipt: &JsonValue,
    checked_at: &str,
    evidence_digest: Digest,
) -> Result<bool, Problem> {
    let decision_fields = object_fields(decision)?;
    let evidence_fields = object_fields(evidence)?;
    let receipt_fields = object_fields(receipt)?;
    let decision_id = field_string(decision_fields, "decisionId")?;
    let bundle_id = field_string(evidence_fields, "bundleId")?;
    let decision_scope = object_fields(required_field(decision_fields, "scope")?)?;
    let evidence_policy = object_fields(required_field(evidence_fields, "policy")?)?;
    let evidence_request = object_fields(required_field(evidence_fields, "request")?)?;
    let evidence_revocation = object_fields(required_field(evidence_fields, "revocation")?)?;
    let decision_reference = object_fields(required_field(evidence_fields, "decision")?)?;
    let receipt_digest = digest_hex(required_field(receipt_fields, "bundleDigest")?)?;
    let evidence_decision_digest = digest_hex(required_field(decision_reference, "digest")?)?;
    let decision_digest = document_digest(decision)?;
    let decision_digest_hex = decision_digest.to_hex();
    let evidence_digest_hex = evidence_digest.to_hex();
    let mut decision_is_listed = false;
    for output in array_items(required_field(evidence_fields, "outputs")?)? {
        let output = object_fields(output)?;
        if field_string(output, "documentId")? == decision_id
            && field_string(output, "schemaId")? == "urn:fenrua:schema:decision-v1"
            && digest_hex(required_field(output, "digest")?)? == decision_digest_hex.as_str()
        {
            decision_is_listed = true;
        }
    }
    Ok(
        field_string(decision_fields, "evidenceBundleId")? == bundle_id
            && field_string(receipt_fields, "bundleId")? == bundle_id
            && field_string(receipt_fields, "decisionId")? == decision_id
            && field_string(decision_reference, "decisionId")? == decision_id
            && evidence_decision_digest == decision_digest_hex.as_str()
            && receipt_digest == evidence_digest_hex.as_str()
            && field_string(decision_fields, "issuedAt")? == checked_at
            && field_string(evidence_fields, "createdAt")? == checked_at
            && field_string(receipt_fields, "issuedAt")? == checked_at
            && field_string(decision_fields, "decision")?
                == field_string(receipt_fields, "decision")?
            && field_string(decision_fields, "subjectId")?
                == field_string(evidence_fields, "subject")?
            && field_string(decision_fields, "subjectId")?
                == field_string(receipt_fields, "subjectId")?
            && field_string(decision_fields, "actorId")? == field_string(evidence_fields, "actor")?
            && field_string(decision_fields, "actorId")?
                == field_string(receipt_fields, "actorId")?
            && field_string(decision_fields, "action")? == field_string(receipt_fields, "action")?
            && field_string(decision_fields, "resource")?
                == field_string(receipt_fields, "resource")?
            && field_string(decision_fields, "policyId")?
                == field_string(evidence_policy, "policyId")?
            && field_string(decision_fields, "policyRevision")?
                == field_string(evidence_policy, "revision")?
            && digest_hex(required_field(decision_fields, "requestDigest")?)?
                == digest_hex(required_field(evidence_request, "digest")?)?
            && field_string(decision_scope, "tenantId")?
                == field_string(evidence_fields, "tenantScope")?
            && field_string(decision_scope, "environmentId")?
                == field_string(evidence_fields, "environment")?
            && field_string(decision_scope, "tenantId")?
                == field_string(
                    object_fields(required_field(evidence_policy, "scope")?)?,
                    "tenantId",
                )?
            && field_string(decision_scope, "environmentId")?
                == field_string(
                    object_fields(required_field(evidence_policy, "scope")?)?,
                    "environmentId",
                )?
            && field_string(decision_scope, "tenantId")?
                == field_string(
                    object_fields(required_field(evidence_revocation, "scope")?)?,
                    "tenantId",
                )?
            && field_string(decision_scope, "environmentId")?
                == field_string(
                    object_fields(required_field(evidence_revocation, "scope")?)?,
                    "environmentId",
                )?
            && field_string(decision_fields, "expiresAt")?
                == field_string(evidence_fields, "expiresAt")?
            && field_string(decision_fields, "expiresAt")?
                == field_string(receipt_fields, "expiresAt")?
            && decision_is_listed,
    )
}

struct VerificationResultInput<'a> {
    decision: &'a JsonValue,
    evidence: &'a JsonValue,
    checked_at: &'a str,
    envelope_digest: Digest,
    evidence_digest: Digest,
    verification_state: &'a str,
    findings: Vec<JsonValue>,
    limitations: Vec<String>,
}

fn build_result(input: VerificationResultInput<'_>) -> Result<JsonValue, Problem> {
    let decision_fields = object_fields(input.decision)?;
    let evidence_fields = object_fields(input.evidence)?;
    let scope = required_field(decision_fields, "scope")?.clone();
    let target = object([
        (
            "evidenceBundleId",
            text(field_string(evidence_fields, "bundleId")?),
        ),
        ("digest", digest_json(input.evidence_digest)),
        (
            "createdAt",
            text(field_string(evidence_fields, "createdAt")?),
        ),
    ]);
    let verification_id = derived_id("urn:fenrua:verification:r2-", input.envelope_digest);
    Ok(object([
        ("schemaVersion", text("fenrua.verification-result.v1")),
        ("verificationId", text(&verification_id)),
        ("scope", scope),
        ("target", target),
        (
            "verifier",
            object([
                (
                    "verifierId",
                    text("urn:fenrua:verifier:local-r2-independent"),
                ),
                ("version", text(env!("CARGO_PKG_VERSION"))),
                ("profile", text(LOCAL_UNSIGNED_PROFILE)),
            ]),
        ),
        ("verificationState", text(input.verification_state)),
        ("findings", JsonValue::Array(input.findings)),
        ("checkedAt", text(input.checked_at)),
        (
            "expiresAt",
            text(field_string(decision_fields, "expiresAt")?),
        ),
        // The v1 field names the verifier's input; in R2 that input is the
        // complete submitted evaluation envelope, not the original request.
        ("inputDigest", digest_json(input.envelope_digest)),
        ("evidenceDigest", digest_json(input.evidence_digest)),
        ("limitations", strings(&input.limitations)),
    ]))
}

fn local_unsigned_signature_matches(value: &JsonValue) -> Result<bool, Problem> {
    let fields = object_fields(value)?;
    let signature = object_fields(required_field(fields, "signature")?)?;
    if field_string(signature, "profile")? != LOCAL_UNSIGNED_PROFILE
        || field_string(signature, "keyId")? != LOCAL_UNSIGNED_KEY_ID
    {
        return Ok(false);
    }
    let expected = Digest::from_hex(digest_hex(required_field(signature, "payloadDigest")?)?)?;
    let actual = canonical_document_without_top_level_member(
        value,
        "signature",
        DigestDomain::LocalUnsignedPayloadR2Prototype,
    )?
    .digest();
    Ok(actual == expected)
}

fn signed_document(value: JsonValue) -> Result<JsonValue, Problem> {
    let mut fields = match value {
        JsonValue::Object(fields) => fields,
        _ => return Err(Problem::new(ProblemCode::InvalidArgument)),
    };
    let payload = JsonValue::Object(fields.clone());
    let digest =
        canonical_document_in_domain(&payload, DigestDomain::LocalUnsignedPayloadR2Prototype)?
            .digest();
    fields.insert(
        "signature".to_owned(),
        object([
            ("profile", text(LOCAL_UNSIGNED_PROFILE)),
            ("keyId", text(LOCAL_UNSIGNED_KEY_ID)),
            ("payloadDigest", digest_json(digest)),
        ]),
    );
    Ok(JsonValue::Object(fields))
}

fn document_digest(value: &JsonValue) -> Result<Digest, Problem> {
    Ok(canonical_document_in_domain(value, DigestDomain::CanonicalJsonR2Prototype)?.digest())
}

fn digest_hex(value: &JsonValue) -> Result<&str, Problem> {
    let fields = object_fields(value)?;
    field_string(fields, "value")
}

fn field_string<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, Problem> {
    string_value(required_field(fields, name)?)
}

fn derived_id(prefix: &str, digest: Digest) -> String {
    let encoded = digest.to_hex();
    format!("{prefix}{}", &encoded[..24])
}

fn finding(code: &str, severity: &str, message: &str) -> JsonValue {
    object([
        ("code", text(code)),
        ("severity", text(severity)),
        ("message", text(message)),
    ])
}

fn digest_json(digest: Digest) -> JsonValue {
    object([
        ("algorithm", text("sha-256")),
        ("value", text(&digest.to_hex())),
    ])
}

fn strings(values: &[String]) -> JsonValue {
    JsonValue::Array(values.iter().map(|value| text(value)).collect())
}

fn text(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}

fn object<const N: usize>(entries: [(&str, JsonValue); N]) -> JsonValue {
    let mut fields = BTreeMap::new();
    for (name, value) in entries {
        fields.insert(name.to_owned(), value);
    }
    JsonValue::Object(fields)
}

#[cfg(test)]
mod tests {
    use fenrua_protocol::{JsonValue, ParseLimits, parse_json};

    use super::{
        IntegrityVerification, local_unsigned_signature_matches, object, text,
        verify_canonical_digest,
    };

    #[test]
    fn generic_integrity_check_detects_a_changed_document() {
        let original = match parse_json(br#"{"a":1}"#, ParseLimits::R1_FOUNDATION) {
            Ok(value) => value,
            Err(error) => panic!("original fixture must parse: {error}"),
        };
        let changed = match parse_json(br#"{"a":2}"#, ParseLimits::R1_FOUNDATION) {
            Ok(value) => value,
            Err(error) => panic!("changed fixture must parse: {error}"),
        };
        let digest = match fenrua_c14n::canonical_document(&original) {
            Ok(document) => document.digest(),
            Err(error) => panic!("original fixture must canonicalize: {error}"),
        };
        let result = match verify_canonical_digest(&changed, digest) {
            Ok(result) => result,
            Err(error) => panic!("changed fixture must canonicalize: {error}"),
        };
        assert_eq!(result, IntegrityVerification::Mismatch);
    }

    #[test]
    fn local_unsigned_check_rejects_a_mutated_payload() {
        let unsigned = object([("value", text("original"))]);
        let digest = match fenrua_c14n::canonical_document_in_domain(
            &unsigned,
            fenrua_c14n::DigestDomain::LocalUnsignedPayloadR2Prototype,
        ) {
            Ok(document) => document.digest(),
            Err(error) => panic!("fixture payload must digest: {error}"),
        };
        let mut fields = match unsigned {
            JsonValue::Object(fields) => fields,
            _ => panic!("fixture must be an object"),
        };
        fields.insert(
            "signature".to_owned(),
            object([
                ("profile", text("local-unsigned-development")),
                ("keyId", text("urn:fenrua:key:local-unsigned-development")),
                (
                    "payloadDigest",
                    object([
                        ("algorithm", text("sha-256")),
                        ("value", text(&digest.to_hex())),
                    ]),
                ),
            ]),
        );
        let signed = JsonValue::Object(fields.clone());
        assert!(matches!(
            local_unsigned_signature_matches(&signed),
            Ok(true)
        ));
        fields.insert("value".to_owned(), text("mutated"));
        assert!(matches!(
            local_unsigned_signature_matches(&JsonValue::Object(fields)),
            Ok(false)
        ));
    }
}
