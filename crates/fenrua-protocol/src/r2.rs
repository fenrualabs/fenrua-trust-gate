//! Strict, local-only R2 prototype admission for a pinned subset of the
//! Fenrua v0.1 schemas.
//!
//! This module does not implement a general JSON Schema engine. It accepts the
//! smallest closed subset required by the R2 local-unsigned workflow and fails
//! closed for every other schema feature. The normative registry remains in the
//! separately governed `fenrua-specs` repository.

use std::collections::{BTreeMap, BTreeSet};

use crate::{JsonValue, ParseLimits, Problem, ProblemCode, parse_json};

pub const R2_LOCAL_SPECS_REPOSITORY: &str = "https://github.com/fenrualabs/fenrua-specs";
pub const R2_LOCAL_SPECS_COMMIT: &str = "268788e18bb39d69ffed706294d2605878f04c34";
pub const R2_LOCAL_SCHEMA_PIN: &str = "fenrua-specs/v0.1@268788e18bb39d69ffed706294d2605878f04c34";
pub const R2_LOCAL_PROFILE_ID: &str = "urn:fenrua:compatibility-profile:local-unsigned-r2";
pub const LOCAL_UNSIGNED_PROFILE: &str = "local-unsigned-development";
pub const LOCAL_UNSIGNED_KEY_ID: &str = "urn:fenrua:key:local-unsigned-development";
pub const R2_EVALUATION_ENVELOPE_SCHEMA: &str = "fenrua.local-evaluation.r2-draft";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2DocumentKind {
    EntityManifest,
    AuthorityPolicy,
    ToolCallRequest,
    RevocationSet,
    Decision,
    EvidenceBundle,
    Receipt,
    VerificationResult,
    EvaluationEnvelope,
}

impl R2DocumentKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::EntityManifest => "entity-manifest",
            Self::AuthorityPolicy => "authority-policy",
            Self::ToolCallRequest => "tool-call-request",
            Self::RevocationSet => "revocation-set",
            Self::Decision => "decision",
            Self::EvidenceBundle => "evidence-bundle",
            Self::Receipt => "receipt",
            Self::VerificationResult => "verification-result",
            Self::EvaluationEnvelope => "local-evaluation-envelope",
        }
    }

    pub const fn schema_version(self) -> &'static str {
        match self {
            Self::EntityManifest => "fenrua.entity-manifest.v1",
            Self::AuthorityPolicy => "fenrua.authority-policy.v1",
            Self::ToolCallRequest => "fenrua.tool-call-request.v1",
            Self::RevocationSet => "fenrua.revocation-set.v1",
            Self::Decision => "fenrua.decision.v1",
            Self::EvidenceBundle => "fenrua.evidence-bundle.v1",
            Self::Receipt => "fenrua.receipt.v1",
            Self::VerificationResult => "fenrua.verification-result.v1",
            Self::EvaluationEnvelope => R2_EVALUATION_ENVELOPE_SCHEMA,
        }
    }

    pub const fn schema_id(self) -> Option<&'static str> {
        match self {
            Self::EntityManifest => Some("urn:fenrua:schema:entity-manifest-v1"),
            Self::AuthorityPolicy => Some("urn:fenrua:schema:authority-policy-v1"),
            Self::ToolCallRequest => Some("urn:fenrua:schema:tool-call-request-v1"),
            Self::RevocationSet => Some("urn:fenrua:schema:revocation-set-v1"),
            Self::Decision => Some("urn:fenrua:schema:decision-v1"),
            Self::EvidenceBundle => Some("urn:fenrua:schema:evidence-bundle-v1"),
            Self::Receipt => Some("urn:fenrua:schema:receipt-v1"),
            Self::VerificationResult => Some("urn:fenrua:schema:verification-result-v1"),
            Self::EvaluationEnvelope => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2Document {
    kind: R2DocumentKind,
    value: JsonValue,
}

impl R2Document {
    pub const fn kind(&self) -> R2DocumentKind {
        self.kind
    }

    pub const fn value(&self) -> &JsonValue {
        &self.value
    }

    pub fn into_value(self) -> JsonValue {
        self.value
    }
}

pub fn parse_r2_document(input: &[u8], kind: R2DocumentKind) -> Result<R2Document, Problem> {
    let value = parse_json(input, ParseLimits::R1_FOUNDATION)?;
    validate_r2_document(kind, &value)?;
    Ok(R2Document { kind, value })
}

pub fn validate_r2_document(kind: R2DocumentKind, value: &JsonValue) -> Result<(), Problem> {
    match kind {
        R2DocumentKind::EntityManifest => validate_manifest(value),
        R2DocumentKind::AuthorityPolicy => validate_policy(value),
        R2DocumentKind::ToolCallRequest => validate_request(value),
        R2DocumentKind::RevocationSet => validate_revocation_set(value),
        R2DocumentKind::Decision => validate_decision(value),
        R2DocumentKind::EvidenceBundle => validate_evidence_bundle(value),
        R2DocumentKind::Receipt => validate_receipt(value),
        R2DocumentKind::VerificationResult => validate_verification_result(value),
        R2DocumentKind::EvaluationEnvelope => validate_evaluation_envelope(value),
    }
}

pub fn object_fields(value: &JsonValue) -> Result<&BTreeMap<String, JsonValue>, Problem> {
    match value {
        JsonValue::Object(fields) => Ok(fields),
        _ => Err(schema_error()),
    }
}

pub fn array_items(value: &JsonValue) -> Result<&[JsonValue], Problem> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(schema_error()),
    }
}

pub fn string_value(value: &JsonValue) -> Result<&str, Problem> {
    match value {
        JsonValue::String(value) => Ok(value),
        _ => Err(schema_error()),
    }
}

pub fn bool_value(value: &JsonValue) -> Result<bool, Problem> {
    match value {
        JsonValue::Bool(value) => Ok(*value),
        _ => Err(schema_error()),
    }
}

pub fn required_field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a JsonValue, Problem> {
    object.get(name).ok_or_else(schema_error)
}

pub fn optional_field<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Option<&'a JsonValue> {
    object.get(name)
}

pub fn validate_r2_timestamp(value: &str) -> Result<(), Problem> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return Err(Problem::new(ProblemCode::InvalidTimestamp));
    }
    for index in [
        0_usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22,
    ] {
        if !bytes[index].is_ascii_digit() {
            return Err(Problem::new(ProblemCode::InvalidTimestamp));
        }
    }
    let year = decimal(&bytes[0..4])?;
    let month = decimal(&bytes[5..7])?;
    let day = decimal(&bytes[8..10])?;
    let hour = decimal(&bytes[11..13])?;
    let minute = decimal(&bytes[14..16])?;
    let second = decimal(&bytes[17..19])?;
    let _millisecond = decimal(&bytes[20..23])?;
    if year == 0 || month == 0 || month > 12 || hour > 23 || minute > 59 || second > 59 {
        return Err(Problem::new(ProblemCode::InvalidTimestamp));
    }
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return Err(Problem::new(ProblemCode::InvalidTimestamp)),
    };
    if day == 0 || day > maximum_day {
        return Err(Problem::new(ProblemCode::InvalidTimestamp));
    }
    Ok(())
}

fn validate_manifest(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::EntityManifest,
        &[
            "schemaVersion",
            "manifestId",
            "subjectId",
            "ownerId",
            "scope",
            "entityType",
            "lifecycle",
            "revision",
            "issuedAt",
            "expiresAt",
            "integrity",
            "evidenceRefs",
            "signature",
        ],
        &[
            "displayName",
            "declaredCapabilities",
            "artifacts",
            "dataClassification",
            "supersedes",
        ],
    )?;
    urn(
        required_string(object, "manifestId")?,
        "urn:fenrua:entity-manifest:",
    )?;
    urn(required_string(object, "subjectId")?, "urn:fenrua:entity:")?;
    identifier(required_string(object, "ownerId")?)?;
    validate_scope(required_field(object, "scope")?)?;
    one_of(
        required_string(object, "entityType")?,
        &[
            "organisation",
            "operator",
            "workload",
            "agent",
            "model",
            "tool",
            "artifact",
            "deployment",
        ],
    )?;
    lifecycle(required_string(object, "lifecycle")?)?;
    revision(required_string(object, "revision")?)?;
    timestamp_field(object, "issuedAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "issuedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    validate_digest(required_field(object, "integrity")?)?;
    evidence_references(required_field(object, "evidenceRefs")?)?;
    validate_local_unsigned_signature(required_field(object, "signature")?)?;
    if let Some(value) = optional_field(object, "displayName") {
        short_text(string_value(value)?)?;
    }
    if let Some(value) = optional_field(object, "declaredCapabilities") {
        let items = nonempty_array(value, 64)?;
        for item in items {
            action(string_value(item)?)?;
        }
    }
    if let Some(value) = optional_field(object, "artifacts") {
        let items = array_bounded(value, 64)?;
        for item in items {
            validate_artifact(item)?;
        }
    }
    if let Some(value) = optional_field(object, "dataClassification") {
        one_of(
            string_value(value)?,
            &["public", "internal", "confidential", "restricted"],
        )?;
    }
    if let Some(value) = optional_field(object, "supersedes") {
        urn(string_value(value)?, "urn:fenrua:entity-manifest:")?;
    }
    Ok(())
}

fn validate_policy(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::AuthorityPolicy,
        &[
            "schemaVersion",
            "policyId",
            "scope",
            "revision",
            "lifecycle",
            "issuerId",
            "issuedAt",
            "effectiveAt",
            "expiresAt",
            "rules",
            "integrity",
            "evidenceRefs",
            "signature",
        ],
        &["supersedes"],
    )?;
    urn(required_string(object, "policyId")?, "urn:fenrua:policy:")?;
    validate_scope(required_field(object, "scope")?)?;
    revision(required_string(object, "revision")?)?;
    lifecycle(required_string(object, "lifecycle")?)?;
    identifier(required_string(object, "issuerId")?)?;
    timestamp_field(object, "issuedAt")?;
    timestamp_field(object, "effectiveAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "issuedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    ordered_time(
        required_string(object, "effectiveAt")?,
        required_string(object, "expiresAt")?,
    )?;
    let rules = nonempty_array(required_field(object, "rules")?, 256)?;
    let mut rule_ids = BTreeSet::new();
    for rule in rules {
        let rule_id = validate_rule(rule)?;
        if !rule_ids.insert(rule_id.to_owned()) {
            return Err(schema_error());
        }
    }
    validate_digest(required_field(object, "integrity")?)?;
    evidence_references(required_field(object, "evidenceRefs")?)?;
    validate_local_unsigned_signature(required_field(object, "signature")?)?;
    if let Some(value) = optional_field(object, "supersedes") {
        urn(string_value(value)?, "urn:fenrua:policy:")?;
    }
    Ok(())
}

fn validate_request(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::ToolCallRequest,
        &[
            "schemaVersion",
            "requestId",
            "scope",
            "subjectId",
            "actorId",
            "action",
            "resource",
            "context",
            "issuedAt",
            "expiresAt",
            "nonce",
            "replayRequired",
            "payloadDigest",
            "signature",
        ],
        &["artifact"],
    )?;
    urn(
        required_string(object, "requestId")?,
        "urn:fenrua:tool-call-request:",
    )?;
    validate_scope(required_field(object, "scope")?)?;
    urn(required_string(object, "subjectId")?, "urn:fenrua:entity:")?;
    identifier(required_string(object, "actorId")?)?;
    action(required_string(object, "action")?)?;
    resource(required_string(object, "resource")?)?;
    validate_context(required_field(object, "context")?)?;
    timestamp_field(object, "issuedAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "issuedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    base64url(required_string(object, "nonce")?)?;
    bool_value(required_field(object, "replayRequired")?)?;
    validate_digest(required_field(object, "payloadDigest")?)?;
    validate_local_unsigned_signature(required_field(object, "signature")?)?;
    if let Some(value) = optional_field(object, "artifact") {
        validate_artifact(value)?;
    }
    Ok(())
}

fn validate_revocation_set(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::RevocationSet,
        &[
            "schemaVersion",
            "revocationSetId",
            "scope",
            "sequence",
            "issuerId",
            "issuedAt",
            "effectiveAt",
            "expiresAt",
            "nextUpdateAt",
            "revocations",
            "integrity",
            "signature",
        ],
        &[],
    )?;
    urn(
        required_string(object, "revocationSetId")?,
        "urn:fenrua:revocation-set:",
    )?;
    validate_scope(required_field(object, "scope")?)?;
    revision(required_string(object, "sequence")?)?;
    identifier(required_string(object, "issuerId")?)?;
    for field in ["issuedAt", "effectiveAt", "expiresAt", "nextUpdateAt"] {
        timestamp_field(object, field)?;
    }
    ordered_time(
        required_string(object, "issuedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    ordered_time(
        required_string(object, "effectiveAt")?,
        required_string(object, "expiresAt")?,
    )?;
    let revocations = array_bounded(required_field(object, "revocations")?, 4_096)?;
    let mut revocation_ids = BTreeSet::new();
    for revocation in revocations {
        let id = validate_revocation(revocation)?;
        if !revocation_ids.insert(id.to_owned()) {
            return Err(schema_error());
        }
    }
    validate_digest(required_field(object, "integrity")?)?;
    validate_local_unsigned_signature(required_field(object, "signature")?)?;
    Ok(())
}

fn validate_decision(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::Decision,
        &[
            "schemaVersion",
            "decisionId",
            "scope",
            "profileId",
            "decision",
            "verificationState",
            "reasonCodes",
            "subjectId",
            "actorId",
            "action",
            "resource",
            "policyId",
            "policyRevision",
            "requestDigest",
            "evidenceBundleId",
            "issuedAt",
            "expiresAt",
            "limitations",
        ],
        &["signature"],
    )?;
    urn(
        required_string(object, "decisionId")?,
        "urn:fenrua:decision:",
    )?;
    validate_scope(required_field(object, "scope")?)?;
    if required_string(object, "profileId")? != R2_LOCAL_PROFILE_ID {
        return Err(Problem::new(ProblemCode::UnsupportedProfile));
    }
    one_of(required_string(object, "decision")?, &["ALLOW", "DENY"])?;
    verification_state(required_string(object, "verificationState")?)?;
    reason_codes(required_field(object, "reasonCodes")?)?;
    urn(required_string(object, "subjectId")?, "urn:fenrua:entity:")?;
    identifier(required_string(object, "actorId")?)?;
    action(required_string(object, "action")?)?;
    resource(required_string(object, "resource")?)?;
    urn(required_string(object, "policyId")?, "urn:fenrua:policy:")?;
    revision(required_string(object, "policyRevision")?)?;
    validate_digest(required_field(object, "requestDigest")?)?;
    urn(
        required_string(object, "evidenceBundleId")?,
        "urn:fenrua:evidence-bundle:",
    )?;
    timestamp_field(object, "issuedAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "issuedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    limitations(required_field(object, "limitations")?)?;
    if let Some(signature) = optional_field(object, "signature") {
        validate_local_unsigned_signature(signature)?;
    }
    Ok(())
}

fn validate_evidence_bundle(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::EvidenceBundle,
        &[
            "schemaVersion",
            "bundleId",
            "tenantScope",
            "environment",
            "subject",
            "actor",
            "request",
            "policy",
            "decision",
            "approvals",
            "integrity",
            "revocation",
            "runtime",
            "inputs",
            "outputs",
            "events",
            "limitations",
            "createdAt",
            "expiresAt",
            "producer",
            "producerVersion",
            "signatureProfile",
            "keyId",
            "signature",
        ],
        &[],
    )?;
    urn(
        required_string(object, "bundleId")?,
        "urn:fenrua:evidence-bundle:",
    )?;
    urn(
        required_string(object, "tenantScope")?,
        "urn:fenrua:tenant:",
    )?;
    urn(
        required_string(object, "environment")?,
        "urn:fenrua:environment:",
    )?;
    urn(required_string(object, "subject")?, "urn:fenrua:entity:")?;
    identifier(required_string(object, "actor")?)?;
    validate_document_ref(required_field(object, "request")?)?;
    validate_policy_ref(required_field(object, "policy")?)?;
    validate_decision_ref(required_field(object, "decision")?)?;
    for field in ["approvals", "integrity", "inputs", "outputs", "events"] {
        array_bounded(required_field(object, field)?, 128)?;
    }
    validate_revocation_ref(required_field(object, "revocation")?)?;
    validate_runtime_ref(required_field(object, "runtime")?)?;
    limitations(required_field(object, "limitations")?)?;
    timestamp_field(object, "createdAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "createdAt")?,
        required_string(object, "expiresAt")?,
    )?;
    identifier(required_string(object, "producer")?)?;
    semver(required_string(object, "producerVersion")?)?;
    if required_string(object, "signatureProfile")? != LOCAL_UNSIGNED_PROFILE
        || required_string(object, "keyId")? != LOCAL_UNSIGNED_KEY_ID
    {
        return Err(Problem::new(ProblemCode::UnsupportedProfile));
    }
    validate_local_unsigned_signature(required_field(object, "signature")?)?;
    Ok(())
}

fn validate_receipt(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::Receipt,
        &[
            "schemaVersion",
            "receiptId",
            "bundleId",
            "decisionId",
            "decision",
            "subjectId",
            "actorId",
            "action",
            "resource",
            "reasonCodes",
            "issuedAt",
            "expiresAt",
            "bundleDigest",
            "summary",
            "limitations",
            "signature",
        ],
        &[],
    )?;
    urn(required_string(object, "receiptId")?, "urn:fenrua:receipt:")?;
    urn(
        required_string(object, "bundleId")?,
        "urn:fenrua:evidence-bundle:",
    )?;
    urn(
        required_string(object, "decisionId")?,
        "urn:fenrua:decision:",
    )?;
    one_of(required_string(object, "decision")?, &["ALLOW", "DENY"])?;
    urn(required_string(object, "subjectId")?, "urn:fenrua:entity:")?;
    identifier(required_string(object, "actorId")?)?;
    action(required_string(object, "action")?)?;
    resource(required_string(object, "resource")?)?;
    reason_codes(required_field(object, "reasonCodes")?)?;
    timestamp_field(object, "issuedAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "issuedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    validate_digest(required_field(object, "bundleDigest")?)?;
    long_text(required_string(object, "summary")?)?;
    limitations(required_field(object, "limitations")?)?;
    validate_local_unsigned_signature(required_field(object, "signature")?)?;
    Ok(())
}

fn validate_verification_result(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::VerificationResult,
        &[
            "schemaVersion",
            "verificationId",
            "scope",
            "target",
            "verifier",
            "verificationState",
            "findings",
            "checkedAt",
            "expiresAt",
            "inputDigest",
            "evidenceDigest",
            "limitations",
            "signature",
        ],
        &[],
    )?;
    urn(
        required_string(object, "verificationId")?,
        "urn:fenrua:verification:",
    )?;
    validate_scope(required_field(object, "scope")?)?;
    validate_evidence_reference(required_field(object, "target")?)?;
    validate_verifier(required_field(object, "verifier")?)?;
    verification_state(required_string(object, "verificationState")?)?;
    let findings = array_bounded(required_field(object, "findings")?, 64)?;
    for finding in findings {
        validate_finding(finding)?;
    }
    timestamp_field(object, "checkedAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "checkedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    validate_digest(required_field(object, "inputDigest")?)?;
    validate_digest(required_field(object, "evidenceDigest")?)?;
    limitations(required_field(object, "limitations")?)?;
    validate_local_unsigned_signature(required_field(object, "signature")?)?;
    Ok(())
}

fn validate_evaluation_envelope(value: &JsonValue) -> Result<(), Problem> {
    let object = root(
        value,
        R2DocumentKind::EvaluationEnvelope,
        &[
            "schemaVersion",
            "evaluationAt",
            "decision",
            "evidenceBundle",
            "receipt",
        ],
        &[],
    )?;
    timestamp_field(object, "evaluationAt")?;
    validate_decision(required_field(object, "decision")?)?;
    validate_evidence_bundle(required_field(object, "evidenceBundle")?)?;
    validate_receipt(required_field(object, "receipt")?)?;
    Ok(())
}

fn validate_rule(value: &JsonValue) -> Result<&str, Problem> {
    let object = object_fields(value)?;
    exact_fields(
        object,
        &[
            "ruleId",
            "effect",
            "subjectSelector",
            "actorSelector",
            "actions",
            "resources",
            "scope",
            "reasonCode",
        ],
        &[
            "timeWindow",
            "requiredIntegrityDigests",
            "requiredEvidence",
            "requiredApprovals",
        ],
    )?;
    let rule_id = required_string(object, "ruleId")?;
    urn(rule_id, "urn:fenrua:rule:")?;
    one_of(required_string(object, "effect")?, &["ALLOW", "DENY"])?;
    validate_selector(required_field(object, "subjectSelector")?)?;
    validate_selector(required_field(object, "actorSelector")?)?;
    for field in ["actions", "resources"] {
        let items = nonempty_array(required_field(object, field)?, 64)?;
        for item in items {
            if field == "actions" {
                action(string_value(item)?)?;
            } else {
                resource(string_value(item)?)?;
            }
        }
    }
    validate_scope(required_field(object, "scope")?)?;
    reason_code(required_string(object, "reasonCode")?)?;
    if let Some(value) = optional_field(object, "timeWindow") {
        validate_time_window(value)?;
    }
    if let Some(value) = optional_field(object, "requiredIntegrityDigests") {
        let items = array_bounded(value, 32)?;
        for item in items {
            validate_digest(item)?;
        }
    }
    if let Some(value) = optional_field(object, "requiredEvidence") {
        let items = array_bounded(value, 32)?;
        for item in items {
            token(string_value(item)?)?;
        }
    }
    if let Some(value) = optional_field(object, "requiredApprovals") {
        let items = array_bounded(value, 16)?;
        for item in items {
            validate_approval_requirement(item)?;
        }
    }
    Ok(rule_id)
}

fn validate_scope(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["tenantId", "environmentId"], &[])?;
    urn(required_string(object, "tenantId")?, "urn:fenrua:tenant:")?;
    urn(
        required_string(object, "environmentId")?,
        "urn:fenrua:environment:",
    )?;
    Ok(())
}

fn validate_selector(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["ids"], &[])?;
    let ids = nonempty_array(required_field(object, "ids")?, 64)?;
    let mut values = BTreeSet::new();
    for id in ids {
        let id = string_value(id)?;
        identifier(id)?;
        if !values.insert(id) {
            return Err(schema_error());
        }
    }
    Ok(())
}

fn validate_context(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["contextId", "audience", "bindings"], &[])?;
    identifier(required_string(object, "contextId")?)?;
    identifier(required_string(object, "audience")?)?;
    let bindings = nonempty_array(required_field(object, "bindings")?, 32)?;
    let mut keys = BTreeSet::new();
    for binding in bindings {
        let object = object_fields(binding)?;
        exact_fields(object, &["key", "value"], &[])?;
        let key = required_string(object, "key")?;
        token(key)?;
        short_text(required_string(object, "value")?)?;
        if !keys.insert(key) {
            return Err(schema_error());
        }
    }
    Ok(())
}

fn validate_artifact(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(
        object,
        &[
            "artifactId",
            "scope",
            "revision",
            "digest",
            "effectiveAt",
            "evidenceRefs",
        ],
        &[],
    )?;
    urn(
        required_string(object, "artifactId")?,
        "urn:fenrua:artifact:",
    )?;
    validate_scope(required_field(object, "scope")?)?;
    revision(required_string(object, "revision")?)?;
    validate_digest(required_field(object, "digest")?)?;
    timestamp_field(object, "effectiveAt")?;
    evidence_references(required_field(object, "evidenceRefs")?)?;
    Ok(())
}

fn validate_policy_ref(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(
        object,
        &[
            "policyId",
            "scope",
            "revision",
            "digest",
            "effectiveAt",
            "evidenceRefs",
        ],
        &[],
    )?;
    urn(required_string(object, "policyId")?, "urn:fenrua:policy:")?;
    validate_scope(required_field(object, "scope")?)?;
    revision(required_string(object, "revision")?)?;
    validate_digest(required_field(object, "digest")?)?;
    timestamp_field(object, "effectiveAt")?;
    evidence_references(required_field(object, "evidenceRefs")?)?;
    Ok(())
}

fn validate_decision_ref(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["decisionId", "digest", "issuedAt"], &[])?;
    urn(
        required_string(object, "decisionId")?,
        "urn:fenrua:decision:",
    )?;
    validate_digest(required_field(object, "digest")?)?;
    timestamp_field(object, "issuedAt")
}

fn validate_document_ref(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["documentId", "schemaId", "digest"], &[])?;
    identifier(required_string(object, "documentId")?)?;
    schema_id(required_string(object, "schemaId")?)?;
    validate_digest(required_field(object, "digest")?)
}

fn validate_revocation_ref(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(
        object,
        &[
            "revocationSetId",
            "scope",
            "sequence",
            "issuedAt",
            "expiresAt",
            "digest",
        ],
        &[],
    )?;
    urn(
        required_string(object, "revocationSetId")?,
        "urn:fenrua:revocation-set:",
    )?;
    validate_scope(required_field(object, "scope")?)?;
    revision(required_string(object, "sequence")?)?;
    timestamp_field(object, "issuedAt")?;
    timestamp_field(object, "expiresAt")?;
    ordered_time(
        required_string(object, "issuedAt")?,
        required_string(object, "expiresAt")?,
    )?;
    validate_digest(required_field(object, "digest")?)
}

fn validate_runtime_ref(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["runtimeId", "profile", "digest"], &[])?;
    identifier(required_string(object, "runtimeId")?)?;
    token(required_string(object, "profile")?)?;
    validate_digest(required_field(object, "digest")?)
}

fn validate_evidence_reference(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["evidenceBundleId", "digest", "createdAt"], &[])?;
    urn(
        required_string(object, "evidenceBundleId")?,
        "urn:fenrua:evidence-bundle:",
    )?;
    validate_digest(required_field(object, "digest")?)?;
    timestamp_field(object, "createdAt")
}

fn evidence_references(value: &JsonValue) -> Result<(), Problem> {
    let references = nonempty_array(value, 32)?;
    for reference in references {
        validate_evidence_reference(reference)?;
    }
    Ok(())
}

fn validate_time_window(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["notBefore", "notAfter"], &[])?;
    let not_before = required_string(object, "notBefore")?;
    let not_after = required_string(object, "notAfter")?;
    validate_r2_timestamp(not_before)?;
    validate_r2_timestamp(not_after)?;
    ordered_time(not_before, not_after)
}

fn validate_approval_requirement(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["approvalType", "minimumCount"], &[])?;
    token(required_string(object, "approvalType")?)?;
    match required_field(object, "minimumCount")? {
        JsonValue::Number(number) => {
            let count = match number.lexeme().parse::<u8>() {
                Ok(count) => count,
                Err(_) => return Err(schema_error()),
            };
            if (1..=16).contains(&count) {
                Ok(())
            } else {
                Err(schema_error())
            }
        }
        _ => Err(schema_error()),
    }
}

fn validate_revocation(value: &JsonValue) -> Result<&str, Problem> {
    let object = object_fields(value)?;
    exact_fields(
        object,
        &[
            "revocationId",
            "targetId",
            "targetType",
            "reasonCode",
            "effectiveAt",
            "evidenceRefs",
        ],
        &[],
    )?;
    let id = required_string(object, "revocationId")?;
    urn(id, "urn:fenrua:revocation:")?;
    identifier(required_string(object, "targetId")?)?;
    one_of(
        required_string(object, "targetType")?,
        &[
            "policy", "subject", "artifact", "key", "approval", "request",
        ],
    )?;
    reason_code(required_string(object, "reasonCode")?)?;
    timestamp_field(object, "effectiveAt")?;
    evidence_references(required_field(object, "evidenceRefs")?)?;
    Ok(id)
}

fn validate_verifier(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["verifierId", "version", "profile"], &[])?;
    identifier(required_string(object, "verifierId")?)?;
    semver(required_string(object, "version")?)?;
    if required_string(object, "profile")? != LOCAL_UNSIGNED_PROFILE {
        return Err(Problem::new(ProblemCode::UnsupportedProfile));
    }
    Ok(())
}

fn validate_finding(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["code", "severity", "message"], &["documentId"])?;
    finding_code(required_string(object, "code")?)?;
    one_of(
        required_string(object, "severity")?,
        &["critical", "high", "medium", "low", "info"],
    )?;
    short_text(required_string(object, "message")?)?;
    if let Some(value) = optional_field(object, "documentId") {
        identifier(string_value(value)?)?;
    }
    Ok(())
}

fn validate_digest(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["algorithm", "value"], &[])?;
    if required_string(object, "algorithm")? != "sha-256" {
        return Err(Problem::new(ProblemCode::InvalidDigest));
    }
    hex_digest(required_string(object, "value")?)
}

fn validate_local_unsigned_signature(value: &JsonValue) -> Result<(), Problem> {
    let object = object_fields(value)?;
    exact_fields(object, &["profile", "keyId", "payloadDigest"], &[])?;
    if required_string(object, "profile")? != LOCAL_UNSIGNED_PROFILE
        || required_string(object, "keyId")? != LOCAL_UNSIGNED_KEY_ID
    {
        return Err(Problem::new(ProblemCode::UnsupportedProfile));
    }
    validate_digest(required_field(object, "payloadDigest")?)
}

fn root<'a>(
    value: &'a JsonValue,
    kind: R2DocumentKind,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a BTreeMap<String, JsonValue>, Problem> {
    let object = object_fields(value)?;
    exact_fields(object, required, optional)?;
    if required_string(object, "schemaVersion")? != kind.schema_version() {
        return Err(Problem::new(ProblemCode::UnsupportedSchema));
    }
    Ok(object)
}

fn exact_fields(
    object: &BTreeMap<String, JsonValue>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), Problem> {
    for name in required {
        if !object.contains_key(*name) {
            return Err(schema_error());
        }
    }
    for name in object.keys() {
        if !required.contains(&name.as_str()) && !optional.contains(&name.as_str()) {
            return Err(schema_error());
        }
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, Problem> {
    string_value(required_field(object, name)?)
}

fn timestamp_field(object: &BTreeMap<String, JsonValue>, name: &str) -> Result<(), Problem> {
    validate_r2_timestamp(required_string(object, name)?)
}

fn ordered_time(start: &str, end: &str) -> Result<(), Problem> {
    if start >= end {
        return Err(Problem::new(ProblemCode::InvalidTimestamp));
    }
    Ok(())
}

fn nonempty_array(value: &JsonValue, maximum: usize) -> Result<&[JsonValue], Problem> {
    let values = array_bounded(value, maximum)?;
    if values.is_empty() {
        return Err(schema_error());
    }
    Ok(values)
}

fn array_bounded(value: &JsonValue, maximum: usize) -> Result<&[JsonValue], Problem> {
    let values = array_items(value)?;
    if values.len() > maximum {
        return Err(schema_error());
    }
    Ok(values)
}

fn identifier(value: &str) -> Result<(), Problem> {
    if !value.starts_with("urn:fenrua:") || value.len() > 160 {
        return Err(schema_error());
    }
    let segments = value.split(':').collect::<Vec<_>>();
    if segments.len() != 4 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(schema_error());
    }
    if !segments[2].bytes().all(is_lower_token_byte)
        || !segments[3].bytes().all(is_lower_token_byte)
    {
        return Err(schema_error());
    }
    Ok(())
}

fn urn(value: &str, prefix: &str) -> Result<(), Problem> {
    if !value.starts_with(prefix)
        || value.len() <= prefix.len()
        || value.len() > prefix.len().saturating_add(96)
    {
        return Err(schema_error());
    }
    if !value[prefix.len()..].bytes().all(is_lower_token_byte) {
        return Err(schema_error());
    }
    Ok(())
}

fn is_lower_token_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

fn revision(value: &str) -> Result<(), Problem> {
    if value.is_empty()
        || value.len() > 9
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(schema_error());
    }
    Ok(())
}

fn action(value: &str) -> Result<(), Problem> {
    if value.len() < 3
        || value.len() > 96
        || value.split('.').count() < 2
        || value.split('.').count() > 3
    {
        return Err(schema_error());
    }
    for segment in value.split('.') {
        if segment.is_empty() || segment.len() > 32 || !segment.bytes().all(is_lower_token_byte) {
            return Err(schema_error());
        }
    }
    Ok(())
}

fn resource(value: &str) -> Result<(), Problem> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(schema_error());
    }
    Ok(())
}

fn token(value: &str) -> Result<(), Problem> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(is_lower_token_byte)
        || !value.as_bytes()[0].is_ascii_lowercase()
    {
        return Err(schema_error());
    }
    Ok(())
}

fn base64url(value: &str) -> Result<(), Problem> {
    if value.len() < 8
        || value.len() > 4_096
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(schema_error());
    }
    Ok(())
}

fn short_text(value: &str) -> Result<(), Problem> {
    text(value, 256)
}

fn long_text(value: &str) -> Result<(), Problem> {
    text(value, 2_048)
}

fn text(value: &str, maximum: usize) -> Result<(), Problem> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|character| character.is_control() || character == '\u{007f}')
    {
        return Err(schema_error());
    }
    Ok(())
}

fn lifecycle(value: &str) -> Result<(), Problem> {
    one_of(
        value,
        &["draft", "active", "superseded", "retired", "revoked"],
    )
}

fn reason_code(value: &str) -> Result<(), Problem> {
    one_of(
        value,
        &[
            "ALLOW_POLICY_MATCH",
            "DENY_EXPLICIT",
            "DENY_NO_MATCH",
            "DENY_MISSING_IDENTITY",
            "DENY_INVALID_IDENTITY",
            "DENY_SIGNATURE_INVALID",
            "DENY_POLICY_EXPIRED",
            "DENY_POLICY_REVOKED",
            "DENY_SUBJECT_REVOKED",
            "DENY_ARTIFACT_REVOKED",
            "DENY_KEY_REVOKED",
            "DENY_STALE_REVOCATION_STATE",
            "DENY_AUDIENCE_MISMATCH",
            "DENY_CONTEXT_MISMATCH",
            "DENY_INTEGRITY_MISMATCH",
            "DENY_MISSING_APPROVAL",
            "DENY_UNSUPPORTED_SCHEMA",
            "DENY_AMBIGUOUS_POLICY",
            "DENY_REPLAY",
            "DENY_UNSUPPORTED_ENVIRONMENT",
            "DENY_FAIL_CLOSED",
        ],
    )
}

fn reason_codes(value: &JsonValue) -> Result<(), Problem> {
    let values = nonempty_array(value, 32)?;
    let mut unique = BTreeSet::new();
    for value in values {
        let value = string_value(value)?;
        reason_code(value)?;
        if !unique.insert(value) {
            return Err(schema_error());
        }
    }
    Ok(())
}

fn verification_state(value: &str) -> Result<(), Problem> {
    one_of(
        value,
        &[
            "PASS",
            "PASS_WITH_LIMITATIONS",
            "INCOMPLETE",
            "STALE",
            "POLICY_VIOLATION",
            "INTEGRITY_MISMATCH",
            "SIGNATURE_INVALID",
            "RUNTIME_UNVERIFIED",
            "REVOKED",
            "FAIL_CLOSED",
            "UNSUPPORTED_SCHEMA",
            "ERROR",
        ],
    )
}

fn limitations(value: &JsonValue) -> Result<(), Problem> {
    let values = array_bounded(value, 32)?;
    for value in values {
        text(string_value(value)?, 256)?;
    }
    Ok(())
}

fn semver(value: &str) -> Result<(), Problem> {
    let core = value.split_once('-').map_or(value, |(core, _)| core);
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 9
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(schema_error());
    }
    Ok(())
}

fn finding_code(value: &str) -> Result<(), Problem> {
    if value.len() < 3
        || value.len() > 80
        || !value.as_bytes()[0].is_ascii_uppercase()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(schema_error());
    }
    Ok(())
}

fn schema_id(value: &str) -> Result<(), Problem> {
    if !matches!(
        value,
        "urn:fenrua:schema:entity-manifest-v1"
            | "urn:fenrua:schema:authority-policy-v1"
            | "urn:fenrua:schema:tool-call-request-v1"
            | "urn:fenrua:schema:revocation-set-v1"
            | "urn:fenrua:schema:decision-v1"
            | "urn:fenrua:schema:evidence-bundle-v1"
            | "urn:fenrua:schema:receipt-v1"
            | "urn:fenrua:schema:verification-result-v1"
    ) {
        return Err(Problem::new(ProblemCode::UnsupportedSchema));
    }
    Ok(())
}

fn hex_digest(value: &str) -> Result<(), Problem> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Problem::new(ProblemCode::InvalidDigest));
    }
    Ok(())
}

fn one_of(value: &str, values: &[&str]) -> Result<(), Problem> {
    if values.contains(&value) {
        Ok(())
    } else {
        Err(schema_error())
    }
}

fn decimal(bytes: &[u8]) -> Result<u32, Problem> {
    let mut value = 0_u32;
    for byte in bytes {
        let digit = byte
            .checked_sub(b'0')
            .ok_or_else(|| Problem::new(ProblemCode::InvalidTimestamp))?;
        if digit > 9 {
            return Err(Problem::new(ProblemCode::InvalidTimestamp));
        }
        value = value.saturating_mul(10).saturating_add(u32::from(digit));
    }
    Ok(value)
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn schema_error() -> Problem {
    Problem::new(ProblemCode::SchemaValidationFailed)
}

#[cfg(test)]
mod tests {
    use super::{R2DocumentKind, parse_r2_document, validate_r2_timestamp};
    use crate::ProblemCode;

    #[test]
    fn timestamp_validation_rejects_impossible_dates() {
        assert!(validate_r2_timestamp("2028-02-29T12:00:00.000Z").is_ok());
        assert!(validate_r2_timestamp("2027-02-29T12:00:00.000Z").is_err());
        assert!(validate_r2_timestamp("2026-07-14T24:00:00.000Z").is_err());
    }

    #[test]
    fn r2_rejects_unknown_fields_even_when_the_schema_version_matches() {
        let source = br#"{
          "schemaVersion":"fenrua.tool-call-request.v1",
          "requestId":"urn:fenrua:tool-call-request:demo-001",
          "scope":{"tenantId":"urn:fenrua:tenant:demo","environmentId":"urn:fenrua:environment:development"},
          "subjectId":"urn:fenrua:entity:demo-agent",
          "actorId":"urn:fenrua:actor:demo-operator",
          "action":"tool.execute",
          "resource":"artifact:demo-build",
          "context":{"contextId":"urn:fenrua:context:demo-request","audience":"urn:fenrua:audience:demo-tool","bindings":[{"key":"purpose","value":"fixture"}]},
          "issuedAt":"2026-07-14T00:00:00.000Z",
          "expiresAt":"2026-07-14T00:05:00.000Z",
          "nonce":"fixture_nonce_0001",
          "replayRequired":false,
          "payloadDigest":{"algorithm":"sha-256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
          "signature":{"profile":"local-unsigned-development","keyId":"urn:fenrua:key:local-unsigned-development","payloadDigest":{"algorithm":"sha-256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
          "unrecognised":true
        }"#;
        let error = match parse_r2_document(source, R2DocumentKind::ToolCallRequest) {
            Ok(_) => panic!("unknown field must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::SchemaValidationFailed);
    }
}
