//! Deterministic, local-only R2 Trust Gate prototype.
//!
//! The evaluator admits only the pinned, local-unsigned subset defined by
//! `fenrua-protocol`. It has no network, key operation, durable replay store,
//! policy distribution client, or execution adapter. An `ALLOW` is a local
//! prototype decision record, never an instruction to execute an action.

use std::collections::{BTreeMap, BTreeSet};

use fenrua_c14n::{
    Digest, DigestDomain, canonical_document_in_domain,
    canonical_document_without_top_level_member, domain_separated_digest,
};
use fenrua_protocol::{
    JsonValue, LOCAL_UNSIGNED_KEY_ID, LOCAL_UNSIGNED_PROFILE, Problem, ProblemCode,
    R2_LOCAL_PROFILE_ID, R2Document, R2DocumentKind, array_items, bool_value, object_fields,
    optional_field, required_field, string_value, validate_r2_document, validate_r2_timestamp,
};

/// An opaque, bounded replay identity. R2 keeps the interface so callers can
/// model replay state in tests, but it does not claim durable replay control.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayState {
    Fresh,
    ExistingIdempotent,
    Replayed,
    Unavailable,
}

pub trait ReplayCheckpoint {
    fn check(&self, key: &ReplayKey) -> ReplayState;
}

/// Inputs for one deterministic local evaluation. The caller supplies the
/// evaluation instant explicitly; no wall clock or random identifier is read.
#[derive(Clone, Debug)]
pub struct EvaluationInput {
    manifest: R2Document,
    policy: R2Document,
    request: R2Document,
    revocations: R2Document,
    evaluation_at: String,
}

impl EvaluationInput {
    pub fn new(
        manifest: R2Document,
        policy: R2Document,
        request: R2Document,
        revocations: R2Document,
        evaluation_at: String,
    ) -> Result<Self, Problem> {
        if manifest.kind() != R2DocumentKind::EntityManifest
            || policy.kind() != R2DocumentKind::AuthorityPolicy
            || request.kind() != R2DocumentKind::ToolCallRequest
            || revocations.kind() != R2DocumentKind::RevocationSet
        {
            return Err(Problem::new(ProblemCode::InvalidArgument));
        }
        validate_r2_timestamp(&evaluation_at)?;
        Ok(Self {
            manifest,
            policy,
            request,
            revocations,
            evaluation_at,
        })
    }

    pub fn evaluation_at(&self) -> &str {
        &self.evaluation_at
    }
}

/// A local R2 envelope containing a decision, evidence bundle, and receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationArtifact {
    value: JsonValue,
}

impl EvaluationArtifact {
    pub const fn value(&self) -> &JsonValue {
        &self.value
    }

    pub fn into_value(self) -> JsonValue {
        self.value
    }
}

/// Applies the R2 prototype policy subset and emits canonical local evidence.
pub fn evaluate(input: &EvaluationInput) -> Result<EvaluationArtifact, Problem> {
    let values = EvaluationValues::from_input(input)?;
    let plan = evaluate_plan(&values);
    let seed = evaluation_seed(&values)?;
    let decision_id = derived_id("urn:fenrua:decision:r2-", seed);
    let bundle_id = derived_id("urn:fenrua:evidence-bundle:r2-", seed);
    let receipt_id = derived_id("urn:fenrua:receipt:r2-", seed);

    let decision = signed_document(build_decision(&values, &plan, &decision_id, &bundle_id)?)?;
    let decision_digest = document_digest(&decision)?;
    let evidence = signed_document(build_evidence(
        &values,
        &plan,
        &seed,
        &decision,
        &decision_digest,
        &bundle_id,
    )?)?;
    let evidence_digest = document_digest(&evidence)?;
    let receipt = signed_document(build_receipt(
        &values,
        &plan,
        &decision_id,
        &bundle_id,
        &receipt_id,
        &evidence_digest,
    )?)?;

    let value = object([
        ("schemaVersion", text("fenrua.local-evaluation.r2-draft")),
        ("evaluationAt", text(&values.evaluation_at)),
        ("decision", decision),
        ("evidenceBundle", evidence),
        ("receipt", receipt),
    ]);
    validate_r2_document(R2DocumentKind::EvaluationEnvelope, &value)?;
    Ok(EvaluationArtifact { value })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    tenant_id: String,
    environment_id: String,
}

impl Scope {
    fn from_value(value: &JsonValue) -> Result<Self, Problem> {
        let fields = object_fields(value)?;
        Ok(Self {
            tenant_id: field_string(fields, "tenantId")?.to_owned(),
            environment_id: field_string(fields, "environmentId")?.to_owned(),
        })
    }

    fn json(&self) -> JsonValue {
        object([
            ("tenantId", text(&self.tenant_id)),
            ("environmentId", text(&self.environment_id)),
        ])
    }
}

#[derive(Clone, Debug)]
struct ManifestValues {
    id: String,
    subject_id: String,
    owner_id: String,
    scope: Scope,
    lifecycle: String,
    issued_at: String,
    expires_at: String,
    declared_capabilities: BTreeSet<String>,
    artifacts: BTreeMap<String, JsonValue>,
    digest: Digest,
}

#[derive(Clone, Debug)]
struct RuleValues {
    effect: String,
    subject_ids: BTreeSet<String>,
    actor_ids: BTreeSet<String>,
    actions: BTreeSet<String>,
    resources: BTreeSet<String>,
    scope: Scope,
    time_window: Option<(String, String)>,
    required_integrity: BTreeSet<String>,
    requires_evidence: bool,
    requires_approvals: bool,
    reason_code: String,
}

#[derive(Clone, Debug)]
struct PolicyValues {
    id: String,
    issuer_id: String,
    scope: Scope,
    revision: String,
    lifecycle: String,
    issued_at: String,
    effective_at: String,
    expires_at: String,
    rules: Vec<RuleValues>,
    evidence_refs: JsonValue,
    digest: Digest,
}

#[derive(Clone, Debug)]
struct RequestValues {
    id: String,
    scope: Scope,
    subject_id: String,
    actor_id: String,
    action: String,
    resource: String,
    issued_at: String,
    expires_at: String,
    replay_required: bool,
    payload_digest: String,
    artifact: Option<JsonValue>,
    artifact_ids: BTreeSet<String>,
    artifact_digests: BTreeSet<String>,
    digest: Digest,
}

#[derive(Clone, Debug)]
struct RevocationValues {
    id: String,
    sequence: String,
    issuer_id: String,
    scope: Scope,
    issued_at: String,
    effective_at: String,
    expires_at: String,
    next_update_at: String,
    entries: Vec<RevocationEntry>,
    digest: Digest,
}

#[derive(Clone, Debug)]
struct RevocationEntry {
    target_id: String,
    target_type: String,
    effective_at: String,
}

#[derive(Clone, Debug)]
struct EvaluationValues {
    manifest: ManifestValues,
    policy: PolicyValues,
    request: RequestValues,
    revocations: RevocationValues,
    input_signatures_valid: bool,
    evaluation_at: String,
}

impl EvaluationValues {
    fn from_input(input: &EvaluationInput) -> Result<Self, Problem> {
        let mut input_signatures_valid = true;
        for document in [
            &input.manifest,
            &input.policy,
            &input.request,
            &input.revocations,
        ] {
            input_signatures_valid &= local_unsigned_signature_matches(document.value())?;
        }
        Ok(Self {
            manifest: parse_manifest(&input.manifest)?,
            policy: parse_policy(&input.policy)?,
            request: parse_request(&input.request)?,
            revocations: parse_revocations(&input.revocations)?,
            input_signatures_valid,
            evaluation_at: input.evaluation_at.clone(),
        })
    }
}

#[derive(Clone, Debug)]
struct DecisionPlan {
    decision: &'static str,
    verification_state: &'static str,
    reason_codes: BTreeSet<String>,
    limitations: Vec<String>,
}

fn evaluate_plan(values: &EvaluationValues) -> DecisionPlan {
    if !values.input_signatures_valid {
        return deny("DENY_SIGNATURE_INVALID", "INTEGRITY_MISMATCH");
    }
    if values.manifest.owner_id != values.policy.issuer_id
        || values.policy.issuer_id != values.revocations.issuer_id
    {
        return deny("DENY_INVALID_IDENTITY", "FAIL_CLOSED");
    }
    if values.manifest.scope != values.request.scope
        || values.policy.scope != values.request.scope
        || values.revocations.scope != values.request.scope
    {
        return deny("DENY_UNSUPPORTED_ENVIRONMENT", "FAIL_CLOSED");
    }
    if !active_at(
        &values.manifest.issued_at,
        &values.manifest.expires_at,
        &values.evaluation_at,
    ) || values.manifest.lifecycle != "active"
    {
        return deny("DENY_INVALID_IDENTITY", "FAIL_CLOSED");
    }
    if values.manifest.subject_id != values.request.subject_id {
        return deny("DENY_MISSING_IDENTITY", "FAIL_CLOSED");
    }
    if values.manifest.declared_capabilities.is_empty()
        || !values
            .manifest
            .declared_capabilities
            .contains(&values.request.action)
    {
        return deny("DENY_INVALID_IDENTITY", "FAIL_CLOSED");
    }
    if !active_at(
        &values.policy.effective_at,
        &values.policy.expires_at,
        &values.evaluation_at,
    ) || values.policy.lifecycle != "active"
    {
        return deny("DENY_POLICY_EXPIRED", "STALE");
    }
    if values.evaluation_at < values.policy.issued_at {
        return deny("DENY_FAIL_CLOSED", "FAIL_CLOSED");
    }
    if !active_at(
        &values.request.issued_at,
        &values.request.expires_at,
        &values.evaluation_at,
    ) {
        return deny("DENY_FAIL_CLOSED", "STALE");
    }
    if !active_at(
        &values.revocations.effective_at,
        &values.revocations.expires_at,
        &values.evaluation_at,
    ) || values.evaluation_at >= values.revocations.next_update_at
    {
        return deny("DENY_STALE_REVOCATION_STATE", "STALE");
    }
    if values.evaluation_at < values.revocations.issued_at {
        return deny("DENY_STALE_REVOCATION_STATE", "STALE");
    }
    if values.request.replay_required {
        return deny("DENY_REPLAY", "FAIL_CLOSED");
    }
    if let Some(plan) = revocation_denial(values) {
        return plan;
    }
    if let Some(artifact) = &values.request.artifact {
        let artifact_fields = match object_fields(artifact) {
            Ok(fields) => fields,
            Err(_) => return deny("DENY_INTEGRITY_MISMATCH", "INTEGRITY_MISMATCH"),
        };
        let artifact_id = match field_string(artifact_fields, "artifactId") {
            Ok(value) => value,
            Err(_) => return deny("DENY_INTEGRITY_MISMATCH", "INTEGRITY_MISMATCH"),
        };
        let Some(declared_artifact) = values.manifest.artifacts.get(artifact_id) else {
            return deny("DENY_INTEGRITY_MISMATCH", "INTEGRITY_MISMATCH");
        };
        let effective_at = match field_string(artifact_fields, "effectiveAt") {
            Ok(value) => value,
            Err(_) => return deny("DENY_INTEGRITY_MISMATCH", "INTEGRITY_MISMATCH"),
        };
        if declared_artifact != artifact || effective_at > values.evaluation_at.as_str() {
            return deny("DENY_INTEGRITY_MISMATCH", "INTEGRITY_MISMATCH");
        }
    }

    let mut explicit_denies = BTreeSet::new();
    let mut matching_allows = BTreeSet::new();
    let mut integrity_missing = false;
    let mut evidence_unavailable = false;
    let mut approvals_unavailable = false;
    let mut unresolved_deny = false;
    let mut ambiguous = false;

    for rule in &values.policy.rules {
        if !rule_base_matches(rule, values) {
            continue;
        }
        if rule.effect == "ALLOW" && rule.reason_code != "ALLOW_POLICY_MATCH" {
            ambiguous = true;
            continue;
        }
        if rule.effect == "DENY" && !rule.reason_code.starts_with("DENY_") {
            ambiguous = true;
            continue;
        }
        if rule.requires_evidence {
            evidence_unavailable = true;
        }
        if rule.requires_approvals {
            approvals_unavailable = true;
        }
        if rule.requires_evidence || rule.requires_approvals {
            if rule.effect == "DENY" {
                unresolved_deny = true;
            }
            continue;
        }
        if !integrity_matches(rule, values) {
            integrity_missing = true;
            continue;
        }
        if rule.effect == "DENY" {
            explicit_denies.insert("DENY_EXPLICIT".to_owned());
            explicit_denies.insert(rule.reason_code.clone());
        } else {
            matching_allows.insert("ALLOW_POLICY_MATCH".to_owned());
        }
    }

    if ambiguous {
        return deny("DENY_AMBIGUOUS_POLICY", "FAIL_CLOSED");
    }
    if unresolved_deny {
        return deny("DENY_FAIL_CLOSED", "FAIL_CLOSED");
    }
    if !explicit_denies.is_empty() {
        return DecisionPlan {
            decision: "DENY",
            verification_state: "POLICY_VIOLATION",
            reason_codes: explicit_denies,
            limitations: limitations(),
        };
    }
    if !matching_allows.is_empty() {
        return DecisionPlan {
            decision: "ALLOW",
            verification_state: "PASS_WITH_LIMITATIONS",
            reason_codes: matching_allows,
            limitations: limitations(),
        };
    }
    if approvals_unavailable {
        return deny("DENY_MISSING_APPROVAL", "FAIL_CLOSED");
    }
    if evidence_unavailable {
        return deny("DENY_FAIL_CLOSED", "FAIL_CLOSED");
    }
    if integrity_missing {
        return deny("DENY_INTEGRITY_MISMATCH", "INTEGRITY_MISMATCH");
    }
    deny("DENY_NO_MATCH", "POLICY_VIOLATION")
}

fn revocation_denial(values: &EvaluationValues) -> Option<DecisionPlan> {
    for entry in &values.revocations.entries {
        if entry.effective_at > values.evaluation_at {
            continue;
        }
        let reason = match entry.target_type.as_str() {
            "policy" if entry.target_id == values.policy.id => "DENY_POLICY_REVOKED",
            "subject" if entry.target_id == values.manifest.subject_id => "DENY_SUBJECT_REVOKED",
            "artifact" if values.request.artifact_ids.contains(&entry.target_id) => {
                "DENY_ARTIFACT_REVOKED"
            }
            "key" if entry.target_id == LOCAL_UNSIGNED_KEY_ID => "DENY_KEY_REVOKED",
            "request" if entry.target_id == values.request.id => "DENY_FAIL_CLOSED",
            _ => continue,
        };
        return Some(deny(reason, "REVOKED"));
    }
    None
}

fn rule_base_matches(rule: &RuleValues, values: &EvaluationValues) -> bool {
    if rule.scope != values.request.scope
        || !rule.subject_ids.contains(&values.request.subject_id)
        || !rule.actor_ids.contains(&values.request.actor_id)
        || !rule.actions.contains(&values.request.action)
        || !rule.resources.contains(&values.request.resource)
    {
        return false;
    }
    match &rule.time_window {
        Some((not_before, not_after)) => active_at(not_before, not_after, &values.evaluation_at),
        None => true,
    }
}

fn integrity_matches(rule: &RuleValues, values: &EvaluationValues) -> bool {
    rule.required_integrity.iter().all(|digest| {
        digest == &values.request.payload_digest || values.request.artifact_digests.contains(digest)
    })
}

fn active_at(not_before: &str, expires_at: &str, at: &str) -> bool {
    not_before <= at && at < expires_at
}

fn deny(reason: &str, verification_state: &'static str) -> DecisionPlan {
    let mut reason_codes = BTreeSet::new();
    reason_codes.insert(reason.to_owned());
    DecisionPlan {
        decision: "DENY",
        verification_state,
        reason_codes,
        limitations: limitations(),
    }
}

fn limitations() -> Vec<String> {
    vec![
        "R2 local prototype only; this decision is not an execution instruction.".to_owned(),
        "local-unsigned-development does not authenticate a signer identity.".to_owned(),
        "No network lookup, key operation, or durable replay state was used.".to_owned(),
        "Request payload digests are caller-declared; artifact bytes are not supplied to this profile.".to_owned(),
    ]
}

fn parse_manifest(document: &R2Document) -> Result<ManifestValues, Problem> {
    let fields = document_fields(document, R2DocumentKind::EntityManifest)?;
    let declared_capabilities = match optional_field(fields, "declaredCapabilities") {
        Some(value) => string_set(value)?,
        None => BTreeSet::new(),
    };
    let mut artifacts = BTreeMap::new();
    if let Some(value) = optional_field(fields, "artifacts") {
        for artifact in array_items(value)? {
            let artifact_fields = object_fields(artifact)?;
            artifacts.insert(
                field_string(artifact_fields, "artifactId")?.to_owned(),
                artifact.clone(),
            );
        }
    }
    Ok(ManifestValues {
        id: field_string(fields, "manifestId")?.to_owned(),
        subject_id: field_string(fields, "subjectId")?.to_owned(),
        owner_id: field_string(fields, "ownerId")?.to_owned(),
        scope: Scope::from_value(required_field(fields, "scope")?)?,
        lifecycle: field_string(fields, "lifecycle")?.to_owned(),
        issued_at: field_string(fields, "issuedAt")?.to_owned(),
        expires_at: field_string(fields, "expiresAt")?.to_owned(),
        declared_capabilities,
        artifacts,
        digest: document_digest(document.value())?,
    })
}

fn parse_policy(document: &R2Document) -> Result<PolicyValues, Problem> {
    let fields = document_fields(document, R2DocumentKind::AuthorityPolicy)?;
    let mut rules = Vec::new();
    for value in array_items(required_field(fields, "rules")?)? {
        rules.push(parse_rule(value)?);
    }
    Ok(PolicyValues {
        id: field_string(fields, "policyId")?.to_owned(),
        issuer_id: field_string(fields, "issuerId")?.to_owned(),
        scope: Scope::from_value(required_field(fields, "scope")?)?,
        revision: field_string(fields, "revision")?.to_owned(),
        lifecycle: field_string(fields, "lifecycle")?.to_owned(),
        issued_at: field_string(fields, "issuedAt")?.to_owned(),
        effective_at: field_string(fields, "effectiveAt")?.to_owned(),
        expires_at: field_string(fields, "expiresAt")?.to_owned(),
        rules,
        evidence_refs: required_field(fields, "evidenceRefs")?.clone(),
        digest: document_digest(document.value())?,
    })
}

fn parse_rule(value: &JsonValue) -> Result<RuleValues, Problem> {
    let fields = object_fields(value)?;
    let time_window = match optional_field(fields, "timeWindow") {
        Some(value) => {
            let fields = object_fields(value)?;
            Some((
                field_string(fields, "notBefore")?.to_owned(),
                field_string(fields, "notAfter")?.to_owned(),
            ))
        }
        None => None,
    };
    let required_integrity = match optional_field(fields, "requiredIntegrityDigests") {
        Some(value) => digest_set(value)?,
        None => BTreeSet::new(),
    };
    let requires_evidence = optional_field(fields, "requiredEvidence")
        .map(array_items)
        .transpose()?
        .is_some_and(|values| !values.is_empty());
    let requires_approvals = optional_field(fields, "requiredApprovals")
        .map(array_items)
        .transpose()?
        .is_some_and(|values| !values.is_empty());
    Ok(RuleValues {
        effect: field_string(fields, "effect")?.to_owned(),
        subject_ids: selector_ids(required_field(fields, "subjectSelector")?)?,
        actor_ids: selector_ids(required_field(fields, "actorSelector")?)?,
        actions: string_set(required_field(fields, "actions")?)?,
        resources: string_set(required_field(fields, "resources")?)?,
        scope: Scope::from_value(required_field(fields, "scope")?)?,
        time_window,
        required_integrity,
        requires_evidence,
        requires_approvals,
        reason_code: field_string(fields, "reasonCode")?.to_owned(),
    })
}

fn parse_request(document: &R2Document) -> Result<RequestValues, Problem> {
    let fields = document_fields(document, R2DocumentKind::ToolCallRequest)?;
    let artifact = optional_field(fields, "artifact").cloned();
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_digests = BTreeSet::new();
    if let Some(value) = &artifact {
        let artifact_fields = object_fields(value)?;
        artifact_ids.insert(field_string(artifact_fields, "artifactId")?.to_owned());
        artifact_digests.insert(digest_hex(required_field(artifact_fields, "digest")?)?.to_owned());
    }
    Ok(RequestValues {
        id: field_string(fields, "requestId")?.to_owned(),
        scope: Scope::from_value(required_field(fields, "scope")?)?,
        subject_id: field_string(fields, "subjectId")?.to_owned(),
        actor_id: field_string(fields, "actorId")?.to_owned(),
        action: field_string(fields, "action")?.to_owned(),
        resource: field_string(fields, "resource")?.to_owned(),
        issued_at: field_string(fields, "issuedAt")?.to_owned(),
        expires_at: field_string(fields, "expiresAt")?.to_owned(),
        replay_required: bool_value(required_field(fields, "replayRequired")?)?,
        payload_digest: digest_hex(required_field(fields, "payloadDigest")?)?.to_owned(),
        artifact,
        artifact_ids,
        artifact_digests,
        digest: document_digest(document.value())?,
    })
}

fn parse_revocations(document: &R2Document) -> Result<RevocationValues, Problem> {
    let fields = document_fields(document, R2DocumentKind::RevocationSet)?;
    let mut entries = Vec::new();
    for value in array_items(required_field(fields, "revocations")?)? {
        let fields = object_fields(value)?;
        entries.push(RevocationEntry {
            target_id: field_string(fields, "targetId")?.to_owned(),
            target_type: field_string(fields, "targetType")?.to_owned(),
            effective_at: field_string(fields, "effectiveAt")?.to_owned(),
        });
    }
    Ok(RevocationValues {
        id: field_string(fields, "revocationSetId")?.to_owned(),
        sequence: field_string(fields, "sequence")?.to_owned(),
        issuer_id: field_string(fields, "issuerId")?.to_owned(),
        scope: Scope::from_value(required_field(fields, "scope")?)?,
        issued_at: field_string(fields, "issuedAt")?.to_owned(),
        effective_at: field_string(fields, "effectiveAt")?.to_owned(),
        expires_at: field_string(fields, "expiresAt")?.to_owned(),
        next_update_at: field_string(fields, "nextUpdateAt")?.to_owned(),
        entries,
        digest: document_digest(document.value())?,
    })
}

fn document_fields(
    document: &R2Document,
    expected: R2DocumentKind,
) -> Result<&BTreeMap<String, JsonValue>, Problem> {
    if document.kind() != expected {
        return Err(Problem::new(ProblemCode::InvalidArgument));
    }
    object_fields(document.value())
}

fn selector_ids(value: &JsonValue) -> Result<BTreeSet<String>, Problem> {
    let fields = object_fields(value)?;
    string_set(required_field(fields, "ids")?)
}

fn string_set(value: &JsonValue) -> Result<BTreeSet<String>, Problem> {
    let mut values = BTreeSet::new();
    for value in array_items(value)? {
        values.insert(string_value(value)?.to_owned());
    }
    Ok(values)
}

fn digest_set(value: &JsonValue) -> Result<BTreeSet<String>, Problem> {
    let mut values = BTreeSet::new();
    for value in array_items(value)? {
        values.insert(digest_hex(value)?.to_owned());
    }
    Ok(values)
}

fn field_string<'a>(
    fields: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a str, Problem> {
    string_value(required_field(fields, name)?)
}

fn digest_hex(value: &JsonValue) -> Result<&str, Problem> {
    let fields = object_fields(value)?;
    string_value(required_field(fields, "value")?)
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

fn evaluation_seed(values: &EvaluationValues) -> Result<Digest, Problem> {
    let mut bytes = Vec::new();
    for value in [
        values.manifest.digest,
        values.policy.digest,
        values.request.digest,
        values.revocations.digest,
    ] {
        bytes.extend_from_slice(value.to_hex().as_bytes());
        bytes.push(0);
    }
    bytes.extend_from_slice(values.evaluation_at.as_bytes());
    Ok(domain_separated_digest(
        DigestDomain::EvaluationArtifactR2Prototype,
        &bytes,
    ))
}

fn derived_id(prefix: &str, seed: Digest) -> String {
    let encoded = seed.to_hex();
    format!("{prefix}{}", &encoded[..24])
}

fn build_decision(
    values: &EvaluationValues,
    plan: &DecisionPlan,
    decision_id: &str,
    bundle_id: &str,
) -> Result<JsonValue, Problem> {
    Ok(object([
        ("schemaVersion", text("fenrua.decision.v1")),
        ("decisionId", text(decision_id)),
        ("scope", values.request.scope.json()),
        ("profileId", text(R2_LOCAL_PROFILE_ID)),
        ("decision", text(plan.decision)),
        ("verificationState", text(plan.verification_state)),
        ("reasonCodes", string_array(&plan.reason_codes)),
        ("subjectId", text(&values.request.subject_id)),
        ("actorId", text(&values.request.actor_id)),
        ("action", text(&values.request.action)),
        ("resource", text(&values.request.resource)),
        ("policyId", text(&values.policy.id)),
        ("policyRevision", text(&values.policy.revision)),
        ("requestDigest", digest_json(values.request.digest)),
        ("evidenceBundleId", text(bundle_id)),
        ("issuedAt", text(&values.evaluation_at)),
        ("expiresAt", text(decision_expiry(values))),
        ("limitations", strings(&plan.limitations)),
    ]))
}

fn build_evidence(
    values: &EvaluationValues,
    plan: &DecisionPlan,
    seed: &Digest,
    decision: &JsonValue,
    decision_digest: &Digest,
    bundle_id: &str,
) -> Result<JsonValue, Problem> {
    let event_id = derived_id("urn:fenrua:audit-event:r2-", *seed);
    let event_digest = domain_separated_digest(
        DigestDomain::EvidenceBundleR2Prototype,
        format!("{event_id}\0{}", values.evaluation_at).as_bytes(),
    );
    let integrity = match &values.request.artifact {
        Some(artifact) => JsonValue::Array(vec![artifact.clone()]),
        None => JsonValue::Array(Vec::new()),
    };
    Ok(object([
        ("schemaVersion", text("fenrua.evidence-bundle.v1")),
        ("bundleId", text(bundle_id)),
        ("tenantScope", text(&values.request.scope.tenant_id)),
        ("environment", text(&values.request.scope.environment_id)),
        ("subject", text(&values.request.subject_id)),
        ("actor", text(&values.request.actor_id)),
        (
            "request",
            document_reference(
                &values.request.id,
                "urn:fenrua:schema:tool-call-request-v1",
                values.request.digest,
            ),
        ),
        ("policy", policy_reference(values, values.policy.digest)?),
        (
            "decision",
            decision_reference(
                decision_id(decision)?,
                *decision_digest,
                &values.evaluation_at,
            ),
        ),
        ("approvals", JsonValue::Array(Vec::new())),
        ("integrity", integrity),
        (
            "revocation",
            revocation_reference(values, values.revocations.digest),
        ),
        ("runtime", runtime_reference(*seed)),
        (
            "inputs",
            JsonValue::Array(vec![
                document_reference(
                    &values.manifest.id,
                    "urn:fenrua:schema:entity-manifest-v1",
                    values.manifest.digest,
                ),
                document_reference(
                    &values.policy.id,
                    "urn:fenrua:schema:authority-policy-v1",
                    values.policy.digest,
                ),
                document_reference(
                    &values.request.id,
                    "urn:fenrua:schema:tool-call-request-v1",
                    values.request.digest,
                ),
                document_reference(
                    &values.revocations.id,
                    "urn:fenrua:schema:revocation-set-v1",
                    values.revocations.digest,
                ),
            ]),
        ),
        (
            "outputs",
            JsonValue::Array(vec![document_reference(
                decision_id(decision)?,
                "urn:fenrua:schema:decision-v1",
                *decision_digest,
            )]),
        ),
        (
            "events",
            JsonValue::Array(vec![object([
                ("eventId", text(&event_id)),
                ("digest", digest_json(event_digest)),
                ("occurredAt", text(&values.evaluation_at)),
            ])]),
        ),
        ("limitations", strings(&plan.limitations)),
        ("createdAt", text(&values.evaluation_at)),
        ("expiresAt", text(decision_expiry(values))),
        ("producer", text("urn:fenrua:producer:trust-gate-local-r2")),
        ("producerVersion", text(env!("CARGO_PKG_VERSION"))),
        ("signatureProfile", text(LOCAL_UNSIGNED_PROFILE)),
        ("keyId", text(LOCAL_UNSIGNED_KEY_ID)),
    ]))
}

fn build_receipt(
    values: &EvaluationValues,
    plan: &DecisionPlan,
    decision_id: &str,
    bundle_id: &str,
    receipt_id: &str,
    evidence_digest: &Digest,
) -> Result<JsonValue, Problem> {
    let summary = match plan.decision {
        "ALLOW" => {
            "Local R2 prototype decision record. It is not an instruction to execute an action."
        }
        _ => {
            "Local R2 prototype denial record. The caller must fail closed and must not execute the requested action."
        }
    };
    Ok(object([
        ("schemaVersion", text("fenrua.receipt.v1")),
        ("receiptId", text(receipt_id)),
        ("bundleId", text(bundle_id)),
        ("decisionId", text(decision_id)),
        ("decision", text(plan.decision)),
        ("subjectId", text(&values.request.subject_id)),
        ("actorId", text(&values.request.actor_id)),
        ("action", text(&values.request.action)),
        ("resource", text(&values.request.resource)),
        ("reasonCodes", string_array(&plan.reason_codes)),
        ("issuedAt", text(&values.evaluation_at)),
        ("expiresAt", text(decision_expiry(values))),
        ("bundleDigest", digest_json(*evidence_digest)),
        ("summary", text(summary)),
        ("limitations", strings(&plan.limitations)),
    ]))
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
    fields.insert("signature".to_owned(), local_unsigned_signature(digest));
    Ok(JsonValue::Object(fields))
}

fn local_unsigned_signature(digest: Digest) -> JsonValue {
    object([
        ("profile", text(LOCAL_UNSIGNED_PROFILE)),
        ("keyId", text(LOCAL_UNSIGNED_KEY_ID)),
        ("payloadDigest", digest_json(digest)),
    ])
}

fn document_digest(value: &JsonValue) -> Result<Digest, Problem> {
    Ok(canonical_document_in_domain(value, DigestDomain::CanonicalJsonR2Prototype)?.digest())
}

fn decision_expiry(values: &EvaluationValues) -> &str {
    [
        values.request.expires_at.as_str(),
        values.policy.expires_at.as_str(),
        values.manifest.expires_at.as_str(),
        values.revocations.expires_at.as_str(),
    ]
    .into_iter()
    .min()
    .unwrap_or(values.request.expires_at.as_str())
}

fn decision_id(decision: &JsonValue) -> Result<&str, Problem> {
    let fields = object_fields(decision)?;
    field_string(fields, "decisionId")
}

fn document_reference(document_id: &str, schema_id: &str, digest: Digest) -> JsonValue {
    object([
        ("documentId", text(document_id)),
        ("schemaId", text(schema_id)),
        ("digest", digest_json(digest)),
    ])
}

fn policy_reference(values: &EvaluationValues, digest: Digest) -> Result<JsonValue, Problem> {
    Ok(object([
        ("policyId", text(&values.policy.id)),
        ("scope", values.policy.scope.json()),
        ("revision", text(&values.policy.revision)),
        ("digest", digest_json(digest)),
        ("effectiveAt", text(&values.policy.effective_at)),
        ("evidenceRefs", values.policy.evidence_refs.clone()),
    ]))
}

fn decision_reference(decision_id: &str, digest: Digest, issued_at: &str) -> JsonValue {
    object([
        ("decisionId", text(decision_id)),
        ("digest", digest_json(digest)),
        ("issuedAt", text(issued_at)),
    ])
}

fn revocation_reference(values: &EvaluationValues, digest: Digest) -> JsonValue {
    object([
        ("revocationSetId", text(&values.revocations.id)),
        ("scope", values.revocations.scope.json()),
        ("sequence", text(&values.revocations.sequence)),
        ("issuedAt", text(&values.revocations.issued_at)),
        ("expiresAt", text(&values.revocations.expires_at)),
        ("digest", digest_json(digest)),
    ])
}

fn runtime_reference(seed: Digest) -> JsonValue {
    object([
        ("runtimeId", text("urn:fenrua:runtime:local-unsigned-r2")),
        ("profile", text("local-unsigned-r2")),
        (
            "digest",
            digest_json(domain_separated_digest(
                DigestDomain::EvidenceBundleR2Prototype,
                seed.to_hex().as_bytes(),
            )),
        ),
    ])
}

fn digest_json(digest: Digest) -> JsonValue {
    object([
        ("algorithm", text("sha-256")),
        ("value", text(&digest.to_hex())),
    ])
}

fn string_array(values: &BTreeSet<String>) -> JsonValue {
    JsonValue::Array(values.iter().map(|value| text(value)).collect())
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
    use fenrua_c14n::{
        DigestDomain, canonical_document_in_domain, canonical_document_without_top_level_member,
    };
    use fenrua_protocol::{
        JsonValue, ParseLimits, R2Document, R2DocumentKind, parse_json, parse_r2_document,
    };

    use super::{EvaluationArtifact, EvaluationInput, evaluate};

    fn value(source: &str) -> JsonValue {
        match parse_json(source.as_bytes(), ParseLimits::R1_FOUNDATION) {
            Ok(value) => value,
            Err(error) => panic!("fixture must parse: {error}"),
        }
    }

    fn signed_document(mut value: JsonValue, kind: R2DocumentKind) -> R2Document {
        let digest = match canonical_document_without_top_level_member(
            &value,
            "signature",
            DigestDomain::LocalUnsignedPayloadR2Prototype,
        ) {
            Ok(document) => document.digest(),
            Err(error) => panic!("fixture must canonicalize: {error}"),
        };
        let JsonValue::Object(fields) = &mut value else {
            panic!("fixture must be an object");
        };
        let Some(JsonValue::Object(signature)) = fields.get_mut("signature") else {
            panic!("fixture must contain a signature");
        };
        let Some(JsonValue::Object(payload_digest)) = signature.get_mut("payloadDigest") else {
            panic!("fixture must contain a payload digest");
        };
        payload_digest.insert("value".to_owned(), JsonValue::String(digest.to_hex()));
        let bytes =
            match canonical_document_in_domain(&value, DigestDomain::CanonicalJsonR2Prototype) {
                Ok(document) => document.bytes().to_vec(),
                Err(error) => panic!("fixture must serialize: {error}"),
            };
        match parse_r2_document(&bytes, kind) {
            Ok(document) => document,
            Err(error) => panic!("signed fixture must validate: {error}"),
        }
    }

    fn manifest() -> R2Document {
        signed_document(
            value(include_str!("../../../fixtures/r2/manifest.json")),
            R2DocumentKind::EntityManifest,
        )
    }

    fn policy(effect: &str) -> R2Document {
        policy_with_issuer(effect, "urn:fenrua:organisation:fenrua")
    }

    fn policy_with_issuer(effect: &str, issuer_id: &str) -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        fields.insert(
            "issuerId".to_owned(),
            JsonValue::String(issuer_id.to_owned()),
        );
        let Some(JsonValue::Array(rules)) = fields.get_mut("rules") else {
            panic!("policy fixture must contain rules");
        };
        let Some(JsonValue::Object(rule)) = rules.first_mut() else {
            panic!("policy fixture must contain one rule");
        };
        rule.insert("effect".to_owned(), JsonValue::String(effect.to_owned()));
        rule.insert(
            "reasonCode".to_owned(),
            JsonValue::String(
                if effect == "ALLOW" {
                    "ALLOW_POLICY_MATCH"
                } else {
                    "DENY_EXPLICIT"
                }
                .to_owned(),
            ),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn policy_with_unresolved_deny() -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        let Some(JsonValue::Array(rules)) = fields.get_mut("rules") else {
            panic!("policy fixture must contain rules");
        };
        let Some(mut deny) = rules.first().cloned() else {
            panic!("policy fixture must contain one rule");
        };
        let JsonValue::Object(deny_fields) = &mut deny else {
            panic!("policy rule must be an object");
        };
        deny_fields.insert(
            "ruleId".to_owned(),
            JsonValue::String("urn:fenrua:rule:r2-deny-needs-evidence".to_owned()),
        );
        deny_fields.insert("effect".to_owned(), JsonValue::String("DENY".to_owned()));
        deny_fields.insert(
            "reasonCode".to_owned(),
            JsonValue::String("DENY_EXPLICIT".to_owned()),
        );
        deny_fields.insert(
            "requiredEvidence".to_owned(),
            JsonValue::Array(vec![JsonValue::String("synthetic-evidence".to_owned())]),
        );
        rules.push(deny);
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn artifact_reference(digest: &str) -> JsonValue {
        value(&format!(
            r#"{{
  "artifactId": "urn:fenrua:artifact:r2-build",
  "scope": {{
    "tenantId": "urn:fenrua:tenant:demo",
    "environmentId": "urn:fenrua:environment:development"
  }},
  "revision": "1",
  "digest": {{
    "algorithm": "sha-256",
    "value": "{digest}"
  }},
  "effectiveAt": "2026-07-14T00:00:00.000Z",
  "evidenceRefs": [{{
    "evidenceBundleId": "urn:fenrua:evidence-bundle:bootstrap-evidence",
    "digest": {{
      "algorithm": "sha-256",
      "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }},
    "createdAt": "2026-07-14T00:00:00.000Z"
  }}]
}}"#
        ))
    }

    fn manifest_with_artifact(digest: &str) -> R2Document {
        let mut manifest = value(include_str!("../../../fixtures/r2/manifest.json"));
        let JsonValue::Object(fields) = &mut manifest else {
            panic!("manifest fixture must be an object");
        };
        fields.insert(
            "artifacts".to_owned(),
            JsonValue::Array(vec![artifact_reference(digest)]),
        );
        signed_document(manifest, R2DocumentKind::EntityManifest)
    }

    fn request_with_artifact(digest: &str) -> R2Document {
        let mut request = value(include_str!("../../../fixtures/r2/request-offline.json"));
        let JsonValue::Object(fields) = &mut request else {
            panic!("request fixture must be an object");
        };
        fields.insert("artifact".to_owned(), artifact_reference(digest));
        signed_document(request, R2DocumentKind::ToolCallRequest)
    }

    fn request(replay_required: bool, valid_signature: bool) -> R2Document {
        let mut request = value(if replay_required {
            include_str!("../../../fixtures/r2/request-replay-required.json")
        } else {
            include_str!("../../../fixtures/r2/request-offline.json")
        });
        if valid_signature {
            return signed_document(request, R2DocumentKind::ToolCallRequest);
        }
        let JsonValue::Object(fields) = &mut request else {
            panic!("request fixture must be an object");
        };
        let Some(JsonValue::Object(signature)) = fields.get_mut("signature") else {
            panic!("request fixture must contain a signature");
        };
        let Some(JsonValue::Object(payload_digest)) = signature.get_mut("payloadDigest") else {
            panic!("request fixture must contain a payload digest");
        };
        payload_digest.insert("value".to_owned(), JsonValue::String("0".repeat(64)));
        let bytes =
            match canonical_document_in_domain(&request, DigestDomain::CanonicalJsonR2Prototype) {
                Ok(document) => document.bytes().to_vec(),
                Err(error) => panic!("request fixture must serialize: {error}"),
            };
        match parse_r2_document(&bytes, R2DocumentKind::ToolCallRequest) {
            Ok(document) => document,
            Err(error) => panic!("invalid-signature fixture must validate structurally: {error}"),
        }
    }

    fn revocations(sequence: &str) -> R2Document {
        revocations_with_issuer(sequence, "urn:fenrua:organisation:fenrua")
    }

    fn revocations_with_issuer(sequence: &str, issuer_id: &str) -> R2Document {
        let mut revocations = value(include_str!(
            "../../../fixtures/r2/revocations-current.json"
        ));
        let JsonValue::Object(fields) = &mut revocations else {
            panic!("revocation fixture must be an object");
        };
        fields.insert(
            "sequence".to_owned(),
            JsonValue::String(sequence.to_owned()),
        );
        fields.insert(
            "issuerId".to_owned(),
            JsonValue::String(issuer_id.to_owned()),
        );
        signed_document(revocations, R2DocumentKind::RevocationSet)
    }

    fn evaluate_fixture(
        effect: &str,
        replay_required: bool,
        valid_request_signature: bool,
        revocation_sequence: &str,
    ) -> EvaluationArtifact {
        let input = match EvaluationInput::new(
            manifest(),
            policy(effect),
            request(replay_required, valid_request_signature),
            revocations(revocation_sequence),
            "2026-07-14T00:01:00.000Z".to_owned(),
        ) {
            Ok(input) => input,
            Err(error) => panic!("fixture input must construct: {error}"),
        };
        match evaluate(&input) {
            Ok(artifact) => artifact,
            Err(error) => panic!("fixture must evaluate: {error}"),
        }
    }

    fn evaluate_input(
        manifest: R2Document,
        policy: R2Document,
        request: R2Document,
        revocations: R2Document,
    ) -> EvaluationArtifact {
        let input = match EvaluationInput::new(
            manifest,
            policy,
            request,
            revocations,
            "2026-07-14T00:01:00.000Z".to_owned(),
        ) {
            Ok(input) => input,
            Err(error) => panic!("fixture input must construct: {error}"),
        };
        match evaluate(&input) {
            Ok(artifact) => artifact,
            Err(error) => panic!("fixture must evaluate: {error}"),
        }
    }

    #[test]
    fn simple_allow_is_deterministic_and_contains_no_execution_field() {
        let first = evaluate_fixture("ALLOW", false, true, "1");
        let second = evaluate_fixture("ALLOW", false, true, "1");
        assert_eq!(first, second);
        let value = match fenrua_c14n::canonicalize(
            first.value(),
            fenrua_c14n::CanonicalizationLimits::R1_FOUNDATION,
        ) {
            Ok(value) => value,
            Err(error) => panic!("artifact must canonicalize: {error}"),
        };
        let rendered = match String::from_utf8(value) {
            Ok(rendered) => rendered,
            Err(_) => panic!("artifact must be UTF-8"),
        };
        assert!(rendered.contains("\"decision\":\"ALLOW\""));
        assert!(!rendered.contains("\"execution\""));
    }

    #[test]
    fn explicit_deny_overrides_without_emitting_an_execution_direction() {
        let artifact = evaluate_fixture("DENY", false, true, "1");
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_EXPLICIT"));
    }

    #[test]
    fn unresolved_matching_deny_fails_closed_before_an_allow_can_win() {
        let artifact = evaluate_input(
            manifest(),
            policy_with_unresolved_deny(),
            request(false, true),
            revocations("1"),
        );
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_FAIL_CLOSED"));
    }

    #[test]
    fn request_artifact_must_match_the_manifest_declaration() {
        let artifact = evaluate_input(
            manifest_with_artifact(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            policy("ALLOW"),
            request_with_artifact(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            revocations("1"),
        );
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_INTEGRITY_MISMATCH"));
    }

    #[test]
    fn replay_sensitive_request_fails_closed() {
        let artifact = evaluate_fixture("ALLOW", true, true, "1");
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_REPLAY"));
    }

    #[test]
    fn invalid_local_unsigned_input_signature_fails_closed() {
        let artifact = evaluate_fixture("ALLOW", false, false, "1");
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_SIGNATURE_INVALID"));
    }

    #[test]
    fn declared_owner_and_policy_issuer_mismatch_fails_closed() {
        let input = match EvaluationInput::new(
            manifest(),
            policy_with_issuer("ALLOW", "urn:fenrua:organisation:other"),
            request(false, true),
            revocations("1"),
            "2026-07-14T00:01:00.000Z".to_owned(),
        ) {
            Ok(input) => input,
            Err(error) => panic!("fixture input must construct: {error}"),
        };
        let artifact = match evaluate(&input) {
            Ok(artifact) => artifact,
            Err(error) => panic!("fixture must evaluate: {error}"),
        };
        assert!(format!("{:?}", artifact.value()).contains("DENY_INVALID_IDENTITY"));
    }

    #[test]
    fn declared_policy_and_revocation_issuer_mismatch_fails_closed() {
        let input = match EvaluationInput::new(
            manifest(),
            policy("ALLOW"),
            request(false, true),
            revocations_with_issuer("1", "urn:fenrua:organisation:other"),
            "2026-07-14T00:01:00.000Z".to_owned(),
        ) {
            Ok(input) => input,
            Err(error) => panic!("fixture input must construct: {error}"),
        };
        let artifact = match evaluate(&input) {
            Ok(artifact) => artifact,
            Err(error) => panic!("fixture must evaluate: {error}"),
        };
        assert!(format!("{:?}", artifact.value()).contains("DENY_INVALID_IDENTITY"));
    }

    #[test]
    fn evidence_records_the_supplied_revocation_sequence() {
        let artifact = evaluate_fixture("ALLOW", false, true, "2");
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("sequence\": String(\"2\")"));
    }

    #[test]
    fn generated_envelope_is_strict_json() {
        let artifact = evaluate_fixture("ALLOW", false, true, "1");
        let bytes = match fenrua_c14n::canonicalize(
            artifact.value(),
            fenrua_c14n::CanonicalizationLimits::R1_FOUNDATION,
        ) {
            Ok(bytes) => bytes,
            Err(error) => panic!("artifact must canonicalize: {error}"),
        };
        assert!(parse_json(&bytes, ParseLimits::R1_FOUNDATION).is_ok());
    }
}
