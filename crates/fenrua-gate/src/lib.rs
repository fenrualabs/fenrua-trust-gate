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
    let output_expires_at = decision_expiry(&values, &plan)?;

    let decision = signed_document(build_decision(
        &values,
        &plan,
        &decision_id,
        &bundle_id,
        &output_expires_at,
    )?)?;
    let decision_digest = document_digest(&decision)?;
    let evidence = signed_document(build_evidence(
        &values,
        &plan,
        &seed,
        &decision,
        &decision_digest,
        &bundle_id,
        &output_expires_at,
    )?)?;
    let evidence_digest = document_digest(&evidence)?;
    let receipt = signed_document(build_receipt(
        &values,
        &plan,
        &decision_id,
        &bundle_id,
        &receipt_id,
        &evidence_digest,
        &output_expires_at,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Context {
    context_id: String,
    audience: String,
    bindings: Vec<(String, String)>,
}

impl Context {
    fn from_value(value: &JsonValue) -> Result<Self, Problem> {
        let fields = object_fields(value)?;
        let mut binding_keys = BTreeSet::new();
        let mut bindings = Vec::new();
        for binding in array_items(required_field(fields, "bindings")?)? {
            let binding = object_fields(binding)?;
            let key = field_string(binding, "key")?.to_owned();
            let value = field_string(binding, "value")?.to_owned();
            if !binding_keys.insert(key.clone()) {
                return Err(Problem::new(ProblemCode::InvalidArgument));
            }
            bindings.push((key, value));
        }
        Ok(Self {
            context_id: field_string(fields, "contextId")?.to_owned(),
            audience: field_string(fields, "audience")?.to_owned(),
            bindings,
        })
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
    context_selector: Context,
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
    context: Context,
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
    let mut audience_mismatch = false;
    let mut context_mismatch = false;

    for rule in &values.policy.rules {
        if !rule_base_matches(rule, values) {
            continue;
        }
        match context_match(rule, &values.request) {
            ContextMatch::Match => {}
            ContextMatch::AudienceMismatch => {
                audience_mismatch = true;
                continue;
            }
            ContextMatch::ContextMismatch => {
                context_mismatch = true;
                continue;
            }
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
    if audience_mismatch {
        return deny("DENY_AUDIENCE_MISMATCH", "POLICY_VIOLATION");
    }
    if context_mismatch {
        return deny("DENY_CONTEXT_MISMATCH", "POLICY_VIOLATION");
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextMatch {
    Match,
    AudienceMismatch,
    ContextMismatch,
}

fn context_match(rule: &RuleValues, request: &RequestValues) -> ContextMatch {
    if rule.context_selector.audience != request.context.audience {
        return ContextMatch::AudienceMismatch;
    }
    if rule.context_selector.context_id != request.context.context_id
        || rule.context_selector.bindings != request.context.bindings
    {
        return ContextMatch::ContextMismatch;
    }
    ContextMatch::Match
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
        context_selector: Context::from_value(required_field(fields, "contextSelector")?)?,
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
        context: Context::from_value(required_field(fields, "context")?)?,
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
    expires_at: &str,
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
        ("expiresAt", text(expires_at)),
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
    expires_at: &str,
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
        ("schemaVersion", text("fenrua.evidence-bundle.v2")),
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
                    "urn:fenrua:schema:authority-policy-v2",
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
        ("expiresAt", text(expires_at)),
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
    expires_at: &str,
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
        ("expiresAt", text(expires_at)),
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

fn decision_expiry(values: &EvaluationValues, plan: &DecisionPlan) -> Result<String, Problem> {
    let earliest_input_expiry = [
        values.request.expires_at.as_str(),
        values.policy.expires_at.as_str(),
        values.manifest.expires_at.as_str(),
        values.revocations.expires_at.as_str(),
    ]
    .into_iter()
    .min()
    .unwrap_or(values.request.expires_at.as_str());

    if earliest_input_expiry > values.evaluation_at.as_str() {
        return Ok(earliest_input_expiry.to_owned());
    }

    if plan.decision == "DENY" {
        // A denial must remain structurally valid even when its source evidence
        // is already stale. Keep that envelope interval to one UTC millisecond
        // rather than extending it to a still-valid unrelated input boundary.
        return next_utc_millisecond(&values.evaluation_at);
    }

    Err(Problem::new(ProblemCode::InvalidTimestamp))
}

fn next_utc_millisecond(timestamp: &str) -> Result<String, Problem> {
    validate_r2_timestamp(timestamp)?;
    let bytes = timestamp.as_bytes();
    let mut year = decimal_component(&bytes[0..4]);
    let mut month = decimal_component(&bytes[5..7]);
    let mut day = decimal_component(&bytes[8..10]);
    let mut hour = decimal_component(&bytes[11..13]);
    let mut minute = decimal_component(&bytes[14..16]);
    let mut second = decimal_component(&bytes[17..19]);
    let mut millisecond = decimal_component(&bytes[20..23]);

    millisecond += 1;
    if millisecond == 1_000 {
        millisecond = 0;
        second += 1;
    }
    if second == 60 {
        second = 0;
        minute += 1;
    }
    if minute == 60 {
        minute = 0;
        hour += 1;
    }
    if hour == 24 {
        hour = 0;
        day += 1;
    }
    if day > days_in_month(year, month) {
        day = 1;
        month += 1;
    }
    if month == 13 {
        month = 1;
        year += 1;
    }
    if year > 9_999 {
        return Err(Problem::new(ProblemCode::InvalidTimestamp));
    }

    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millisecond:03}Z"
    ))
}

fn decimal_component(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
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

    use super::{EvaluationArtifact, EvaluationInput, evaluate, next_utc_millisecond};

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

    fn structurally_admitted_document(value: JsonValue, kind: R2DocumentKind) -> R2Document {
        let bytes =
            match canonical_document_in_domain(&value, DigestDomain::CanonicalJsonR2Prototype) {
                Ok(document) => document.bytes().to_vec(),
                Err(error) => panic!("fixture must serialize: {error}"),
            };
        match parse_r2_document(&bytes, kind) {
            Ok(document) => document,
            Err(error) => panic!("mutated fixture must validate structurally: {error}"),
        }
    }

    fn mutated_document(
        source: &str,
        kind: R2DocumentKind,
        field: &str,
        changed_value: &str,
    ) -> R2Document {
        let mut document = value(source);
        let JsonValue::Object(fields) = &mut document else {
            panic!("fixture must be an object");
        };
        fields.insert(
            field.to_owned(),
            JsonValue::String(changed_value.to_owned()),
        );
        structurally_admitted_document(document, kind)
    }

    fn document_with_timestamp(
        source: &str,
        kind: R2DocumentKind,
        field: &str,
        timestamp: &str,
    ) -> R2Document {
        let mut document = value(source);
        let JsonValue::Object(fields) = &mut document else {
            panic!("fixture must be an object");
        };
        fields.insert(field.to_owned(), JsonValue::String(timestamp.to_owned()));
        signed_document(document, kind)
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

    fn policy_with_context_selector(
        context_id: &str,
        audience: &str,
        binding_value: &str,
    ) -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        let Some(JsonValue::Array(rules)) = fields.get_mut("rules") else {
            panic!("policy fixture must contain rules");
        };
        let Some(JsonValue::Object(rule)) = rules.first_mut() else {
            panic!("policy fixture must contain one rule");
        };
        rule.insert(
            "contextSelector".to_owned(),
            value(&format!(
                r#"{{
  "contextId": "{context_id}",
  "audience": "{audience}",
  "bindings": [{{"key": "purpose", "value": "{binding_value}"}}]
}}"#
            )),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn policy_with_lifecycle(lifecycle: &str) -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        fields.insert(
            "lifecycle".to_owned(),
            JsonValue::String(lifecycle.to_owned()),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn policy_with_expiry(expires_at: &str) -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        fields.insert(
            "expiresAt".to_owned(),
            JsonValue::String(expires_at.to_owned()),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn policy_with_time_window(not_before: &str, not_after: &str) -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        let Some(JsonValue::Array(rules)) = fields.get_mut("rules") else {
            panic!("policy fixture must contain rules");
        };
        let Some(JsonValue::Object(rule)) = rules.first_mut() else {
            panic!("policy fixture must contain one rule");
        };
        rule.insert(
            "timeWindow".to_owned(),
            value(&format!(
                r#"{{"notBefore":"{not_before}","notAfter":"{not_after}"}}"#
            )),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn policy_with_matching_deny_and_allow() -> R2Document {
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
            JsonValue::String("urn:fenrua:rule:r2-matching-deny".to_owned()),
        );
        deny_fields.insert("effect".to_owned(), JsonValue::String("DENY".to_owned()));
        deny_fields.insert(
            "reasonCode".to_owned(),
            JsonValue::String("DENY_EXPLICIT".to_owned()),
        );
        rules.push(deny);
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn manifest_with_expiry(expires_at: &str) -> R2Document {
        let mut manifest = value(include_str!("../../../fixtures/r2/manifest.json"));
        let JsonValue::Object(fields) = &mut manifest else {
            panic!("manifest fixture must be an object");
        };
        fields.insert(
            "expiresAt".to_owned(),
            JsonValue::String(expires_at.to_owned()),
        );
        signed_document(manifest, R2DocumentKind::EntityManifest)
    }

    fn policy_with_resource(resource: &str) -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        let Some(JsonValue::Array(rules)) = fields.get_mut("rules") else {
            panic!("policy fixture must contain rules");
        };
        let Some(JsonValue::Object(rule)) = rules.first_mut() else {
            panic!("policy fixture must contain one rule");
        };
        rule.insert(
            "resources".to_owned(),
            JsonValue::Array(vec![JsonValue::String(resource.to_owned())]),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn policy_with_required_approval() -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        let Some(JsonValue::Array(rules)) = fields.get_mut("rules") else {
            panic!("policy fixture must contain rules");
        };
        let Some(JsonValue::Object(rule)) = rules.first_mut() else {
            panic!("policy fixture must contain one rule");
        };
        rule.insert(
            "requiredApprovals".to_owned(),
            value(r#"[{"approvalType":"operator-approval","minimumCount":1}]"#),
        );
        signed_document(policy, R2DocumentKind::AuthorityPolicy)
    }

    fn policy_with_ambiguous_allow_reason() -> R2Document {
        let mut policy = value(include_str!("../../../fixtures/r2/policy-allow.json"));
        let JsonValue::Object(fields) = &mut policy else {
            panic!("policy fixture must be an object");
        };
        let Some(JsonValue::Array(rules)) = fields.get_mut("rules") else {
            panic!("policy fixture must contain rules");
        };
        let Some(JsonValue::Object(rule)) = rules.first_mut() else {
            panic!("policy fixture must contain one rule");
        };
        rule.insert(
            "reasonCode".to_owned(),
            JsonValue::String("DENY_EXPLICIT".to_owned()),
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

    fn request_with_subject(subject_id: &str) -> R2Document {
        let mut request = value(include_str!("../../../fixtures/r2/request-offline.json"));
        let JsonValue::Object(fields) = &mut request else {
            panic!("request fixture must be an object");
        };
        fields.insert(
            "subjectId".to_owned(),
            JsonValue::String(subject_id.to_owned()),
        );
        signed_document(request, R2DocumentKind::ToolCallRequest)
    }

    fn request_with_environment(environment_id: &str) -> R2Document {
        let mut request = value(include_str!("../../../fixtures/r2/request-offline.json"));
        let JsonValue::Object(fields) = &mut request else {
            panic!("request fixture must be an object");
        };
        let Some(JsonValue::Object(scope)) = fields.get_mut("scope") else {
            panic!("request fixture must contain a scope");
        };
        scope.insert(
            "environmentId".to_owned(),
            JsonValue::String(environment_id.to_owned()),
        );
        signed_document(request, R2DocumentKind::ToolCallRequest)
    }

    fn request_with_expiry(expires_at: &str) -> R2Document {
        let mut request = value(include_str!("../../../fixtures/r2/request-offline.json"));
        let JsonValue::Object(fields) = &mut request else {
            panic!("request fixture must be an object");
        };
        fields.insert(
            "expiresAt".to_owned(),
            JsonValue::String(expires_at.to_owned()),
        );
        signed_document(request, R2DocumentKind::ToolCallRequest)
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

    fn revocations_with_next_update(next_update_at: &str) -> R2Document {
        let mut revocations = value(include_str!(
            "../../../fixtures/r2/revocations-current.json"
        ));
        let JsonValue::Object(fields) = &mut revocations else {
            panic!("revocation fixture must be an object");
        };
        fields.insert(
            "nextUpdateAt".to_owned(),
            JsonValue::String(next_update_at.to_owned()),
        );
        signed_document(revocations, R2DocumentKind::RevocationSet)
    }

    fn revocations_with_expiry(expires_at: &str) -> R2Document {
        let mut revocations = value(include_str!(
            "../../../fixtures/r2/revocations-current.json"
        ));
        let JsonValue::Object(fields) = &mut revocations else {
            panic!("revocation fixture must be an object");
        };
        fields.insert(
            "expiresAt".to_owned(),
            JsonValue::String(expires_at.to_owned()),
        );
        signed_document(revocations, R2DocumentKind::RevocationSet)
    }

    fn revocations_with_target(target_type: &str, target_id: &str) -> R2Document {
        let mut revocations = value(include_str!(
            "../../../fixtures/r2/revocations-current.json"
        ));
        let JsonValue::Object(fields) = &mut revocations else {
            panic!("revocation fixture must be an object");
        };
        let Some(JsonValue::Array(entries)) = fields.get_mut("revocations") else {
            panic!("revocation fixture must contain entries");
        };
        entries.push(value(&format!(
            r#"{{
  "revocationId": "urn:fenrua:revocation:r2-{target_type}-test",
  "targetId": "{target_id}",
  "targetType": "{target_type}",
  "reasonCode": "DENY_EXPLICIT",
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
        )));
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
        evaluate_input_at(
            manifest,
            policy,
            request,
            revocations,
            "2026-07-14T00:01:00.000Z",
        )
    }

    fn evaluate_input_at(
        manifest: R2Document,
        policy: R2Document,
        request: R2Document,
        revocations: R2Document,
        evaluation_at: &str,
    ) -> EvaluationArtifact {
        let input = match EvaluationInput::new(
            manifest,
            policy,
            request,
            revocations,
            evaluation_at.to_owned(),
        ) {
            Ok(input) => input,
            Err(error) => panic!("fixture input must construct: {error}"),
        };
        match evaluate(&input) {
            Ok(artifact) => artifact,
            Err(error) => panic!("fixture must evaluate: {error}"),
        }
    }

    fn assert_single_decision(
        case_name: &str,
        artifact: &EvaluationArtifact,
        expected_decision: &str,
        expected_state: &str,
        expected_reason: &str,
    ) {
        let JsonValue::Object(envelope) = artifact.value() else {
            panic!("evaluation artifact must be an object");
        };
        let Some(JsonValue::Object(decision)) = envelope.get("decision") else {
            panic!("evaluation artifact must contain a decision");
        };
        assert!(
            matches!(
                decision.get("decision"),
                Some(JsonValue::String(value)) if value == expected_decision
            ),
            "{case_name}: unexpected decision"
        );
        assert!(
            matches!(
                decision.get("verificationState"),
                Some(JsonValue::String(value)) if value == expected_state
            ),
            "{case_name}: unexpected verification state"
        );
        assert!(
            matches!(
                decision.get("reasonCodes"),
                Some(JsonValue::Array(values))
                    if matches!(values.as_slice(), [JsonValue::String(value)] if value == expected_reason)
            ),
            "{case_name}: unexpected reason codes"
        );
    }

    fn assert_output_times(artifact: &EvaluationArtifact, issued_at: &str, expires_at: &str) {
        let JsonValue::Object(envelope) = artifact.value() else {
            panic!("evaluation artifact must be an object");
        };
        for (record_name, issued_field) in [
            ("decision", "issuedAt"),
            ("evidenceBundle", "createdAt"),
            ("receipt", "issuedAt"),
        ] {
            let Some(JsonValue::Object(record)) = envelope.get(record_name) else {
                panic!("evaluation artifact must contain {record_name}");
            };
            assert!(
                matches!(
                    record.get(issued_field),
                    Some(JsonValue::String(value)) if value == issued_at
                ),
                "{record_name}: unexpected issue timestamp"
            );
            assert!(
                matches!(
                    record.get("expiresAt"),
                    Some(JsonValue::String(value)) if value == expires_at
                ),
                "{record_name}: unexpected expiration timestamp"
            );
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
    fn decision_boundary_matrix_covers_supported_fail_closed_outcomes() {
        let artifact_digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cases = [
            (
                "request scope mismatch",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    request_with_environment("urn:fenrua:environment:other"),
                    revocations("1"),
                ),
                "DENY",
                "FAIL_CLOSED",
                "DENY_UNSUPPORTED_ENVIRONMENT",
            ),
            (
                "request subject mismatch",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    request_with_subject("urn:fenrua:entity:other"),
                    revocations("1"),
                ),
                "DENY",
                "FAIL_CLOSED",
                "DENY_MISSING_IDENTITY",
            ),
            (
                "retired policy",
                evaluate_input(
                    manifest(),
                    policy_with_lifecycle("retired"),
                    request(false, true),
                    revocations("1"),
                ),
                "DENY",
                "STALE",
                "DENY_POLICY_EXPIRED",
            ),
            (
                "stale revocation state",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    request(false, true),
                    revocations_with_next_update("2026-07-14T00:01:00.000Z"),
                ),
                "DENY",
                "STALE",
                "DENY_STALE_REVOCATION_STATE",
            ),
            (
                "revoked policy",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    request(false, true),
                    revocations_with_target("policy", "urn:fenrua:policy:r2-demo"),
                ),
                "DENY",
                "REVOKED",
                "DENY_POLICY_REVOKED",
            ),
            (
                "revoked subject",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    request(false, true),
                    revocations_with_target("subject", "urn:fenrua:entity:r2-agent"),
                ),
                "DENY",
                "REVOKED",
                "DENY_SUBJECT_REVOKED",
            ),
            (
                "revoked key",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    request(false, true),
                    revocations_with_target("key", "urn:fenrua:key:local-unsigned-development"),
                ),
                "DENY",
                "REVOKED",
                "DENY_KEY_REVOKED",
            ),
            (
                "revoked artifact",
                evaluate_input(
                    manifest_with_artifact(artifact_digest),
                    policy("ALLOW"),
                    request_with_artifact(artifact_digest),
                    revocations_with_target("artifact", "urn:fenrua:artifact:r2-build"),
                ),
                "DENY",
                "REVOKED",
                "DENY_ARTIFACT_REVOKED",
            ),
            (
                "no matching resource",
                evaluate_input(
                    manifest(),
                    policy_with_resource("artifact:unmatched"),
                    request(false, true),
                    revocations("1"),
                ),
                "DENY",
                "POLICY_VIOLATION",
                "DENY_NO_MATCH",
            ),
            (
                "unresolved approval",
                evaluate_input(
                    manifest(),
                    policy_with_required_approval(),
                    request(false, true),
                    revocations("1"),
                ),
                "DENY",
                "FAIL_CLOSED",
                "DENY_MISSING_APPROVAL",
            ),
            (
                "ambiguous allow reason",
                evaluate_input(
                    manifest(),
                    policy_with_ambiguous_allow_reason(),
                    request(false, true),
                    revocations("1"),
                ),
                "DENY",
                "FAIL_CLOSED",
                "DENY_AMBIGUOUS_POLICY",
            ),
        ];

        for (case_name, artifact, decision, verification_state, reason) in cases {
            assert_single_decision(case_name, &artifact, decision, verification_state, reason);
        }
    }

    #[test]
    fn policy_expiry_boundary_emits_a_strict_minimal_deny_envelope() {
        let expires_at = "2026-07-14T00:00:30.000Z";
        let before_expiry = evaluate_input_at(
            manifest(),
            policy_with_expiry(expires_at),
            request(false, true),
            revocations("1"),
            "2026-07-14T00:00:29.999Z",
        );
        assert_single_decision(
            "policy just before expiry",
            &before_expiry,
            "ALLOW",
            "PASS_WITH_LIMITATIONS",
            "ALLOW_POLICY_MATCH",
        );
        assert_output_times(&before_expiry, "2026-07-14T00:00:29.999Z", expires_at);

        let at_expiry = evaluate_input_at(
            manifest(),
            policy_with_expiry(expires_at),
            request(false, true),
            revocations("1"),
            expires_at,
        );
        assert_single_decision(
            "policy at expiry",
            &at_expiry,
            "DENY",
            "STALE",
            "DENY_POLICY_EXPIRED",
        );
        assert_output_times(&at_expiry, expires_at, "2026-07-14T00:00:30.001Z");

        let repeat_at_expiry = evaluate_input_at(
            manifest(),
            policy_with_expiry(expires_at),
            request(false, true),
            revocations("1"),
            expires_at,
        );
        assert_eq!(at_expiry, repeat_at_expiry);
    }

    #[test]
    fn each_direct_expiry_boundary_emits_a_strict_deny_envelope() {
        let expires_at = "2026-07-14T00:00:30.000Z";
        let assert_expired = |case_name: &str,
                              manifest: R2Document,
                              policy: R2Document,
                              request: R2Document,
                              revocations: R2Document,
                              expected_state: &str,
                              expected_reason: &str| {
            let artifact = evaluate_input_at(manifest, policy, request, revocations, expires_at);
            assert_single_decision(
                case_name,
                &artifact,
                "DENY",
                expected_state,
                expected_reason,
            );
            assert_output_times(&artifact, expires_at, "2026-07-14T00:00:30.001Z");
        };

        assert_expired(
            "expired manifest",
            manifest_with_expiry(expires_at),
            policy("ALLOW"),
            request(false, true),
            revocations("1"),
            "FAIL_CLOSED",
            "DENY_INVALID_IDENTITY",
        );
        assert_expired(
            "expired policy",
            manifest(),
            policy_with_expiry(expires_at),
            request(false, true),
            revocations("1"),
            "STALE",
            "DENY_POLICY_EXPIRED",
        );
        assert_expired(
            "expired request",
            manifest(),
            policy("ALLOW"),
            request_with_expiry(expires_at),
            revocations("1"),
            "STALE",
            "DENY_FAIL_CLOSED",
        );
        assert_expired(
            "expired revocation set",
            manifest(),
            policy("ALLOW"),
            request(false, true),
            revocations_with_expiry(expires_at),
            "STALE",
            "DENY_STALE_REVOCATION_STATE",
        );
    }

    #[test]
    fn direct_issued_at_boundaries_fail_closed_without_implicit_clock_skew() {
        let evaluation_at = "2026-07-14T00:01:00.000Z";
        let future = "2026-07-14T00:01:00.001Z";
        let at_boundary = evaluate_input_at(
            document_with_timestamp(
                include_str!("../../../fixtures/r2/manifest.json"),
                R2DocumentKind::EntityManifest,
                "issuedAt",
                evaluation_at,
            ),
            document_with_timestamp(
                include_str!("../../../fixtures/r2/policy-allow.json"),
                R2DocumentKind::AuthorityPolicy,
                "issuedAt",
                evaluation_at,
            ),
            document_with_timestamp(
                include_str!("../../../fixtures/r2/request-offline.json"),
                R2DocumentKind::ToolCallRequest,
                "issuedAt",
                evaluation_at,
            ),
            document_with_timestamp(
                include_str!("../../../fixtures/r2/revocations-current.json"),
                R2DocumentKind::RevocationSet,
                "issuedAt",
                evaluation_at,
            ),
            evaluation_at,
        );
        assert_single_decision(
            "direct inputs at their issue boundary",
            &at_boundary,
            "ALLOW",
            "PASS_WITH_LIMITATIONS",
            "ALLOW_POLICY_MATCH",
        );

        let cases = [
            (
                "future manifest issuedAt",
                evaluate_input_at(
                    document_with_timestamp(
                        include_str!("../../../fixtures/r2/manifest.json"),
                        R2DocumentKind::EntityManifest,
                        "issuedAt",
                        future,
                    ),
                    policy("ALLOW"),
                    request(false, true),
                    revocations("1"),
                    evaluation_at,
                ),
                "FAIL_CLOSED",
                "DENY_INVALID_IDENTITY",
            ),
            (
                "future policy issuedAt",
                evaluate_input_at(
                    manifest(),
                    document_with_timestamp(
                        include_str!("../../../fixtures/r2/policy-allow.json"),
                        R2DocumentKind::AuthorityPolicy,
                        "issuedAt",
                        future,
                    ),
                    request(false, true),
                    revocations("1"),
                    evaluation_at,
                ),
                "FAIL_CLOSED",
                "DENY_FAIL_CLOSED",
            ),
            (
                "future request issuedAt",
                evaluate_input_at(
                    manifest(),
                    policy("ALLOW"),
                    document_with_timestamp(
                        include_str!("../../../fixtures/r2/request-offline.json"),
                        R2DocumentKind::ToolCallRequest,
                        "issuedAt",
                        future,
                    ),
                    revocations("1"),
                    evaluation_at,
                ),
                "STALE",
                "DENY_FAIL_CLOSED",
            ),
            (
                "future revocation issuedAt",
                evaluate_input_at(
                    manifest(),
                    policy("ALLOW"),
                    request(false, true),
                    document_with_timestamp(
                        include_str!("../../../fixtures/r2/revocations-current.json"),
                        R2DocumentKind::RevocationSet,
                        "issuedAt",
                        future,
                    ),
                    evaluation_at,
                ),
                "STALE",
                "DENY_STALE_REVOCATION_STATE",
            ),
        ];

        for (case_name, artifact, verification_state, reason_code) in cases {
            assert_single_decision(
                case_name,
                &artifact,
                "DENY",
                verification_state,
                reason_code,
            );
        }
    }

    #[test]
    fn output_expiry_carries_across_utc_calendar_boundaries() {
        assert_eq!(
            next_utc_millisecond("2027-02-28T23:59:59.999Z"),
            Ok("2027-03-01T00:00:00.000Z".to_owned())
        );
        assert_eq!(
            next_utc_millisecond("2028-02-28T23:59:59.999Z"),
            Ok("2028-02-29T00:00:00.000Z".to_owned())
        );
        assert_eq!(
            next_utc_millisecond("2028-12-31T23:59:59.999Z"),
            Ok("2029-01-01T00:00:00.000Z".to_owned())
        );
        assert!(next_utc_millisecond("9999-12-31T23:59:59.999Z").is_err());
    }

    #[test]
    fn policy_time_window_is_half_open_at_each_millisecond_boundary() {
        let not_before = "2026-07-14T00:00:30.000Z";
        let not_after = "2026-07-14T00:00:31.000Z";
        let cases = [
            (
                "before time window",
                "2026-07-14T00:00:29.999Z",
                "DENY",
                "POLICY_VIOLATION",
                "DENY_NO_MATCH",
            ),
            (
                "at time window start",
                not_before,
                "ALLOW",
                "PASS_WITH_LIMITATIONS",
                "ALLOW_POLICY_MATCH",
            ),
            (
                "just before time window end",
                "2026-07-14T00:00:30.999Z",
                "ALLOW",
                "PASS_WITH_LIMITATIONS",
                "ALLOW_POLICY_MATCH",
            ),
            (
                "at time window end",
                not_after,
                "DENY",
                "POLICY_VIOLATION",
                "DENY_NO_MATCH",
            ),
            (
                "after time window",
                "2026-07-14T00:00:31.001Z",
                "DENY",
                "POLICY_VIOLATION",
                "DENY_NO_MATCH",
            ),
        ];

        for (case_name, evaluation_at, decision, verification_state, reason) in cases {
            let artifact = evaluate_input_at(
                manifest(),
                policy_with_time_window(not_before, not_after),
                request(false, true),
                revocations("1"),
                evaluation_at,
            );
            assert_single_decision(case_name, &artifact, decision, verification_state, reason);
        }
    }

    #[test]
    fn matching_explicit_deny_overrides_a_matching_allow_rule() {
        let artifact = evaluate_input(
            manifest(),
            policy_with_matching_deny_and_allow(),
            request(false, true),
            revocations("1"),
        );
        assert_single_decision(
            "matching explicit deny",
            &artifact,
            "DENY",
            "POLICY_VIOLATION",
            "DENY_EXPLICIT",
        );
    }

    #[test]
    fn audience_mismatch_is_denied_after_the_other_rule_selectors_match() {
        let artifact = evaluate_input(
            manifest(),
            policy_with_context_selector(
                "urn:fenrua:context:r2-demo",
                "urn:fenrua:audience:other-tool",
                "fixture",
            ),
            request(false, true),
            revocations("1"),
        );
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_AUDIENCE_MISMATCH"));
    }

    #[test]
    fn context_id_mismatch_is_denied_after_the_audience_matches() {
        let artifact = evaluate_input(
            manifest(),
            policy_with_context_selector(
                "urn:fenrua:context:other",
                "urn:fenrua:audience:r2-tool",
                "fixture",
            ),
            request(false, true),
            revocations("1"),
        );
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_CONTEXT_MISMATCH"));
    }

    #[test]
    fn context_binding_mismatch_is_denied_after_the_audience_matches() {
        let artifact = evaluate_input(
            manifest(),
            policy_with_context_selector(
                "urn:fenrua:context:r2-demo",
                "urn:fenrua:audience:r2-tool",
                "other-purpose",
            ),
            request(false, true),
            revocations("1"),
        );
        let rendered = format!("{:?}", artifact.value());
        assert!(rendered.contains("DENY_CONTEXT_MISMATCH"));
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
    fn altered_direct_inputs_fail_at_the_signature_boundary() {
        let cases = [
            (
                "altered manifest",
                evaluate_input(
                    mutated_document(
                        include_str!("../../../fixtures/r2/manifest.json"),
                        R2DocumentKind::EntityManifest,
                        "revision",
                        "2",
                    ),
                    policy("ALLOW"),
                    request(false, true),
                    revocations("1"),
                ),
            ),
            (
                "altered policy",
                evaluate_input(
                    manifest(),
                    mutated_document(
                        include_str!("../../../fixtures/r2/policy-allow.json"),
                        R2DocumentKind::AuthorityPolicy,
                        "revision",
                        "2",
                    ),
                    request(false, true),
                    revocations("1"),
                ),
            ),
            (
                "altered request",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    mutated_document(
                        include_str!("../../../fixtures/r2/request-offline.json"),
                        R2DocumentKind::ToolCallRequest,
                        "nonce",
                        "fixture_nonce_0002",
                    ),
                    revocations("1"),
                ),
            ),
            (
                "altered revocation set",
                evaluate_input(
                    manifest(),
                    policy("ALLOW"),
                    request(false, true),
                    mutated_document(
                        include_str!("../../../fixtures/r2/revocations-current.json"),
                        R2DocumentKind::RevocationSet,
                        "sequence",
                        "2",
                    ),
                ),
            ),
        ];

        for (case_name, artifact) in cases {
            assert_single_decision(
                case_name,
                &artifact,
                "DENY",
                "INTEGRITY_MISMATCH",
                "DENY_SIGNATURE_INVALID",
            );
        }
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
