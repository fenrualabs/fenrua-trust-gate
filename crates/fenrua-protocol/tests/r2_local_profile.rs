use fenrua_protocol::{ProblemCode, R2DocumentKind, parse_r2_document};

const MANIFEST: &str = include_str!("../../../fixtures/r2/manifest.json");
const POLICY: &str = include_str!("../../../fixtures/r2/policy-allow.json");
const REQUEST: &str = include_str!("../../../fixtures/r2/request-offline.json");

fn replace_once(input: &str, from: &str, to: &str) -> String {
    assert!(input.contains(from), "fixture anchor must remain stable");
    input.replacen(from, to, 1)
}

fn assert_fixture_is_admitted(input: &str, kind: R2DocumentKind) {
    match parse_r2_document(input.as_bytes(), kind) {
        Ok(_) => {}
        Err(error) => panic!("base R2 fixture must be admitted: {error}"),
    }
}

fn assert_rejected(input: &str, kind: R2DocumentKind, expected: ProblemCode) {
    let error = match parse_r2_document(input.as_bytes(), kind) {
        Ok(_) => panic!("mutated R2 fixture must be rejected by the closed local profile"),
        Err(error) => error,
    };
    assert_eq!(error.code(), expected);
}

#[test]
fn closed_profile_rejects_unknown_manifest_top_level_field() {
    assert_fixture_is_admitted(MANIFEST, R2DocumentKind::EntityManifest);
    let source = replace_once(
        MANIFEST,
        "  \"schemaVersion\": \"fenrua.entity-manifest.v1\",\n",
        "  \"schemaVersion\": \"fenrua.entity-manifest.v1\",\n  \"unexpected\": true,\n",
    );

    assert_rejected(
        &source,
        R2DocumentKind::EntityManifest,
        ProblemCode::SchemaValidationFailed,
    );
}

#[test]
fn closed_profile_rejects_non_millisecond_utc_timestamp() {
    assert_fixture_is_admitted(MANIFEST, R2DocumentKind::EntityManifest);
    let source = replace_once(
        MANIFEST,
        "\"issuedAt\": \"2026-07-14T00:00:00.000Z\"",
        "\"issuedAt\": \"2026-07-14T00:00:00Z\"",
    );

    assert_rejected(
        &source,
        R2DocumentKind::EntityManifest,
        ProblemCode::InvalidTimestamp,
    );
}

#[test]
fn closed_profile_rejects_unsupported_signature_profile() {
    assert_fixture_is_admitted(MANIFEST, R2DocumentKind::EntityManifest);
    let source = replace_once(
        MANIFEST,
        "\"profile\": \"local-unsigned-development\"",
        "\"profile\": \"ed25519\"",
    );

    assert_rejected(
        &source,
        R2DocumentKind::EntityManifest,
        ProblemCode::UnsupportedProfile,
    );
}

#[test]
fn closed_profile_rejects_duplicate_policy_rule_id() {
    assert_fixture_is_admitted(POLICY, R2DocumentKind::AuthorityPolicy);
    let source = replace_once(
        POLICY,
        "    }\n  ],\n  \"integrity\":",
        "    },\n    {\n      \"ruleId\": \"urn:fenrua:rule:r2-allow\",\n      \"effect\": \"ALLOW\",\n      \"subjectSelector\": {\n        \"ids\": [\"urn:fenrua:entity:r2-agent\"]\n      },\n      \"actorSelector\": {\n        \"ids\": [\"urn:fenrua:actor:r2-operator\"]\n      },\n      \"actions\": [\"tool.execute\"],\n      \"resources\": [\"artifact:r2-build\"],\n      \"scope\": {\n        \"tenantId\": \"urn:fenrua:tenant:demo\",\n        \"environmentId\": \"urn:fenrua:environment:development\"\n      },\n      \"reasonCode\": \"ALLOW_POLICY_MATCH\"\n    }\n  ],\n  \"integrity\":",
    );

    assert_rejected(
        &source,
        R2DocumentKind::AuthorityPolicy,
        ProblemCode::SchemaValidationFailed,
    );
}

#[test]
fn closed_profile_rejects_v1_policy_obligations_without_r2_semantics() {
    assert_fixture_is_admitted(POLICY, R2DocumentKind::AuthorityPolicy);
    let source = replace_once(
        POLICY,
        "      \"reasonCode\": \"ALLOW_POLICY_MATCH\"\n",
        "      \"reasonCode\": \"ALLOW_POLICY_MATCH\",\n      \"obligations\": [{\"code\": \"retain\", \"description\": \"synthetic\"}]\n",
    );

    assert_rejected(
        &source,
        R2DocumentKind::AuthorityPolicy,
        ProblemCode::SchemaValidationFailed,
    );
}

#[test]
fn closed_profile_rejects_v1_request_policy_references_without_r2_semantics() {
    assert_fixture_is_admitted(REQUEST, R2DocumentKind::ToolCallRequest);
    let source = replace_once(
        REQUEST,
        "  \"signature\": {\n",
        "  \"policyRefs\": [],\n  \"signature\": {\n",
    );

    assert_rejected(
        &source,
        R2DocumentKind::ToolCallRequest,
        ProblemCode::SchemaValidationFailed,
    );
}
