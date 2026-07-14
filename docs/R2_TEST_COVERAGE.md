# R2 Test Coverage Record

Status: source-only coverage record for the unreleased R2 local prototype

This record maps the implemented R2 corpus to the local subset of Industrial 10
workstream 4 sections 14.4, 14.7, 14.10, and 31. It is not a release claim,
supported-platform claim, security assessment, or statement that the deferred
product requirements are complete.

## Verification Command

Run the complete local gate from the repository root:

```text
./ci/r2-checks.sh
```

The gate runs formatting and lint checks, the Rust workspace test suite,
public-admission controls, dependency policy, verifier dependency isolation,
and the exact R2 schema-pin check.

## Implemented and Tested R2 Subset

| Area | Deterministic evidence | Boundary proved |
| --- | --- | --- |
| Allow and repeatability | `simple_allow_is_deterministic_and_contains_no_execution_field` | Identical inputs and explicit timestamp produce the same local record; `ALLOW` has no execution field. |
| Explicit deny and deny-overrides | `matching_explicit_deny_overrides_a_matching_allow_rule` | A matching explicit DENY wins over a matching ALLOW. |
| Context binding | Audience, context identifier, and ordered binding tests | Context substitutions deny before an allow can apply. |
| Scope and identity | Decision boundary matrix and issuer-alignment tests | Scope, subject, owner, and issuer disagreements fail closed. |
| Time windows | `policy_time_window_is_half_open_at_each_millisecond_boundary` | Rule windows are UTC half-open intervals: `[notBefore, notAfter)`. |
| Direct-input expiry | `each_direct_expiry_boundary_emits_a_strict_deny_envelope` | Expired manifest, policy, request, and revocation set each emit a strict DENY envelope with the documented reason. |
| Output expiry integrity | Expiry-boundary and calendar rollover tests | Stale DENY records use a minimal one-millisecond linked output interval; normal ALLOW records remain bounded by the earliest input expiry. |
| Revocation | Boundary matrix and supplied sequence evidence test | Stale revocation state and direct policy, subject, artifact, and key revocations deny deterministically. |
| Integrity | `altered_direct_inputs_fail_at_the_signature_boundary` | Altered manifest, policy, request, and revocation-set inputs are denied before policy evaluation. |
| Artifact declaration | Artifact mismatch and revoked-artifact cases | A request artifact must equal its manifest declaration before it can affect a decision. |
| Unavailable controls | Replay and required-approval tests | R2 has no durable replay or approval adapter and fails closed when either is mandatory. |
| Emitted evidence | Testkit independent verifier tests | The separate verifier recomputes local payload digests and linked decision, evidence, receipt, and expiry relationships. |
| Admission | Parser, profile, and CLI tests | Bounded input, duplicate-key, unknown-field, unsupported-profile, non-millisecond timestamp, and oversized-file failures are covered. |

## Explicit R2 Deferrals

The following Industrial 10 corpus requirements are deliberately not claimed by
R2 because the required model or dependency does not exist in this local
prototype:

| Requirement | R2 status | Required later gate |
| --- | --- | --- |
| Authenticated signing, key rotation, and key overlap | Deferred | Reviewed signing profiles, custody, rotation semantics, and independent vectors. |
| Approval satisfied path | Deferred | A defined approval document and resolver, with integrity and expiry semantics. |
| Durable replay detection and concurrency | Deferred | Scoped atomic replay storage and race testing. |
| Policy distribution, cyclic policy graphs, and supersession service | Deferred | Versioned policy graph and control-plane contract. |
| Tenant isolation | Deferred | Tenant registry, storage boundary, and cross-tenant integration tests. |
| SDK, hosted API, and local emulator | Deferred | Stable released interface contract and developer-platform implementation. |
| Fuzzing, property generation, cross-platform determinism, and performance limits | Deferred | Release-grade corpus, CI matrix, benchmark, and reproducibility evidence. |

`path`-like resource text is not resolved by R2 because it has no filesystem or
execution adapter. That does not establish a future path-security guarantee;
any adapter must define and test its own resource acquisition boundary.

## Interpretation Rules

- A passing R2 test proves only the stated local behavior for its bounded input.
- A `DENY` record is a local prototype record, never an instruction to execute.
- The local-unsigned marker detects changed payloads but does not authenticate a
  signer, establish key custody, or provide production cryptographic assurance.
- New accepted fields, profiles, or policy semantics require a contract update,
  negative vectors, compatibility assessment, threat-model update, and a new
  coverage review before promotion.
