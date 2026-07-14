# R2 Local Prototype Record

Status: active source prototype; unreleased and not publicly available

## Contract Pin

| Field | Value |
| --- | --- |
| Prototype version | `0.1.0-r2.0` |
| Compatibility profile | `urn:fenrua:compatibility-profile:local-unsigned-r2` |
| Schema registry | `https://github.com/fenrualabs/fenrua-specs` |
| Exact registry revision | `268788e18bb39d69ffed706294d2605878f04c34` |
| Schema pin | `fenrua-specs/v0.1@268788e18bb39d69ffed706294d2605878f04c34` |
| Evaluation envelope | `fenrua.local-evaluation.r2-draft` |
| Active marker | `local-unsigned-development` |

The R2 implementation does not make the `fenrua-specs` documents generally
available or immutable. It admits only the exact closed subset described below.

## Accepted Inputs

| Document | Required local role |
| --- | --- |
| `fenrua.entity-manifest.v1` | Active subject identity and declared capability. |
| `fenrua.authority-policy.v1` | Active policy containing the constrained rule subset. |
| `fenrua.tool-call-request.v1` | Subject, actor, action, resource, context, nonce, digest, and explicit replay requirement. |
| `fenrua.revocation-set.v1` | Scope, sequence, freshness window, and direct revocations. |

All direct inputs must be structurally admitted and use the exact local marker
and key identifier. The gate recomputes their local payload digest, but that
does not authenticate origin. Unsupported fields, profiles, document kinds, and
future schema versions fail closed.

R2 intentionally rejects the v1 request `sequence`, `challenge`, and
`policyRefs` fields, along with policy `obligations`, because this prototype
does not define their semantics. A known schema field is never silently
accepted and ignored.

## Evaluation Order

1. Parse bounded bytes and reject duplicate keys.
2. Structurally admit the closed R2 profile.
3. Check each direct local payload digest.
4. Check declared manifest-owner, policy-issuer, and revocation-issuer alignment,
   then scope, lifecycle, identity/capability, time, and revocation freshness.
5. Deny replay-sensitive requests because no durable replay state exists.
6. Check direct revocations before policy allow.
7. Evaluate matching constrained rules. An assessed explicit deny overrides
   allow; a base-matching deny whose required evidence or approval cannot be
   evaluated fails closed before an allow can win; no match denies.
8. Emit canonical decision, evidence bundle, receipt, and local envelope.
9. Recompute output integrity/link relationships in the separate verifier
   before the CLI writes the output.

## Output Boundary

The evaluator creates deterministic identifiers from a domain-separated digest
of the direct input documents and caller-supplied evaluation time. It creates no
random identifier, network event, or host observation. The evidence bundle
records direct document digests and the revocation sequence; it is not an
append-only service or a signed public record.

When a request includes an artifact reference, it must exactly equal a manifest
artifact declaration and be effective at the supplied evaluation time. R2 still
does not retrieve or hash artifact bytes; the accepted digest remains a local
declared value.

`fenrua receipt inspect` recomputes the receipt's local payload digest and
reports `LOCAL_PAYLOAD_MATCH` or `INTEGRITY_MISMATCH`. That result detects a
changed local receipt; it does not authenticate a signer.

`fenrua-verify` deliberately has no dependency on `fenrua-gate`. Its R2 result
means the emitted envelope's local payload digests and cross-record links were
recomputed successfully. It does not mean the verifier independently validated
the producer's policy semantics, authenticated a signer, or authorises execution.
The `fenrua.verification-result.v1` `inputDigest` binds the complete submitted
R2 evaluation envelope, which is the verifier's input, rather than an original
request file.

## Exit Conditions for This Prototype

The CI path must pass with the pinned Rust toolchain, lockfile, strict parser
tests, deterministic positive/negative tests, no gate dependency in the verifier,
public-admission scan, and this exact registry pin. Passing those checks does
not satisfy the R3/R4 release gates.
