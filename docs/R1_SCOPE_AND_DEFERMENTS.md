# R1 Foundation and R2 Local Prototype Scope

Status: R1 foundation retained; R2 local-only prototype active
Last reviewed: 2026-07-14

R1 established bounded parsing, canonicalisation, safe failure records,
reserved profile discovery, and deterministic test scaffolding. R2 builds a
narrow local workflow on that foundation. It is not a promotion to a reference
implementation, limited preview, or public product release.

## Delivered R2 Boundary

- closed structural admission for entity manifest, authority policy, tool-call
  request, revocation set, decision, evidence bundle, receipt, verification
  result, and R2 evaluation envelope;
- a source pin to `fenrua-specs/v0.1@268788e18bb39d69ffed706294d2605878f04c34`;
- deterministic local-unsigned payload-digest checking for the four direct
  inputs and all emitted records;
- deterministic time/freshness, scope, identity, revocation, constrained-rule,
  deny-overrides, and no-match-deny behavior;
- deterministic decision, evidence bundle, receipt, and separate local
  envelope-integrity verifier;
- explicit-file CLI commands and public-safe synthetic fixtures.

## Deferred by Design

| Capability | Why it remains deferred | Minimum later gate |
| --- | --- | --- |
| General v1 schema support | R2 only accepts a closed profile subset. | Immutable released schemas and complete vectors. |
| Signer authentication and keys | Local unsigned payload digest is not a signature. | Reviewed profile, custody, rotation, and vectors. |
| Durable replay control | R2 fails closed when replay state is mandatory. | Scoped atomic storage and concurrency tests. |
| Approvals and policy distribution | There is no control plane or approval adapter. | Signed policy/approval design and integration tests. |
| Artifact-byte integrity | R2 records caller-declared payload digests only. | Defined artifact acquisition and byte-binding contract. |
| Independent policy assurance | The verifier checks emitted integrity and links only. | Separate policy implementation/reproduction review. |
| Release and availability | Source and tests are not a release. | R3 to R4 gates in `PROMOTION_GATES.md`. |

No R2 source record claims production readiness, cryptographic assurance,
tenant isolation, availability, support, certification, or a completed public
Trust Gate offering.
