# Fenrua Trust Gate R1 Foundation

Status: R1 specification foundation, unreleased

This repository is the isolated Rust source foundation for a future local,
deterministic Fenrua Trust Gate. It exists under the owner-approved repository
boundary recorded in the wider programme. It is not a product release, hosted
service, public preview, SDK, API, security assurance statement, or evidence
that a Trust Gate workflow is available.

## What Is Present

- strict local JSON parsing with input, depth, collection, string, and number
  bounds;
- duplicate-object-key rejection before any deserialisation can overwrite a
  value;
- deterministic R1-draft canonical JSON and domain-separated SHA-256 digest
  primitives;
- non-leaky local problem envelopes containing only stable categories and an
  optional byte offset;
- bootstrap schema/profile discovery that explicitly accepts zero schemas and
  enables zero cryptographic operations;
- deterministic test-only clock and replay-checkpoint foundations;
- a thin `fenrua` discovery CLI with `version`, `schema list`, and `doctor`.

## What Is Deliberately Not Present

- released or accepted v1 schema definitions;
- manifest, policy, request, revocation, or evidence file handling;
- policy evaluation, `ALLOW`/`DENY` output, or execution control;
- evidence-bundle or receipt contracts;
- real signature verification, signing, key generation, private-key handling,
  provider integrations, key rotation, or revocation operations;
- HTTP, remote schema resolution, control-plane access, telemetry, databases,
  customer data, or filesystem adapters;
- a release artifact, SBOM, provenance, deployment, support commitment, or
  promotion beyond R1.

Those omissions are intentional. See
[R1 Scope and Deferred Work](docs/R1_SCOPE_AND_DEFERMENTS.md) and
[Promotion Gates](docs/PROMOTION_GATES.md).

## Workspace

| Crate | R1 responsibility | Explicit boundary |
| --- | --- | --- |
| `fenrua-protocol` | Strict bounded JSON, safe problem envelope, reserved-name discovery | Accepts no Trust Gate schema document. |
| `fenrua-c14n` | R1-draft canonical JSON and domain-separated SHA-256 primitives | Not a released canonicalisation profile. |
| `fenrua-crypto` | Reserved signing-profile registry | No signing, verification, or key operation. |
| `fenrua-gate` | Fail-closed evaluation boundary and replay trait | No policy/evaluation/decision implementation. |
| `fenrua-verify` | Generic canonical-digest comparison package boundary | Not an evidence-bundle verifier; never depends on `fenrua-gate`. |
| `fenrua-cli` | Truthful discovery adapter | No file I/O or product workflow commands. |
| `fenrua-testkit` | Deterministic test clock and in-memory replay fixture | Test-only; not an operational service. |

## Local Verification

The source pin is Rust `1.97.0`. After obtaining dependencies through an
approved channel, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./scripts/check-public-admission.sh
./scripts/check-dependency-policy.sh
./scripts/check-verifier-boundary.sh
```

The CLI is a static discovery surface, not a health check:

```bash
cargo run -p fenrua-cli -- version --json
cargo run -p fenrua-cli -- schema list --json
cargo run -p fenrua-cli -- doctor --json
```

## Security and Public-Source Boundary

Do not add secrets, customer data, private evidence, screenshots, raw audit
reports, scan dumps, working review material, or production payloads. The
admission policy and its local guard are documented in
[Repository Admission Policy](docs/REPOSITORY_ADMISSION_POLICY.md). Security
reporting is not yet operationally configured; see [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

## Document Map

- [R1 Scope and Deferred Work](docs/R1_SCOPE_AND_DEFERMENTS.md)
- [Trust Boundary](docs/TRUST_BOUNDARY.md)
- [Decision Semantics](docs/DECISION_SEMANTICS.md)
- [Cryptographic Profile Boundary](docs/CRYPTOGRAPHIC_PROFILES.md)
- [Dependency Inventory](docs/DEPENDENCY_INVENTORY.md)
- [Dependency Policy](docs/DEPENDENCY_POLICY.md)
- [Threat Model Index](docs/THREAT_MODEL_INDEX.md)
- [Promotion Gates](docs/PROMOTION_GATES.md)
- [Compatibility Policy](docs/COMPATIBILITY_POLICY.md)
