# Fenrua Trust Gate R2 Local Prototype

Status: unreleased R2 local-only prototype, `0.1.0-r2.0`

This public Rust workspace is a bounded prototype of the local Fenrua Trust
Gate decision path. It is not a product release, hosted service, SDK, API,
security assurance statement, or proof that a Trust Gate workflow is publicly
available. The repository accepts a closed local subset of the separately
governed `fenrua-specs` v0.1 registry at
`268788e18bb39d69ffed706294d2605878f04c34`.

## R2 Local Path

The implemented prototype accepts four explicit local JSON files:

- entity manifest;
- authority policy;
- tool-call request;
- revocation set.

It then performs bounded parsing, duplicate-key rejection, closed-profile
structural admission, local-unsigned payload-digest checks, caller-supplied
UTC-millisecond time checks, freshness/revocation checks, deterministic
deny-overrides policy evaluation, and deterministic local evidence generation.
It emits a decision, evidence bundle, and human-readable receipt in one R2
envelope. A separate `fenrua-verify` crate recomputes that envelope's emitted
payload digests and cross-document relationships without depending on
`fenrua-gate`.

`ALLOW` is a local prototype record only. It is never an instruction to
execute an action.

## Explicit Limitations

- The R2 validator is a closed local-profile implementation, not a general
  JSON Schema engine or a release of the v1 schemas.
- `local-unsigned-development` detects a changed local payload digest but does
  not authenticate a signer identity, perform a key operation, or establish
  key custody.
- The input `payloadDigest` fields remain caller-declared because artifact
  bytes are outside this profile.
- No network, remote schema lookup, telemetry, database, environment lookup,
  random ID source, wall-clock read, durable replay store, approval adapter,
  or execution adapter exists.
- A replay-sensitive request is denied because R2 has no durable replay state.
- The separate verifier checks emitted local-envelope integrity and links. It
  does not re-evaluate policy, independently assure the decision, or create
  execution authority.
- There is no signed artifact, SBOM, provenance, supported-platform matrix,
  preview, compatibility commitment, or public availability claim.

See [R2 Local Prototype](docs/R2_LOCAL_PROTOTYPE.md),
[Decision Semantics](docs/DECISION_SEMANTICS.md), and
[Promotion Gates](docs/PROMOTION_GATES.md).

## Local Commands

```bash
cargo run -p fenrua-cli -- version --json
cargo run -p fenrua-cli -- schema list --json
cargo run -p fenrua-cli -- gate evaluate \
  --manifest fixtures/r2/manifest.json \
  --policy fixtures/r2/policy-allow.json \
  --request fixtures/r2/request-offline.json \
  --revocations fixtures/r2/revocations-current.json \
  --at 2026-07-14T00:01:00.000Z \
  --output /tmp/fenrua-r2-evaluation.json
cargo run -p fenrua-cli -- evidence verify /tmp/fenrua-r2-evaluation.json
```

The output path must not already exist. R2 uses `create_new` followed by
`sync_all`; it does not claim an atomic multi-file publication protocol.

## Local Verification

Rust `1.97.0` is pinned in `rust-toolchain.toml`. After dependencies have been
obtained through an approved channel, run:

```bash
./ci/r2-checks.sh
```

The checks run formatting, lints, locked tests, public-admission controls,
dependency-policy controls, verifier dependency isolation, and the exact R2
schema-pin record check.

## Workspace

| Crate | R2 responsibility | Boundary |
| --- | --- | --- |
| `fenrua-protocol` | Strict parser and closed local-profile admission | No general schema engine or released schema claim. |
| `fenrua-c14n` | Deterministic canonical JSON and domain-separated SHA-256 | Not a released canonicalisation profile. |
| `fenrua-crypto` | Profile discovery | No signing, verification, or key operations. |
| `fenrua-gate` | Deterministic local evaluation and evidence construction | No network, durable replay, or execution adapter. |
| `fenrua-verify` | Separate local-envelope integrity and link verifier | Does not re-evaluate policy or depend on `fenrua-gate`. |
| `fenrua-cli` | Explicit local file adapter | No remote API, background service, or hidden configuration. |
| `fenrua-testkit` | Deterministic fixtures and test replay model | Test-only; not operational replay protection. |

## Security and Source Boundary

Do not add secrets, customer data, private evidence, screenshots, raw audit
reports, scan dumps, or working-review material. See
[Repository Admission Policy](docs/REPOSITORY_ADMISSION_POLICY.md) and
[SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
