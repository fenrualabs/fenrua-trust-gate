# ADR-0002: JavaScript SDK and Repository Boundary

Status: accepted R2 source-boundary decision; no public SDK repository or
package is authorised by this record

Date: 2026-07-14

## Context

Industrial 10 workstream 5 calls for a strict TypeScript SDK after the local
Trust Gate interface stabilises. The repository-creation gate also requires an
ADR covering ownership, public classification, dependency direction, release,
secret and data boundaries, archival, maintenance, and alternatives before a
new repository is created.

The current R2 Trust Gate is an unreleased, local-only prototype. Its closed
profile is pinned to a governed schema revision, but the project has no released
schema contract, authenticated signing profile, supported-platform policy,
package provenance, or SDK compatibility commitment. Creating a public package
now would imply an integration surface that the source does not yet support.

## Decision

R2 will not create `fenrua-sdk-js`, publish an SDK package, or expose a
JavaScript API from this repository.

When the contract reaches the later promotion criteria below, the preferred
initial implementation is a generated `packages/sdk-js` package within
`fenrua-trust-gate`, provided it demonstrably reduces release and compatibility
complexity. A standalone public `fenrua-sdk-js` repository remains an option
only after the owner approves it and the package's independent maintenance and
release burden is justified.

The future SDK must expose only explicitly supported operations:

```text
validateManifest
validatePolicy
validateRequest
evaluate
verifyEvidence
inspectReceipt
listSupportedSchemas
```

It must not silently invoke a network service, create execution authority, or
claim production signing, tenant isolation, or hosted availability.

## Future Repository Gate

Before creating a package or repository, all of the following are required:

1. Owner approval for the public/private classification and repository choice.
2. Immutable released schemas and an explicit compatibility window.
3. A reviewed API-to-schema mapping with deterministic generated types.
4. A Node-supported version policy and explicit browser boundary.
5. Exact-pinned dependencies, no `any` in the public API, ESM build output,
   cancellation semantics, structured errors, and no network by default.
6. Deterministic cross-language vectors that agree with the Trust Gate and
   independent verifier on supported operations.
7. Release controls for versioning, SBOM, provenance, signing, changelog,
   known limitations, support ownership, and revocation or emergency response.
8. A public-source admission review confirming that no secret, customer data,
   private evidence, or provider credential can enter package source, fixtures,
   generated output, logs, or documentation.

## Ownership and Boundaries

| Concern | Decision |
| --- | --- |
| Initial owner | Fenrua engineering, with an owner-assigned package and release maintainer before publication. |
| Public classification | Deferred pending owner approval and completion of the future repository gate. |
| Source boundary | Public-safe schemas, generated types, deterministic fixtures, and docs only. |
| Artifact boundary | A release package is not source proof; it requires a signed artifact, digest, SBOM, provenance, and release manifest. |
| Dependency direction | Future SDK code may depend on immutable schema artifacts and generated types; it must not import a private control plane, secret store, or production key material. |
| Network boundary | No network by default. Any hosted client is a separately versioned, reviewed control-plane capability. |
| Data boundary | No customer, tenant, credential, or private evidence data belongs in public package tests or examples. |
| Secret boundary | No signing key, access token, environment secret, or provider credential may enter source, package artifacts, logs, or browser payloads. |
| Archival | If a standalone repository is later retired, preserve its signed releases, SBOMs, provenance, compatibility record, migration notice, and security contact. |
| Maintenance | No support-window or availability promise exists until an owner assigns maintainer, escalation, and release responsibilities. |

## Alternatives Considered

| Alternative | Decision | Reason |
| --- | --- | --- |
| Publish a standalone SDK now | Rejected for R2. | The current local profile is not a released or supported integration contract. |
| Add a hand-written package inside the Trust Gate now | Rejected for R2. | It would create a public API before stable generated types and compatibility policy exist. |
| Initial monorepo package after contract stabilisation | Preferred candidate. | It can share deterministic fixtures and release governance while keeping dependency direction visible. |
| Standalone `fenrua-sdk-js` after owner approval | Deferred option. | Appropriate only when independent release cadence and maintenance justify the repository. |

## Consequences

This decision preserves the truthful R2 boundary: the current CLI and local
library remain source-only prototype surfaces, and no SDK installation or
integration claim is made. It does not prevent SDK delivery; it defines the
minimum engineering and owner evidence required to do so without manufacturing
a premature developer platform.
