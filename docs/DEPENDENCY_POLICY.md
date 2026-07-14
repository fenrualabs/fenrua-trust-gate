# Dependency Policy

Status: active R1 source policy

## Rules

- Every direct and transitive package is pinned by `Cargo.lock`.
- Direct registry dependencies use an exact Cargo version requirement.
- Git dependencies, unchecked binary downloads, install scripts, telemetry-by-
  default dependencies, async runtimes, HTTP clients, URL resolvers, database
  clients, scripting engines, and generic error-erasure libraries are not
  admitted to the R1 decision foundation.
- A dependency change needs a purpose, Fenrua owner, exact version, licence,
  source, security state, update plan, and removal plan in
  `DEPENDENCY_INVENTORY.md` before the lockfile is refreshed.
- `scripts/check-dependency-policy.sh` compares the exact lockfile package set
  with `ci/approved-lock-packages.txt` and rejects Git sources.
- The R1 guard is not a vulnerability scan or legal opinion. Vulnerability,
  licence, and provenance review remain release-gate work.

## Current Direct Dependency

`sha2 = "=0.10.9"` is the only third-party direct dependency. It supplies an
established SHA-256 implementation for deterministic integrity primitives. R1
does not implement custom cryptographic algorithms and does not use `sha2` for
signing or private-key operations.

## Change Procedure

1. Open a reviewed change with the dependency purpose and threat impact.
2. Confirm no lower-level standard-library implementation is sufficient.
3. Update the inventory, approved package list, and lockfile together.
4. Run all locked checks without a post-acquisition network dependency.
5. Before a release, run the separately approved vulnerability, licence, SBOM,
   provenance, and reproducibility controls.
