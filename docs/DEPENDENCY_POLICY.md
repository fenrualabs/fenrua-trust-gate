# Dependency Policy

Status: active R2 source policy with a source-only Ed25519 prerequisite

## Rules

- Every direct and transitive package is pinned by the applicable lockfile:
  `Cargo.lock` for the stable R2 workspace and `fuzz/Cargo.lock` for the
  isolated nightly fuzz workspace.
- Direct registry dependencies use an exact Cargo version requirement.
- Git dependencies, unchecked binary downloads, install scripts, telemetry-by-
default dependencies, async runtimes, HTTP clients, URL resolvers, database
clients, scripting engines, and generic error-erasure libraries are not
admitted to the R2 local prototype. The source-only Ed25519 prerequisite does
not change that runtime boundary or enable a signing route.
- A dependency change needs a purpose, Fenrua owner, exact version, licence,
  source, security state, update plan, and removal plan in
  `DEPENDENCY_INVENTORY.md` before the lockfile is refreshed.
- `scripts/check-dependency-policy.sh` compares the stable exact lockfile
  package set with `ci/approved-lock-packages.txt` and rejects Git sources.
  `scripts/check-fuzz-target.sh` applies the same exact-set and Git-source
  guard to the isolated fuzz workspace, its curated seeds, and its target
  boundary markers.
- The R2 guard is not a vulnerability scan or legal opinion. Vulnerability,
  licence, and provenance review remain release-gate work.

## Current Direct Dependencies

`sha2 = "=0.10.9"` supplies the established SHA-256 implementation for
deterministic R2 integrity primitives. R2 does not implement custom
cryptographic algorithms and does not use `sha2` for signing or private-key
operations.

`ed25519-dalek = "=3.0.0"` and
`base64ct = { version = "=1.8.3", default-features = false, features = ["alloc"] }`
support only the unintegrated `fenrua-crypto::ed25519_v1` source prerequisite:
standard Ed25519 verification and strict unpadded Base64URL record encoding.
They do not enable R2 CLI, Gate, verifier, provider, storage, or release
operations.

`getrandom = "=0.4.3"` is a direct dev dependency used only to create
ephemeral process-local test material. It is not a runtime identifier source,
key store, configuration input, or evidence artifact.

The isolated, nightly-only fuzz workspace has one additional third-party direct
dependency: `libfuzzer-sys = "=0.4.13"`. It is used only to build the bounded
test target in `fuzz/`; it is not linked into the stable R2 CLI, Gate, or
verifier. Its NCSA runtime licence and target-conditional transitive licences
remain release-review work.

## Change Procedure

1. Open a reviewed change with the dependency purpose and threat impact.
2. Confirm no lower-level standard-library implementation is sufficient.
3. Update the inventory, approved package list, and lockfile together.
4. Run all locked checks without a post-acquisition network dependency.
5. Before a release, run the separately approved vulnerability, licence, SBOM,
   provenance, and reproducibility controls.
