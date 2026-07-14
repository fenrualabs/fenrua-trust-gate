# Dependency Inventory

Status: R2 prototype inventory; not a release SBOM or vulnerability attestation
Lockfile: `Cargo.lock` version 4
Review owner: A8 security and supply chain role, subject to named-maintainer confirmation

All entries are crates.io registry packages with Cargo checksums in the
applicable lockfile. Security state means only that the package is recorded for
R2 review; it does not assert that it has been audited, is vulnerability-free,
licence-cleared for release, or release-approved. The removal plan for each
transitive package is to remove its parent dependency or replace the parent
after reviewed design work.

| Package | Exact version | Licence | Purpose | Owner | Security state | Update policy | Removal plan |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `base64ct` | `1.8.3` | Apache-2.0 OR MIT | Direct strict Base64URL encoding for the source-only Ed25519 record. | A8 | Recorded, not release-approved. | Manual reviewed update with decoding tests. | Remove with the source-only Ed25519 prerequisite. |
| `block-buffer` | `0.10.4` | MIT OR Apache-2.0 | `sha2` buffering support. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `block-buffer` | `0.12.1` | MIT OR Apache-2.0 | `sha2` 0.11 buffering support for `ed25519-dalek`. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `cfg-if` | `1.0.4` | MIT OR Apache-2.0 | `sha2` platform conditional support. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `cpufeatures` | `0.2.17` | MIT OR Apache-2.0 | `sha2` CPU feature detection. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `cpufeatures` | `0.3.0` | MIT OR Apache-2.0 | `sha2` 0.11 CPU feature detection for `ed25519-dalek`. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `crypto-common` | `0.1.7` | MIT OR Apache-2.0 | Digest trait support for `sha2`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `crypto-common` | `0.2.2` | MIT OR Apache-2.0 | Digest trait support for `sha2` 0.11. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `curve25519-dalek` | `5.0.0` | BSD-3-Clause | Curve arithmetic implementation used by `ed25519-dalek`. | A8 | Recorded transitive, not release-approved. | Changes only with Ed25519 review and vectors. | Remove with `ed25519-dalek`. |
| `curve25519-dalek-derive` | `0.1.1` | MIT/Apache-2.0 | Compile-time support for curve arithmetic. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `curve25519-dalek`. |
| `digest` | `0.10.7` | MIT OR Apache-2.0 | Digest trait support for `sha2`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `digest` | `0.11.3` | MIT OR Apache-2.0 | Digest trait support for `sha2` 0.11. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `ed25519` | `3.0.0` | Apache-2.0 OR MIT | Ed25519 signature type dependency of `ed25519-dalek`. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `ed25519-dalek` | `3.0.0` | BSD-3-Clause | Direct standard Ed25519 signing and strict verification for the source-only prerequisite. | A8 | Recorded, not release-approved. | Manual reviewed update with vectors and independent review. | Remove with the source-only Ed25519 prerequisite. |
| `fiat-crypto` | `0.3.0` | MIT OR Apache-2.0 OR BSD-1-Clause | Target-conditional generated field arithmetic for curve support. | A8 | Recorded target-conditional transitive. | Changes only with curve review. | Remove with `curve25519-dalek`. |
| `generic-array` | `0.14.7` | MIT | Compile-time array support for digest dependencies. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `getrandom` | `0.4.3` | MIT OR Apache-2.0 | Dev-only ephemeral entropy for Ed25519 tests; no runtime key or identifier use. | A8 | Recorded test-only, not release-approved. | Manual reviewed update with test-boundary review. | Remove with Ed25519 tests. |
| `hybrid-array` | `0.4.13` | MIT OR Apache-2.0 | Array support for `sha2` 0.11. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `libc` | `0.2.186` | MIT OR Apache-2.0 | Platform support for `cpufeatures`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `proc-macro2` | `1.0.106` | MIT OR Apache-2.0 | Macro token support for curve derive code. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `curve25519-dalek-derive`. |
| `quote` | `1.0.46` | MIT OR Apache-2.0 | Macro output support for curve derive code. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `curve25519-dalek-derive`. |
| `r-efi` | `6.0.0` | MIT OR Apache-2.0 OR LGPL-2.1-or-later | Target-conditional UEFI support for test-only `getrandom`. | A8 | Recorded target-conditional test transitive. | Changes only with `getrandom` review. | Remove with `getrandom`. |
| `rustc_version` | `0.4.1` | MIT OR Apache-2.0 | Build-time compiler capability check for curve arithmetic. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `curve25519-dalek`. |
| `semver` | `1.0.28` | MIT OR Apache-2.0 | Version parsing for `rustc_version`. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `rustc_version`. |
| `sha2` | `0.10.9` | MIT OR Apache-2.0 | Direct SHA-256 implementation for canonical digests. | A8 | Recorded, not release-approved. | Manual reviewed update with vectors. | Remove only if a reviewed replacement is selected. |
| `sha2` | `0.11.0` | MIT OR Apache-2.0 | Ed25519 dependency hash implementation. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `signature` | `3.0.0` | Apache-2.0 OR MIT | Signature trait used by `ed25519-dalek`. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |
| `subtle` | `2.6.1` | BSD-3-Clause | Constant-time primitive support for curve arithmetic. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `curve25519-dalek`. |
| `syn` | `2.0.118` | MIT OR Apache-2.0 | Syntax parsing for curve derive code. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `curve25519-dalek-derive`. |
| `typenum` | `1.20.1` | MIT OR Apache-2.0 | Type-level numbers for digest dependencies. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `unicode-ident` | `1.0.24` | (MIT OR Apache-2.0) AND Unicode-3.0 | Identifier support for procedural macro parsing. | A8 | Recorded transitive. | Changes only with curve review. | Remove with `syn`. |
| `version_check` | `0.9.5` | MIT/Apache-2.0 | Build-time capability check for `generic-array`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `zeroize` | `1.9.0` | Apache-2.0 OR MIT | Zeroization support enabled by `ed25519-dalek`. | A8 | Recorded transitive. | Changes only with Ed25519 review. | Remove with `ed25519-dalek`. |

Workspace crates are source in this repository rather than external
dependencies and are intentionally omitted from the third-party table. The
full exact package set, including workspace crates, is enforced by
`ci/approved-lock-packages.txt`.

## Isolated Fuzz Workspace Additions

The bounded fuzz target is a separate nightly-only development workspace. It is
not an R2 runtime dependency, release artifact, or production security claim.
Its exact package set is enforced by `ci/approved-fuzz-lock-packages.txt` and
`scripts/check-fuzz-target.sh`. The additional licences below are recorded
for review, not approved for a release bundle.

| Package | Exact version | Licence | Purpose | Owner | Security state | Update policy | Removal plan |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `arbitrary` | `1.4.2` | MIT OR Apache-2.0 | Fuzz-input support required by libfuzzer-sys. | A8 | Recorded fuzz transitive, not release-approved. | Changes only with libfuzzer-sys review. | Remove with libfuzzer-sys. |
| `cc` | `1.2.67` | MIT OR Apache-2.0 | Builds the libFuzzer runtime. | A8 | Recorded fuzz transitive, not release-approved. | Changes only with libfuzzer-sys review. | Remove with libfuzzer-sys. |
| `find-msvc-tools` | `0.1.9` | MIT OR Apache-2.0 | Compiler discovery used by cc. | A8 | Recorded fuzz transitive, not release-approved. | Changes only with cc review. | Remove with cc. |
| `getrandom` | `0.4.3` | MIT OR Apache-2.0 | Process entropy dependency of jobserver. | A8 | Recorded fuzz transitive, not release-approved. | Changes only with jobserver review. | Remove with jobserver. |
| `jobserver` | `0.1.35` | MIT OR Apache-2.0 | Build-job coordination used by cc. | A8 | Recorded fuzz transitive, not release-approved. | Changes only with cc review. | Remove with cc. |
| `libfuzzer-sys` | `0.4.13` | (MIT OR Apache-2.0) AND NCSA | Isolated libFuzzer bindings and runtime. | A8 | Recorded fuzz direct dependency, not release-approved. | Exact-pin review with fuzz target evidence. | Remove the fuzz workspace. |
| `r-efi` | `6.0.0` | MIT OR Apache-2.0 OR LGPL-2.1-or-later | Target-conditional UEFI support for getrandom; not used by the Linux fuzz run. | A8 | Recorded fuzz transitive; licence choice requires release review. | Changes only with getrandom review. | Remove with getrandom. |
| `shlex` | `2.0.1` | MIT OR Apache-2.0 | C compiler command parsing used by cc. | A8 | Recorded fuzz transitive, not release-approved. | Changes only with cc review. | Remove with cc. |
