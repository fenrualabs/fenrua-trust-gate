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
| `sha2` | `0.10.9` | MIT OR Apache-2.0 | Direct SHA-256 implementation for canonical digests. | A8 | Recorded, not release-approved. | Manual reviewed update with vectors. | Remove only if a reviewed replacement is selected. |
| `block-buffer` | `0.10.4` | MIT OR Apache-2.0 | `sha2` buffering support. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `cfg-if` | `1.0.4` | MIT OR Apache-2.0 | `sha2` platform conditional support. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `cpufeatures` | `0.2.17` | MIT OR Apache-2.0 | `sha2` CPU feature detection. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `crypto-common` | `0.1.7` | MIT OR Apache-2.0 | Digest trait support for `sha2`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `digest` | `0.10.7` | MIT OR Apache-2.0 | Digest trait support for `sha2`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `generic-array` | `0.14.7` | MIT | Compile-time array support for digest dependencies. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `libc` | `0.2.186` | MIT OR Apache-2.0 | Platform support for `cpufeatures`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `typenum` | `1.20.1` | MIT OR Apache-2.0 | Type-level numbers for digest dependencies. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |
| `version_check` | `0.9.5` | MIT/Apache-2.0 | Build-time capability check for `generic-array`. | A8 | Recorded transitive. | Changes only with `sha2` review. | Remove with `sha2`. |

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
