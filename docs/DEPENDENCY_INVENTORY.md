# Dependency Inventory

Status: R1 bootstrap inventory; not a release SBOM or vulnerability attestation
Lockfile: `Cargo.lock` version 4
Review owner: A8 security and supply chain role, subject to named-maintainer confirmation

All entries are crates.io registry packages with Cargo checksums in the lockfile.
Security state means only that the package is recorded for R1 review; it does
not assert that it has been audited, is vulnerability-free, or is release
approved. The removal plan for each transitive package is to remove its parent
dependency or replace the parent after reviewed design work.

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
