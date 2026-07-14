# Cryptographic Profile Boundary

Status: only the local-unsigned R2 marker is active; no signer profile is released

R2 recognizes `local-unsigned-development` for a narrow local integrity check.
For this marker, the producer stores a domain-separated SHA-256 digest of the
canonical document with its top-level `signature` member excluded. The gate
checks that digest on each direct input; the separate verifier checks it on each
emitted output record.

This marker does **not** authenticate a signer, validate an identity, prove
possession of a key, provide non-repudiation, operate a private key, or replace
an approved signature scheme. It is deliberately limited to detecting a changed
local record within this prototype boundary.

The names `ed25519-v1`, `p256-v1`, and `enterprise-provider-v1` remain
reserved-unreleased in the active registry. They grant no CLI, Gate, verifier,
provider, generation, import, export, storage, rotation, or revocation
capability. Unknown names and aliases fail closed in the active local profile.

The `fenrua-crypto::ed25519_v1` module is a source-only prerequisite for a
later review. It accepts caller-owned in-memory material, binds `ed25519-v1`,
the canonicalization label, the stable key ID, and canonical JSON bytes into
the signed message, and verifies a strict Base64URL record. It is not a key
resolver or custody implementation and is not reachable from any R2 command or
document admission path. It does not promote the profile or change the R2
local-unsigned limitation. See `ADR-0003-ED25519_SOURCE_PROFILE.md`.

No private-key material belongs in source, fixtures, CLI output, error records,
or public documentation. Any authenticated profile requires a published
canonical-byte contract, mutation vectors, lifecycle controls, custody design,
independent cryptographic review, and a promotion decision.
