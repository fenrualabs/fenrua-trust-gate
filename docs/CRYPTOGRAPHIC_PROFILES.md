# Cryptographic Profile Boundary

Status: only the local-unsigned R2 marker is implemented; no signer profile is released

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
reserved-unreleased. They grant no signing, verification, provider, generation,
import, export, storage, rotation, or revocation capability. Unknown names and
aliases fail closed in the active local profile.

No private-key material belongs in source, fixtures, CLI output, error records,
or public documentation. Any authenticated profile requires a published
canonical-byte contract, mutation vectors, lifecycle controls, custody design,
independent cryptographic review, and a promotion decision.
