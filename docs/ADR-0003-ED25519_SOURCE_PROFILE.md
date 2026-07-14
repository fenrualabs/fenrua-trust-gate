# ADR-0003: Source-Only Ed25519 Signing Prerequisite

Status: accepted for source preparation only; not a release or profile promotion

## Context

The R2 local profile intentionally accepts only
`local-unsigned-development`. It detects changed canonical payloads but does
not authenticate a signer. The compatibility schemas reserve `ed25519-v1`, but
the active Trust Gate, CLI, verifier, and profile registry must remain
unreleased until later R3 and release gates have evidence.

## Decision

`fenrua-crypto::ed25519_v1` adds a small source primitive using exact-pinned
reviewed `ed25519-dalek` and `base64ct` dependencies. It is not wired into R2
admission or command handling.

- Profile: `ed25519-v1` only; all other labels are rejected.
- Canonicalization label: `fenrua.c14n.ed25519-v1-r3-source-json`.
- Payload digest: SHA-256 over bounded canonical JSON in the distinct
  `ed25519-payload:r3-source` domain.
- Signed message: `fenrua-trust-gate`, the profile, canonicalization label,
  stable key ID, and canonical payload bytes, separated by NUL bytes in that
  order.
- Signature record: exact `profile`, `keyId`, `payloadDigest`, and `value`
  fields. The digest uses `sha-256` plus lowercase hexadecimal bytes; `value`
  is an unpadded Base64URL encoding of exactly 64 Ed25519 signature bytes.
- Key ID: the existing `urn:fenrua:key:` shape with lowercase ASCII letters,
  digits, and hyphens only. The verifier binds one caller-provided public key
  to one key ID and rejects relabelling before and during signature checking.
- Private material: caller-owned `SigningKey` is borrowed for the operation.
  This module has no private-key generation, import/export, persistence,
  logging, fixture, configuration, provider, or network code.

## Consequences

This supports contract-first testing of canonical-byte binding, profile
downgrade rejection, key-ID binding, digest checks, malformed-record rejection,
and standard Ed25519 verification. It does not create an R2 signing route or a
releasable authenticated profile.

Rotation and revocation are deliberately not implemented. A later key-lifecycle
layer must define trusted key discovery, scoped key metadata, overlap windows,
revocation authority and state, durable audit records, custody, recovery,
independent review, vectors, compatibility policy, and a signed release
decision before this profile can be admitted anywhere.

## Rejected Alternatives

- Treating the existing local digest marker as authentication: it has no key
  proof and would misrepresent the R2 boundary.
- Adding a custom Ed25519 implementation: unnecessary cryptographic risk.
- Enabling `ed25519-v1` in the R2 registry, Gate, CLI, or verifier now: that
  would bypass the required lifecycle and release gates.
- Storing test or operational private keys in source: prohibited. Tests obtain
  ephemeral process-local entropy and retain no key material in evidence.
