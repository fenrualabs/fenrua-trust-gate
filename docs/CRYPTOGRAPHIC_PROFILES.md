# Cryptographic Profile Boundary

Status: bootstrap profile-name registry; no profile implementation or release

The following names are copied from the approved bootstrap contract solely for
exact discovery and future compatibility planning:

- `local-unsigned-development`
- `ed25519-v1`
- `p256-v1`
- `enterprise-provider-v1`

Every entry has status `reserved-unreleased`. Looking up a known name grants no
signing, verification, provider, key generation, import, export, storage, or
rotation capability. Unknown names fail closed; aliases such as `Ed25519` are
not accepted.

No private key material is represented in source, tests, fixtures, CLI output,
problem envelopes, or documentation examples. A future profile requires a
published specification, canonical byte definition, mutation vectors, key
lifecycle controls, independent cryptographic review, and a release decision
before it can be used for a product claim.
