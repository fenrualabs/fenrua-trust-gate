# Compatibility Policy

Status: R2 local prototype record; no public compatibility commitment

`0.1.0-r2.0` identifies an unreleased source prototype. It offers no supported
platform list, SDK/API promise, support window, migration path, or persistence
guarantee. The accepted R2 subset is pinned to
`fenrua-specs/v0.2@3ed6e685aeacb537ef0138e5227d0ddf98cf94ff` and rejects unknown
schemas, fields, profiles, and future versions.

R2 directly admits `fenrua.authority-policy.v2` only. It retains the immutable
v1 policy identifier for evidence-reference compatibility, but rejects a v1
policy as a direct evaluation input rather than silently dropping its missing
context semantics.

R2 emits `fenrua.evidence-bundle.v2` so its evidence references can bind the
direct v2 policy. Its decision, receipt, and verifier-result records remain
their v1 identities; this does not create a compatibility-profile claim.

The R2 CLI is an explicit local fixture interface, not a stable product API.
Its file commands and output envelope may change before a promotion decision.
Callers must not persist, distribute, or integrate against it as a supported
contract.

A future released compatibility policy must define semantic/schema/CLI/SDK/API
versioning, support and deprecation windows, migration, emergency deprecation,
and no-downgrade rules. No future profile may silently interpret a document that
this local profile rejects.
