# Compatibility Policy

Status: R2 local prototype record; no public compatibility commitment

`0.1.0-r2.0` identifies an unreleased source prototype. It offers no supported
platform list, SDK/API promise, support window, migration path, or persistence
guarantee. The accepted R2 subset is pinned to
`fenrua-specs/v0.1@268788e18bb39d69ffed706294d2605878f04c34` and rejects unknown
schemas, fields, profiles, and future versions.

The R2 CLI is an explicit local fixture interface, not a stable product API.
Its file commands and output envelope may change before a promotion decision.
Callers must not persist, distribute, or integrate against it as a supported
contract.

A future released compatibility policy must define semantic/schema/CLI/SDK/API
versioning, support and deprecation windows, migration, emergency deprecation,
and no-downgrade rules. No future profile may silently interpret a document that
this local profile rejects.
