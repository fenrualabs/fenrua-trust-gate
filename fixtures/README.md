# Fixture Corpus

These fixtures are synthetic and contain no customer, provider, private key, or
production data. The `v1/` corpus tests parser/canonicalisation foundations;
the `r2/` corpus tests the bounded local prototype path. Neither is a release
vector set or production evidence.

- `valid/` contains exact JSON that should strict-parse.
- `invalid/` contains exact JSON that must fail before any schema handling.
- `golden/` records a canonical bytes/digest pair for deterministic regression
  testing.

No fixture may be changed merely to make an implementation bug pass. A fixture
change requires an explicit rationale and review.

## R2 local prototype

`r2/` contains synthetic, local-only inputs for the deterministic R2 workflow.
They intentionally use `local-unsigned-development`. Their local signature
payload digests bind the synthetic document bytes, while other declared digests
remain placeholders because the profile has no signer authentication or
artifact-byte verification. They are not production evidence, keys, approvals,
or examples of a released Trust Gate integration.
