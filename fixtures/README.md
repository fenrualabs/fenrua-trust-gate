# R1 Synthetic Fixture Corpus

These fixtures are synthetic and contain no tenant, customer, provider, key,
or production data. They test local parser and canonicalisation primitives only;
they are not schema, policy, decision, evidence, receipt, or cryptographic
profile vectors.

- `valid/` contains exact JSON that should strict-parse.
- `invalid/` contains exact JSON that must fail before any schema handling.
- `golden/` records a canonical bytes/digest pair for deterministic regression
  testing.

No fixture may be changed merely to make an implementation bug pass. A fixture
change requires an explicit rationale and review.
