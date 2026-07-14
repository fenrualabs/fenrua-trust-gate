# R2 CI Boundary

The workflow performs only local source checks: formatting, linting, locked
tests, public-admission checks, dependency-policy checks, verifier isolation,
the R2 schema-pin record check, the bounded fuzz-target record guard, and the
vulnerability-management source-policy guard. Both third-party actions are
pinned by immutable full commit SHA. The CI job does not sign, publish, deploy,
upload evidence, contact a control plane, or claim a release.

Action revisions are visible in `.github/workflows/ci.yml` and must be
consciously updated with their corresponding supply-chain review.
