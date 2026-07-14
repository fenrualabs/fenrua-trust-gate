# Threat Model Index

Status: R2 public-safe index; detailed threat models and independent review remain deferred

| Area | R2 boundary | Current mitigation | Remaining work |
| --- | --- | --- | --- |
| Strict parser | Direct caller supplies untrusted bytes. | Explicit size/depth/collection bounds, duplicate-key rejection, safe problems. | Fuzzing and release corpus. |
| Local profile admission | Caller can send unsupported fields or profile labels. | Closed allowed fields, exact version/marker, fail-closed rejection. | General schema engine and full vectors. |
| Local unsigned payload | Caller can alter a record or present a false origin. | Gate/verifier recompute local payload digest. | Authenticated signing profile, custody, rotation, and external review. |
| Evaluation | Policy inputs can conflict or omit controls. | Scope/time/revocation checks, explicit deny overrides, no-match deny, no execution adapter. | Full policy/approval semantics and independent policy reproduction. |
| Context and audience | Caller can substitute a valid request into a different audience or context. | R2 requires one exact v2 policy context selector and denies audience or context mismatches before a rule can allow. | Versioned compatibility profile and cross-implementation vectors. |
| Replay | A request can be replay-sensitive. | R2 denies every replay-required request. | Scoped durable atomic cache and concurrency testing. |
| Evidence output | Output may be tampered with or links may disagree. | Separate verifier recomputes emitted payload digests and document links. | Independent assurance, append-only semantics, retention, and export. |
| File output | Caller path can exist, fail, or be raced. | Explicit path, `create_new`, `sync_all`, non-leaky I/O failure. | Atomic publication/recovery design and platform coverage. |
| CLI supply chain | Local build invokes Rust toolchain and lockfile. | Pinned toolchain, exact lockfile, CI checks. | Signed artifacts, provenance, SBOM. |
| Public repository | Public source can receive unsafe evidence. | Admission policy and CI guard. | Protected branches, push protection, named CODEOWNERS. |

This index is not a security assessment or a statement that all future threat
models are complete. Each new capability requires assets, actors, trust
boundaries, entry points, abuse cases, mitigations, residual risk, evidence,
owner, and review date.
