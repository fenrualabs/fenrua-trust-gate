# Threat Model Index

Status: R1 public-safe index; detailed threat models deferred to capability work

| Area | R1 boundary | Current mitigation | Remaining work |
| --- | --- | --- | --- |
| Strict parser | Direct caller supplies untrusted bytes. | Explicit size/depth/collection bounds, duplicate-key rejection, safe problems. | Fuzzing and release corpus. |
| Canonicalisation | Caller may construct values outside parser. | Independent canonicalisation bounds, ordered maps, exact decimal normalization. | Differential and external crypto review. |
| CLI supply chain | Local build invokes Rust toolchain and lockfile. | Pinned toolchain, exact lockfile, CI checks. | Signed artifacts, provenance, SBOM. |
| Public repository | Public source can receive unsafe evidence. | Admission policy and CI guard. | Protected branches, push protection, named CODEOWNERS. |
| Profile labels | Labels could be mistaken for key capability. | All labels reserved-unreleased; no key API. | Profile spec, custody, vectors, review. |
| Replay | Future replay control needs durable atomic state. | Trait plus deterministic test fixture only. | Scoped atomic store and concurrency testing. |
| Evidence verifier | Producer/verifier coupling could be misleading. | Separate crate with no `fenrua-gate` dependency; no evidence claim. | Released bundle contract and independently reviewed verifier. |

This index is not a security assessment or a statement that all future threat
models are complete. Each new capability requires assets, actors, trust
boundaries, entry points, abuse cases, mitigations, residual risk, evidence,
owner, and review date.
