# R2 Threat Model Register

Status: source-bounded R2 security register for the unreleased local prototype.

This register satisfies the record structure required by Industrial 10 workstream
9 section 19.1 without representing deferred product planes as implemented.
R2 is a local, explicit-file evaluator with no network, hosted API, key
operation, durable replay store, policy distribution client, tenant state,
control plane, telemetry source, backup process, or execution adapter. An ALLOW
record is never an instruction to execute an action.

The register uses P1 to mean a required promotion gate before a corresponding
release or product plane can be claimed. It does not call an unimplemented
plane resolved. The evidence paths below are source and local-test evidence,
not an independent security assessment, production deployment, or operational
assurance.

## R2 Review Rules

- Review this register before R3 promotion and before accepting a new profile,
  policy semantic, execution adapter, network path, storage path, SDK, or
  hosted service.
- A future capability needs an ADR or RFC, data-flow review, compatibility
  assessment, negative tests, and an updated record before activation.
- Independent review remains an owner-controlled promotion dependency. The
  current source tests do not substitute for it.

### TM-R2-001 Local Trust Gate

- Classification: P1 promotion gate; source-bounded local evaluator exists.
- Assets: Local decision, evidence, and receipt envelopes; subject, policy, request, and revocation inputs.
- Actors: Local caller, untrusted input producer, repository maintainer, and future promotion approver.
- Trust boundaries: Caller-supplied bytes cross the bounded parser into local admission and deterministic evaluation.
- Entry points: Four explicit local files and one caller-supplied UTC-millisecond evaluation timestamp.
- Abuse cases: Malformed or oversized documents, duplicate keys, conflicting identity data, future timestamps, stale inputs, or an ALLOW record presented as execution authority.
- Current mitigation: Closed-profile parsing, bounded JSON, direct integrity checks, scope/time/revocation checks, explicit deny override, no-match deny, and no execution adapter.
- Residual risk: The local-unsigned profile provides no signer authentication, durable replay control, approval resolver, artifact-byte acquisition, or independent semantics reproduction.
- Evidence: docs/TRUST_BOUNDARY.md; docs/DECISION_SEMANTICS.md; docs/R2_TEST_COVERAGE.md; crates/fenrua-gate/src/lib.rs.
- Owner: Fenrua security engineering; promotion approver assignment remains owner-controlled.
- Review date: 2026-07-14; repeat before R3 or any evaluator-boundary change.

### TM-R2-002 Policy Bundle

- Classification: P1 promotion gate; R2 admits one constrained local policy document.
- Assets: Policy issuer, scope, effective window, context selector, rules, requirements, and output policy link.
- Actors: Local policy author, untrusted policy-file producer, caller, and future policy publisher.
- Trust boundaries: Untrusted policy bytes cross local parser and profile admission before rule evaluation.
- Entry points: The explicit policy file supplied to local CLI evaluation.
- Abuse cases: Unknown fields, unsupported profiles, issuer/scope mismatch, future issue date, expired rule, allow-rule substitution, or bypass of explicit deny.
- Current mitigation: Exact allowed fields, profile marker, UTC-millisecond parsing, issuer/scope alignment, half-open time windows, context/audience matching, explicit deny override, and no-match deny.
- Residual risk: There is no authenticated policy signature, distribution service, supersession graph, approval resolver, or independent policy engine.
- Evidence: docs/R2_LOCAL_PROTOTYPE.md; docs/DECISION_SEMANTICS.md; docs/R2_TEST_COVERAGE.md; crates/fenrua-gate/src/lib.rs.
- Owner: Fenrua security engineering; future policy-governance owner must be named before activation.
- Review date: 2026-07-14; repeat before policy distribution or new rule semantics.

### TM-R2-003 Revocation Bundle

- Classification: P1 promotion gate; R2 admits one constrained local revocation document.
- Assets: Revocation issuer, scope, sequence, freshness window, direct revocation targets, and stale-state decisions.
- Actors: Local revocation-file producer, caller, untrusted input producer, and future revocation publisher.
- Trust boundaries: Caller-provided revocation bytes enter bounded parsing and freshness checks without remote lookup.
- Entry points: The explicit revocations file supplied to local CLI evaluation.
- Abuse cases: Stale or future revocation state, scope or issuer mismatch, target substitution, replay of an old bundle, or reliance on an absent remote source.
- Current mitigation: Exact profile admission, direct integrity check, issuer/scope alignment, explicit issued/effective/expires/next-update checks, and fail-closed stale decisions.
- Residual risk: No authenticated distribution, sequence service, durable cache, key rotation, or remote freshness verification exists.
- Evidence: docs/DECISION_SEMANTICS.md; docs/R2_TEST_COVERAGE.md; crates/fenrua-gate/src/lib.rs.
- Owner: Fenrua security engineering; future revocation-service owner must be named before activation.
- Review date: 2026-07-14; repeat before a revocation publication or cache design.

### TM-R2-004 Evidence Bundle

- Classification: P1 promotion gate; R2 emits a local evidence envelope only.
- Assets: Decision, evidence, receipt, payload digests, document links, scope, policy, request digest, and expiry link.
- Actors: Local caller, output-file reader, tampering party, verifier user, and future evidence custodian.
- Trust boundaries: Local evaluator output crosses to a caller-selected filesystem path and later into a separate local verifier.
- Entry points: CLI output path, local evidence verification command, and caller-provided evidence file.
- Abuse cases: Envelope tampering, inconsistent duplicated fields, altered linked digest, stale evidence replay, path collision, or a verifier PASS misrepresented as authorization.
- Current mitigation: Canonical local envelope, create-new output, sync-all, separate verifier without Gate dependency, digest/link recomputation, and explicit local-unsigned finding.
- Residual risk: No authenticated signing, append-only storage, retention policy, evidence upload, custody chain, export control, or independent assurance exists.
- Evidence: docs/TRUST_BOUNDARY.md; docs/R2_TEST_COVERAGE.md; crates/fenrua-cli/src/lib.rs; crates/fenrua-verify/src/lib.rs.
- Owner: Fenrua security engineering; evidence-custody owner must be named before promotion.
- Review date: 2026-07-14; repeat before any retained or shared evidence workflow.

### TM-R2-005 CLI Supply Chain

- Classification: P1 promotion gate; local Rust CLI source and locked dependencies exist.
- Assets: Source tree, Cargo.lock, pinned toolchain, CI scripts, local binary, test corpus, and release identity.
- Actors: Maintainer, dependency publisher, CI runner, local builder, repository contributor, and malicious package source.
- Trust boundaries: Checked-in source and lockfile cross into local builds and CI; dependencies are trusted only through recorded policy.
- Entry points: Cargo manifests and lockfile, CI workflow, build scripts, local command invocation, and repository changes.
- Abuse cases: Dependency substitution, stale or vulnerable dependency, malicious build step, toolchain drift, unsafe source admission, or unsigned binary distribution.
- Current mitigation: Locked Cargo commands, pinned toolchain, dependency inventory/policy checks, public-admission guard, CI checks, and source-only scope statement.
- Residual risk: No signed release artifact, provenance attestation, SBOM release bundle, protected-branch proof, or independent build verification exists.
- Evidence: docs/DEPENDENCY_INVENTORY.md; docs/DEPENDENCY_POLICY.md; ci/r2-checks.sh; scripts/check-dependency-policy.sh; scripts/check-public-admission.sh.
- Owner: Fenrua security engineering with repository maintainer review; release owner remains owner-controlled.
- Review date: 2026-07-14; repeat before public artifact release or dependency-policy change.

### TM-R2-006 SDK Supply Chain

- Classification: Not applicable to R2; P1 gate before any SDK repository, package, or distribution exists.
- Assets: Future SDK source, generated types, package artifact, registry identity, compatibility vectors, and consumer trust.
- Actors: Future SDK maintainer, package publisher, application developer, dependency attacker, and package-registry user.
- Trust boundaries: No SDK package or SDK runtime boundary exists in R2; any future package creates a new consumer boundary.
- Entry points: None in R2; future package registry, installer, public API, and generated artifact are explicitly deferred.
- Abuse cases: Informal SDK release, incompatible type mapping, registry impersonation, network-by-default behavior, or unsafe consumer integration.
- Current mitigation: ADR-0002 prohibits SDK/package work without owner approval and enumerates preconditions including immutable schemas and compatibility vectors.
- Residual risk: The absence of an SDK prevents these attacks today but supplies no future package, provenance, support, or revocation control.
- Evidence: docs/ADR-0002-SDK_REPOSITORY_BOUNDARY.md; docs/R2_TEST_COVERAGE.md; docs/PROMOTION_GATES.md.
- Owner: Product and security owners must jointly approve and name SDK ownership before activation.
- Review date: 2026-07-14; repeat before any SDK design, package, or public interface.

### TM-R2-007 Control Plane

- Classification: Not applicable to R2; P1 gate before any hosted policy, configuration, or orchestration plane exists.
- Assets: Future policy state, rollout controls, service identities, configuration, audit trail, and tenant routing.
- Actors: Future operator, administrator, service account, tenant, attacker, and incident responder.
- Trust boundaries: No control-plane process, API, database, or network identity exists in R2.
- Entry points: None in R2; future management API, deployment system, and policy publisher require a new design.
- Abuse cases: Unauthorized policy change, rollout bypass, privilege escalation, configuration drift, service impersonation, or audit suppression.
- Current mitigation: R2 has no hosted control plane, and local evaluation accepts only explicit caller files under the documented prototype boundary.
- Residual risk: No control-plane authorization, change approval, audit log, recovery process, or independent review exists because the plane is unimplemented.
- Evidence: docs/TRUST_BOUNDARY.md; docs/R1_SCOPE_AND_DEFERMENTS.md; docs/PROMOTION_GATES.md.
- Owner: Product and security owners must name a control-plane owner before activation.
- Review date: 2026-07-14; repeat before any hosted management or policy-distribution service.

### TM-R2-008 Tenant Isolation

- Classification: Not applicable to R2; P1 gate before multi-tenant data or service processing exists.
- Assets: Future tenant identities, policy data, evidence, keys, quotas, audit records, and tenant-scoped operations.
- Actors: Future tenants, tenant administrators, service operators, support staff, and cross-tenant attacker.
- Trust boundaries: R2 has no tenant registry, authenticated caller, shared storage, network service, or tenant-scoped state.
- Entry points: None in R2; future API, storage, identity, and support boundaries are deferred.
- Abuse cases: Cross-tenant reads, writes, policy substitution, key reuse, quota bypass, support misuse, or noisy-neighbor denial of service.
- Current mitigation: No multi-tenant runtime exists; the local prototype makes no tenant-isolation claim.
- Residual risk: Absence of a multi-tenant feature is not a future isolation design, test suite, access-control model, or data-retention control.
- Evidence: docs/TRUST_BOUNDARY.md; docs/R2_TEST_COVERAGE.md; docs/PROMOTION_GATES.md.
- Owner: Product, security, and platform owners must name tenancy ownership before activation.
- Review date: 2026-07-14; repeat before accepting tenant data or introducing shared state.

### TM-R2-009 Key Lifecycle

- Classification: P1 promotion gate; R2 intentionally uses a local-unsigned development marker, not authentication.
- Assets: Future signing keys, key identifiers, custody records, rotation schedule, revocation state, and verification policy.
- Actors: Future signer, key custodian, build system, verifier, attacker, and recovery operator.
- Trust boundaries: R2 performs no key operation, key storage, signing, remote verification, rotation, or custody action.
- Entry points: None for real keys in R2; local profile fields are parser-checked markers only.
- Abuse cases: A local digest presented as a signature, spoofed key identity, stale key, key compromise, unauthorized signing, or failed rotation.
- Current mitigation: The profile is explicitly named local-unsigned-development; source, CLI help, verifier findings, and documentation state that it does not authenticate a signer.
- Residual risk: No real key lifecycle, signing profile, custody, hardware protection, rotation, overlap, revocation, or cryptographic review exists.
- Evidence: docs/CRYPTOGRAPHIC_PROFILES.md; docs/R1_SCOPE_AND_DEFERMENTS.md; crates/fenrua-protocol/src/r2.rs; crates/fenrua-verify/src/lib.rs.
- Owner: Security owner and designated key custodian must be named before any production profile.
- Review date: 2026-07-14; repeat before accepting an authenticated profile or signing artifact.

### TM-R2-010 Evidence Upload

- Classification: Not applicable to R2; P1 gate before any upload, storage, or sharing endpoint exists.
- Assets: Future evidence payloads, metadata, access tokens, retention rules, audit records, and data-subject information.
- Actors: Future uploader, evidence recipient, service operator, support staff, attacker, and privacy reviewer.
- Trust boundaries: R2 writes only one caller-selected local file and has no network client or evidence receiver.
- Entry points: None in R2; future upload API, object storage, export, and webhook paths are deferred.
- Abuse cases: Unauthorized upload, metadata leakage, content tampering, retention failure, cross-tenant disclosure, malware upload, or export bypass.
- Current mitigation: No upload implementation, remote storage, or telemetry path exists; local output is described as prototype data outside repository custody.
- Residual risk: No authorization, scanning, encryption, retention, deletion, audit, incident, or privacy control exists for a future upload system.
- Evidence: docs/TRUST_BOUNDARY.md; docs/R2_TEST_COVERAGE.md; crates/fenrua-cli/src/lib.rs.
- Owner: Product, security, privacy, and operations owners must name evidence-service ownership before activation.
- Review date: 2026-07-14; repeat before network transfer or evidence retention is introduced.

### TM-R2-011 Public Verifier

- Classification: P1 promotion gate; a separate local verifier crate exists, not a hosted public service.
- Assets: Local evidence envelope, verification findings, verifier binary, profile marker, and caller interpretation.
- Actors: Local verifier user, evidence producer, tampering party, maintainer, and future public user.
- Trust boundaries: Caller-provided evidence bytes cross the verifier parser; the verifier is intentionally separate from the Gate crate.
- Entry points: Local evidence verification and receipt inspection commands with caller-supplied files.
- Abuse cases: Malformed evidence, altered linked data, false PASS interpretation, profile confusion, binary substitution, or a request to verify authenticity that R2 cannot prove.
- Current mitigation: Strict R2 parsing, local digest and link recomputation, profile/key marker checks, structured findings, no Gate dependency, and explicit unauthenticated-profile notice.
- Residual risk: The verifier does not authenticate input origin or rerun policy semantics; no hosted endpoint, rate limit, authentication, availability, or abuse control exists.
- Evidence: docs/TRUST_BOUNDARY.md; docs/R2_TEST_COVERAGE.md; crates/fenrua-verify/src/lib.rs; scripts/check-verifier-boundary.sh.
- Owner: Fenrua security engineering; public-service ownership and independent verification scope remain owner-controlled.
- Review date: 2026-07-14; repeat before public hosting, SDK exposure, or assurance claim.

### TM-R2-012 Observation Gateway

- Classification: Not applicable to R2; P1 gate before telemetry, metrics, tracing, or observation ingress exists.
- Assets: Future logs, metrics, traces, service identities, customer metadata, alerts, and operational evidence.
- Actors: Future operator, monitoring provider, tenant, administrator, attacker, and incident responder.
- Trust boundaries: R2 reads no telemetry source and emits no network telemetry, metrics, traces, or observation events.
- Entry points: None in R2; future collector, dashboard, agent, and alert webhooks are deferred.
- Abuse cases: Sensitive data exfiltration, forged metrics, alert suppression, log injection, telemetry endpoint compromise, or cross-tenant observation.
- Current mitigation: No observation gateway is implemented; source documentation explicitly excludes telemetry from the local evaluator boundary.
- Residual risk: No observability privacy model, transport security, retention, alerting, on-call process, or tamper resistance exists for a future service.
- Evidence: docs/TRUST_BOUNDARY.md; crates/fenrua-gate/src/lib.rs; crates/fenrua-cli/src/lib.rs.
- Owner: Platform and security owners must name observation ownership before activation.
- Review date: 2026-07-14; repeat before adding telemetry, metrics, traces, or alerting.

### TM-R2-013 Admin Plane

- Classification: Not applicable to R2; P1 gate before administrative access, roles, or privileged controls exist.
- Assets: Future administrator identities, role assignments, configuration, audit trail, break-glass actions, and approvals.
- Actors: Future administrator, support staff, operator, attacker, auditor, and incident responder.
- Trust boundaries: R2 has no administrative API, authentication, authorization, database, or privileged remote control.
- Entry points: None in R2; future console, CLI administration, API, and support workflow are deferred.
- Abuse cases: Privilege escalation, unauthorized configuration, role confusion, break-glass abuse, audit deletion, or emergency bypass.
- Current mitigation: No admin plane is implemented, and R2 has no execution adapter or remote configuration path.
- Residual risk: No identity assurance, least privilege, segregation of duties, session control, audit retention, or emergency-access process exists for a future plane.
- Evidence: docs/TRUST_BOUNDARY.md; docs/R1_SCOPE_AND_DEFERMENTS.md; docs/PROMOTION_GATES.md.
- Owner: Product, security, and operations owners must name administrative ownership before activation.
- Review date: 2026-07-14; repeat before any privileged interface or support process.

### TM-R2-014 CI/CD

- Classification: P1 promotion gate; local CI checks and repository scripts exist, but release pipeline assurance is incomplete.
- Assets: Source history, CI configuration, test results, dependency locks, build environment, branch policy, and future release artifact.
- Actors: Maintainer, contributor, CI runner, action/dependency publisher, repository administrator, and supply-chain attacker.
- Trust boundaries: Repository changes and pinned automation enter CI; CI output does not yet prove protected release or artifact provenance.
- Entry points: Pull requests, local changes, CI scripts, Cargo manifests/lockfile, workflow configuration, and release triggers.
- Abuse cases: Malicious change merge, compromised action, unreviewed workflow edit, test bypass, dependency drift, secret exposure, or forged release result.
- Current mitigation: Locked Rust commands, static dependency/public-admission/verifier/R2-contract checks, test suite, documented repository controls, and review-only branches.
- Residual risk: Protected-branch settings, push protection, named CODEOWNERS enforcement, workload identity, signed artifacts, provenance, SBOM, and release approval evidence are external and unproven here.
- Evidence: ci/r2-checks.sh; scripts/check-public-admission.sh; scripts/check-dependency-policy.sh; docs/DEPENDENCY_POLICY.md; docs/PROMOTION_GATES.md.
- Owner: Repository maintainer and Fenrua security engineering; release approver remains owner-controlled.
- Review date: 2026-07-14; repeat before changing CI, granting release rights, or publishing an artifact.

### TM-R2-015 Backups

- Classification: Not applicable to R2; P1 gate before service data, managed storage, or repository backup assurances are claimed.
- Assets: Future policy data, evidence, configuration, keys, audit records, source mirrors, and recovery objectives.
- Actors: Future backup operator, storage provider, administrator, attacker, auditor, and incident responder.
- Trust boundaries: R2 has no managed database, evidence vault, hosted storage, or backup agent; caller filesystem remains outside the prototype boundary.
- Entry points: None in R2; future backup scheduler, storage account, restore interface, and export path are deferred.
- Abuse cases: Data loss, undeclared retention, backup disclosure, ransomware propagation, failed restore, stale restore, or backup privilege escalation.
- Current mitigation: No backup claim is made; local output documentation assigns storage, retention, permission, and recovery controls to the caller outside this repository.
- Residual risk: No backup inventory, encryption, retention, restore test, recovery point objective, recovery time objective, or incident process exists for future service data.
- Evidence: docs/TRUST_BOUNDARY.md; docs/PROMOTION_GATES.md; docs/R2_TEST_COVERAGE.md.
- Owner: Operations, security, and data owners must name backup ownership before managed data exists.
- Review date: 2026-07-14; repeat before storing service or customer data.

### TM-R2-016 Incident Response

- Classification: Not applicable to R2 operations; P1 gate before any release, hosted service, customer data, or support claim.
- Assets: Future incident reports, contact paths, logs, evidence, release keys, customer communications, and recovery actions.
- Actors: Future incident commander, security responder, operator, customer, regulator, attacker, and external reviewer.
- Trust boundaries: R2 has no deployed operation, monitoring plane, security-reporting endpoint, support channel, or customer service boundary.
- Entry points: None in R2; future vulnerability intake, alert, escalation, status, disclosure, and recovery channels are deferred.
- Abuse cases: Unreported vulnerability, delayed containment, false incident report, disclosure of sensitive evidence, missing escalation, or irreversible release response.
- Current mitigation: Promotion gates name owner-designated reporting and escalation contacts as external prerequisites; no operational readiness is claimed.
- Residual risk: No staffed response plan, reporting endpoint, severity process, communication plan, evidence vault, drill, or recovery/rollback proof exists for a future release.
- Evidence: docs/PROMOTION_GATES.md; docs/R1_SCOPE_AND_DEFERMENTS.md; FENRUA_LAUNCH_READINESS_LEDGER.md outside this repository.
- Owner: Founder-designated security and operations owners must be named before release or service activation.
- Review date: 2026-07-14; repeat before release, public preview, or operational service.

## Register Interpretation

A completed source record is not a completed production control. The current R2
implementation deliberately denies or omits unavailable controls instead of
simulating them. Before any implementation changes its input, storage, network,
cryptographic, execution, tenancy, or operational boundary, update this
register and obtain the matching promotion evidence.
