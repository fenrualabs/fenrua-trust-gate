# Security Reporting and Handling

Status: R1 source-foundation policy; external intake channel not yet configured

## Current Reporting Boundary

Do not publish vulnerabilities, exploit details, secrets, customer data, raw
logs, scan output, screenshots, or private evidence in a public issue, pull
request, discussion, commit, or repository file.

The repository does not yet record a verified private reporting endpoint or
response SLA. Until the owner configures one, a reporter who cannot safely use
the repository's private vulnerability-reporting capability must request a
verified contact path from Fenrua through an established business channel. This
policy does not claim that a private reporting channel currently exists.

## Scope at R1

The present source scope is limited to bounded parsing, canonicalisation,
digest primitives, profile discovery, and test-only support. No network,
hosted control plane, customer data path, production key operation, released
schema, or evaluator exists here.

## Safe Initial Report Content

Share only the minimum safe metadata needed to open a private report:

- affected source revision;
- package and function name where known;
- impact summary without sensitive payloads;
- reproducible synthetic steps;
- suggested severity;
- whether private evidence exists and requires an approved channel.

## Internal Handling Record

Once a verified private route exists, each finding must use the public-safe
template at `docs/templates/SECURITY_FINDING_RECORD.md` as a record shape. Raw
evidence stays outside this repository. No finding is closed by deleting a
report, weakening a test, or changing a fixture to hide the behavior.

## R1 Decisions Still Required

- owner-designated private reporting endpoint and escalation contacts;
- named triage owner and response targets;
- severity taxonomy and disclosure decision process;
- coordinated disclosure and public-advisory process;
- provider/account boundaries for a future release workflow.
