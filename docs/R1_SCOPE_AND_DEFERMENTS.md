# R1 Scope and Deferred Work

Status: R1 specification foundation; no product availability claim
Last reviewed: 2026-07-14

## Delivered Foundation Boundary

R1 delivers local, deterministic primitives that later work can review without
an implicit service dependency:

- strict bounded JSON syntax parsing, including duplicate-key rejection;
- deterministic canonical bytes and domain-separated SHA-256 digests;
- safe problem categories and a non-leaky adapter envelope;
- explicit reserved-unreleased schema/profile discovery;
- a replay-checkpoint trait and deterministic test fixtures;
- source admission, dependency, and security-reporting boundaries.

## Deferred by Design

The following needs frozen normative schemas, vectors, profile review, and
later promotion evidence. None is represented as implemented here:

| Capability | Deferred reason | Minimum later gate |
| --- | --- | --- |
| Strict schema validation | The bootstrap reserves names but does not release JSON Schema definitions. | Approved specs repository and immutable negative vectors. |
| Policy evaluation and decisions | A constrained policy contract and denial semantics need their own review. | Policy evaluator train with deny-overrides corpus. |
| Signatures and keys | Profile labels are not implementation approval or cryptographic review. | Published profile, vectors, key custody, independent crypto review. |
| Evidence and receipts | Output fields and independent verification contract are not released. | Evidence/receipt schema, vectors, independent verifier. |
| Replay operation | The trait is local and test-only; no durable atomic store exists. | Reviewed replay design and bounded state implementation. |
| CLI file commands | Exact schema contracts and atomic output semantics are not yet implementable truthfully. | Stable schema and evidence trains. |
| SDK/API/control plane | The local path has no network implementation. | Stable contract, tenant/auth controls, operations evidence. |
| Release/public availability | Source existence is not release evidence. | R3-to-R4 gate in `PROMOTION_GATES.md`. |

## Explicit Non-Claims

This source foundation does not claim production readiness, independent
verification, cryptographic assurance, key custody, tenant isolation,
availability, reliability, a security certification, or a completed Trust Gate
workflow.
