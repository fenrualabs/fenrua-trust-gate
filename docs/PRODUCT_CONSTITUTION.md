# Product Constitution

Status: R2 source-boundary constitution; not a public product promise

## Purpose

Fenrua Trust Gate is being developed as local-first decision-control
infrastructure for evaluating whether an action record should be allowed before
an external executor acts. R2 implements only a bounded local prototype of that
direction.

## Intended Users and Use

The intended future users are builders integrating a local decision step around
an AI agent, workload, tool, or artifact. R2 is suitable only for synthetic,
local development and test fixtures. It is not suitable for customer data,
production authorisation, safety certification, cryptographic identity, or
regulated/compliance decisions.

## Local and Hosted Boundary

The decision path is designed to remain local and explicit. A future control
plane may distribute signed policy/revocations and manage scope, but it must not
silently change a local decision. R2 has no hosted component, telemetry,
customer-data path, control plane, or evidence intake.

## Evidence and Privacy Boundary

R2 produces local synthetic evidence only. It does not export, retain, publish,
or classify production data. Public source holds only public-safe source and
synthetic fixtures; private evidence belongs in an approved private process.

## Change, Emergency, and Promotion

Any new accepted schema field, profile, policy semantic, replay behavior, or
execution adapter requires a documented contract change, negative tests, threat
update, compatibility assessment, and promotion evidence. An emergency change
must fail closed when uncertainty remains. R2 cannot be self-promoted beyond
its recorded maturity.
