# ADR-0001: Rust Local Core for the R2 Prototype

Status: accepted for R2 prototype only
Date: 2026-07-14

## Context

The local decision path needs bounded parsing, deterministic behavior, an
explicit dependency graph, and a cross-platform CLI direction. The programme
recommended comparing Rust, Go, Node/TypeScript, and a C++ extension to the
research kernel before choosing a local core.

## Decision

R2 uses a Rust workspace with a small standard-library-first dependency graph
and an exact `sha2` pin. The evaluator, CLI, canonicalisation, parser, and
separate verifier are compiled as distinct crates. The verifier must not depend
on the evaluator crate.

## Considered Alternatives

| Option | Decision | Reason in this phase |
| --- | --- | --- |
| Rust core and CLI | Selected for R2. | Memory-safe language, explicit ownership, deterministic local binary path, and established lint/fuzz ecosystem. |
| Go core | Deferred. | Viable, but would create a second toolchain and does not improve the present bounded prototype. |
| Node/TypeScript core | Deferred to SDK work. | Useful for integration, but a runtime package is not the preferred core boundary for this local prototype. |
| C++ extension to `fenrua-kernel` | Rejected for R2. | It would blur the research-kernel and decision-control boundaries. |

## Consequences

This ADR does not promise a distributed binary, supported platform list, FFI,
SDK, release artifact, or language permanence. Any promotion needs benchmark,
reproducibility, supply-chain, compatibility, and owner-approved release
evidence.
