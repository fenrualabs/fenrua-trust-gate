# Bounded R2 Fuzzing

Status: a source-bounded cargo-fuzz target and curated synthetic seed corpus.
This is not a release-grade fuzzing, security-audit, or production-readiness
claim.

The bounded_json_r2 target feeds every input through strict JSON parsing and
all four direct R2 admissions: entity manifest, authority policy, tool-call
request, and revocation set. When parsing and canonicalisation both succeed,
it asserts that canonical bytes reparse and produce the same canonical bytes
and digest.

## Local Requirements

- Rust nightly on a supported Unix-like x86_64 or AArch64 environment;
- cargo-fuzz installed with cargo install cargo-fuzz;
- a C++11-capable compiler for the libFuzzer runtime.

## Local Commands

From the repository root:

    cargo +nightly fuzz check bounded_json_r2
    cargo +nightly fuzz run bounded_json_r2 -- -runs=10000 -seed=20260714 -max_len=4096 -timeout=5

The curated files under corpus/bounded_json_r2 are public-safe synthetic seeds.
The corpus ignore rule keeps any locally discovered corpus mutations out of the
review worktree until a separate minimisation and admission review approves
them.

## Recorded Local Run

On 2026-07-14, cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13, and Rust
1.99.0-nightly completed this bounded command against a fresh temporary corpus
containing only the six curated JSON seeds:

    cargo +nightly fuzz run bounded_json_r2 /tmp/fenrua-r2-fuzz-seeds-20260714-current -- -runs=10000 -seed=20260714 -max_len=4096 -timeout=5 -verbosity=0 -print_final_stats=1

It exited successfully after 10,000 iterations with no crash; libFuzzer
reported 327 new corpus units and a peak resident set size of 157 MiB. Those
are local run observations, not product coverage, performance, audit, or
assurance metrics.

## Non-Claims

The target does not establish full fuzz coverage, corpus minimisation,
cross-platform determinism, policy-semantic equivalence, authenticated signing,
durable replay, tenant isolation, release readiness, or an independent audit.
