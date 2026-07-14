# R1 Trust Boundary

Status: local source-boundary record, not a deployed architecture

## Trusted Inputs at R1

The strict parser accepts only bytes supplied by its direct caller. It does not
open files, resolve paths, dereference URLs, fetch schemas, evaluate scripts,
read environment variables, obtain wall-clock time, use random identifiers, or
call a network service.

## Untrusted Input Handling

Before any future schema interpretation, R1 rejects input that exceeds its
configured byte, nesting, collection, decoded-string, or number-token bounds.
It rejects malformed UTF-8, malformed JSON, raw control characters, invalid
surrogate usage, duplicate object keys, and trailing data. A generic JSON
deserializer is never allowed to overwrite a duplicate key silently.

## Output Boundary

R1 emits canonical bytes/digests only through library calls and static CLI
discovery information. It emits a safe problem envelope with a stable category
and optional byte offset. It does not emit authorisation, execution direction,
evidence, receipts, keys, user data, host details, paths, stack traces, or raw
input in an error response.

## Future Boundary Conditions

Future schema acceptance, local file adapters, replay storage, signing,
evaluation, evidence generation, verification, and output atomicity must be
introduced only with their own contract, tests, threat-model updates, and
promotion evidence. No later adapter may weaken the R1 parser limits or use a
fallible parser mode that accepts duplicate keys.
