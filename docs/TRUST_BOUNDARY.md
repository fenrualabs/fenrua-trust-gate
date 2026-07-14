# R2 Local Trust Boundary

Status: local source boundary; not a deployed architecture

The CLI opens only caller-supplied explicit file paths. It passes their bytes
through bounded parsing before any R2 structural admission. The implementation
rejects malformed UTF-8/JSON, duplicate keys, trailing data, invalid surrogate
use, and configured byte, depth, collection, string, number, and canonical-byte
bounds. Error output contains a stable category and optional byte offset, never
the path, raw content, host details, stack trace, or nested dependency message.

The local evaluator reads no environment, network, URL, remote schema, database,
telemetry source, wall clock, random source, or dynamic code. The caller supplies
all four documents and the evaluation timestamp. R2 has no durable replay state;
a request that requires replay protection is denied.

The output adapter uses `create_new`, writes one canonical envelope, and calls
`sync_all`. It refuses to overwrite an existing target. This is not a claim of
atomic publication across directories, multiple files, or a filesystem crash
protocol. A caller must treat the emitted envelope as local prototype data and
apply any required storage, permission, retention, and execution controls outside
this repository.

The evaluator has no execution adapter. Its `ALLOW` output does not cross the
trust boundary into an external action. The local verifier has no dependency on
the evaluator crate and checks emitted content integrity/links only; it does not
independently authenticate inputs or re-run policy semantics. It does compare
the duplicated decision, receipt, evidence, scope, policy, request-digest, and
expiry links so an internally contradictory local envelope does not pass.
