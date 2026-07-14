# R2 Decision Semantics

Status: local-only prototype semantics; not a released decision contract

| Term | R2 local meaning | It does not mean |
| --- | --- | --- |
| Admission | Strict bounded JSON parsing plus closed-profile structural checks. | General JSON Schema validation or interoperability approval. |
| Local payload check | Recompute the local-unsigned digest excluding `signature`. | Signer authentication, key ownership, or trusted origin. |
| Evaluation | Deterministic evaluation of the accepted subset with an explicit timestamp. | A hosted policy service or an instruction to act. |
| Authorisation record | Local `ALLOW` or fail-closed `DENY` record. | Permission to execute an external action. |
| Execution | A caller's separate external action. | Implemented or directed by this repository. |
| Evidence | Deterministic local decision/evidence/receipt records. | An append-only evidence service or public assurance artifact. |
| Verification | Separate recomputation of emitted payload digests and record links. | Policy re-evaluation, independent assurance, or cryptographic signer verification. |
| Attestation | A future authenticated producer claim under a promoted profile. | The R2 local-unsigned marker. |

R2 first rejects malformed or unsupported documents. For structurally admitted
inputs, it records `DENY_SIGNATURE_INVALID` when an input local payload digest
does not match. It denies on declared owner/issuer disagreement, scope mismatch,
inactive or expired inputs, identity/capability mismatch, stale revocations,
mandatory replay protection, revocations, no policy match, and unavailable
required evidence or approval. An assessed explicit deny overrides allow; a
base-matching deny with an unavailable requirement fails closed before an allow
can win. After the other selectors match, an audience substitution yields
`DENY_AUDIENCE_MISMATCH` and a context identifier or ordered binding substitution
yields `DENY_CONTEXT_MISMATCH`. A parse ambiguity is never converted into allow.

The evaluation instant is supplied by the caller as a UTC millisecond timestamp;
R2 does not read a wall clock. Identical valid inputs and the same instant
produce identical output. That determinism is bounded to the R2 implementation
and its pinned dependency/toolchain context, not a cross-platform certification.

R2 applies no implicit clock-skew allowance: a direct input issued exactly at
the supplied instant is eligible, while an input issued one millisecond later
fails closed. Timestamps must use the exact UTC `Z` form with milliseconds;
numeric offsets and leap seconds are rejected. This is a parser and local
evaluation rule, not a clock-synchronisation or daylight-saving assurance.

An emitted record normally expires at the earliest direct-input expiration. If
the evaluation occurs at or after any direct-input expiration, R2 still emits a
strict fail-closed record but gives the decision, evidence, and receipt a single
UTC-millisecond output interval. This preserves a structurally valid linked
record without extending stale authority or making a `DENY` reusable as an
authorisation result.

Rule time windows use the half-open UTC interval `[notBefore, notAfter)`: a
matching request is in scope at `notBefore` and out of scope at `notAfter`.
When an ALLOW and an explicit DENY rule both match the same request, the DENY
record wins.
