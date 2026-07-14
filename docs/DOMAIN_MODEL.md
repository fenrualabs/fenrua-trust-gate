# R2 Domain Model

Status: bounded prototype subset; not a complete control-plane model

R2 carries only the local entities required to evaluate its fixtures. Their
stable identifiers, scope, lifecycle/revision/time fields, and evidence links
are structurally required where the pinned local profile supports them.

| Domain entity | R2 role | Boundary |
| --- | --- | --- |
| Tenant and Environment | Scope fields within a direct document. | No tenant registry or isolation proof. |
| Entity / Agent | Subject identified by an active manifest. | No remote identity resolution. |
| Operator | Request actor identifier. | No authenticated human or workload identity. |
| Artifact | Optional request reference and declared digest. | No artifact-byte retrieval or verification. |
| Policy / Policy Revision | One active constrained policy document. | No distribution, supersession service, or general policy language. |
| Request | Explicit local action request. | No API, queue, or executor integration. |
| Revocation | Fresh local revocation set, direct target entries, and sequence. | No monotonic distribution or durable storage. |
| Decision | Deterministic `ALLOW`/`DENY` record. | Not an execution permission. |
| Evidence Bundle / Receipt | Local emitted record and human-readable summary. | Not an append-only or public evidence service. |
| Verification | Separate local integrity/link report. | Not independent assurance or signer validation. |
| Key / Trust Profile | Reserved profile names plus local marker. | No key lifecycle or key operation. |

Approval, key version/rotation, incident, release, observation, build, and
deployment entities remain deferred until their own contracts and boundaries are
implemented.
