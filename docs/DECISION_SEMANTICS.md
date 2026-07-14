# R1 Decision Semantics Boundary

Status: terminology boundary; no decision implementation exists

## Terms

| Term | R1 meaning |
| --- | --- |
| Validation | Checking a future document against a released schema. Not implemented. |
| Verification | Checking a claim or artifact against defined evidence. Only a generic canonical-digest comparison primitive exists. |
| Evaluation | Applying a released constrained policy to validated inputs. Not implemented. |
| Authorisation | A future evaluator's `ALLOW` or `DENY` decision. Not implemented. |
| Execution | An external action taken by a caller. Never directed by R1. |
| Evidence | A future structured record. Not implemented. |
| Attestation | A claim by a defined producer under a released profile. Not implemented. |

A successful parse or matching generic digest is not a policy validation,
verification result, authorisation decision, approval, or instruction to
execute any action. R1 contains no `ALLOW`/`DENY` producer precisely to avoid
confusing these roles.
