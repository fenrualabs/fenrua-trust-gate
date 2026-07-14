# Public Repository Admission Policy

Status: active R2 source-admission control

## Purpose

This is a public source repository. It may hold source, deterministic synthetic
fixtures, public-safe threat summaries, approved advisories, dependency records,
checksums, SBOM/provenance references after release approval, and templates.
It must not become a private evidence store or a working-security-review area.

## Prohibited Material

Reject the following from source control, issues, pull requests, releases, and
generated artifacts:

- credentials, tokens, private keys, certificates, key stores, environment
  files, production connection strings, or local linkage metadata;
- customer, tenant, employee, partner, or production data;
- raw audit reports, pen-test reports, scan dumps, SARIF findings, packet
  captures, debug logs, screenshots, screen recordings, or working review
  artifacts;
- private operational topology, private incident records, private evidence, or
  unredacted security reports;
- generated binaries or downloads without a separately approved release record.

Do not solve a prohibited-material finding by renaming the file, compressing it,
or moving it to an unreviewed path. Preserve the private evidence through an
approved private process, then retain only an approved public-safe summary when
appropriate.

## Admission Procedure

1. Classify the candidate artifact as public source, synthetic fixture,
   approved public evidence, or prohibited/private material.
2. Confirm it contains no secrets, customer data, raw evidence, screenshots, or
   working review content.
3. Run `./scripts/check-public-admission.sh` locally and in CI.
4. Record any exception using `docs/templates/EXCEPTION_RECORD.md`; an exception
   record must never contain the excluded private material itself.
5. Obtain the owner/reviewer approval required by protected-branch governance
   once a verified CODEOWNERS team exists.

## Automated Guard Scope

The guard rejects high-risk filenames, evidence directory names, binary review
artifacts, and common private-key/token markers in text files. It is a
preventive check, not proof that a file is safe. Reviewers still classify data
and preserve the public/private boundary.

## Safe Public Records

The repository may contain only approved, non-sensitive forms of these records:

- source and deterministic synthetic test vectors;
- locked dependency graph and dependency inventory;
- public-safe threat summary and remediation-status summary;
- signed release manifest, SBOM, provenance, and digest after the applicable
  release gate;
- public advisory after coordinated disclosure approval;
- claim, finding, and exception record templates with no live cases or private
  evidence.
