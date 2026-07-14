#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"

specs_commit="268788e18bb39d69ffed706294d2605878f04c34"
schema_pin="fenrua-specs/v0.1@${specs_commit}"

if ! grep -Fq "R2_LOCAL_SPECS_COMMIT: &str = \"${specs_commit}\"" crates/fenrua-protocol/src/r2.rs; then
  printf '%s\n' 'R2 contract failure: protocol source does not pin the approved specs revision' >&2
  exit 1
fi

if ! grep -Fq "R2_LOCAL_SCHEMA_PIN: &str = \"${schema_pin}\"" crates/fenrua-protocol/src/r2.rs; then
  printf '%s\n' 'R2 contract failure: protocol source does not expose the approved schema pin' >&2
  exit 1
fi

if ! grep -Fq "$schema_pin" docs/R2_LOCAL_PROTOTYPE.md; then
  printf '%s\n' 'R2 contract failure: public-safe local-profile record is stale' >&2
  exit 1
fi

if grep -R -n -E '0\.1\.0-r1\.0' --include='Cargo.toml' --include='*.md' --include='*.txt' .; then
  printf '%s\n' 'R2 contract failure: stale R1 package version remains in active source records' >&2
  exit 1
fi

printf '%s\n' 'R2 contract: specs pin and active prototype records verified'
