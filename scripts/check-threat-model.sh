#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
model="${repository_root}/docs/THREAT_MODEL_R2.md"

if [[ ! -f "$model" ]]; then
  printf '%s\n' 'Threat-model failure: docs/THREAT_MODEL_R2.md is missing' >&2
  exit 1
fi

records=(
  TM-R2-001
  TM-R2-002
  TM-R2-003
  TM-R2-004
  TM-R2-005
  TM-R2-006
  TM-R2-007
  TM-R2-008
  TM-R2-009
  TM-R2-010
  TM-R2-011
  TM-R2-012
  TM-R2-013
  TM-R2-014
  TM-R2-015
  TM-R2-016
)

fields=(
  Classification
  Assets
  Actors
  "Trust boundaries"
  "Entry points"
  "Abuse cases"
  "Current mitigation"
  "Residual risk"
  Evidence
  Owner
  "Review date"
)

for record in "${records[@]}"; do
  if ! grep -Fq -- "### ${record} " "$model"; then
    printf 'Threat-model failure: missing record %s\n' "$record" >&2
    exit 1
  fi
done

for field in "${fields[@]}"; do
  count="$(grep -Fc -- "- ${field}:" "$model" || true)"
  if [[ "$count" -ne "${#records[@]}" ]]; then
    printf 'Threat-model failure: expected %s "%s" fields, found %s\n' \
      "${#records[@]}" "$field" "$count" >&2
    exit 1
  fi
done

printf 'Threat-model register: %s records with required fields verified\n' \
  "${#records[@]}"
