#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"

failed=0
private_key_suffix="PRIVATE "
private_key_suffix+="KEY-----"
private_key_pattern="-----BEGIN [A-Z0-9 ]*${private_key_suffix}"
openssh_prefix="-----BEGIN OPENSSH "
secret_pattern="${private_key_pattern}|${openssh_prefix}${private_key_suffix}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}"
while IFS= read -r -d '' file; do
  lowercase_path="$(printf '%s' "$file" | tr '[:upper:]' '[:lower:]')"
  case "$lowercase_path" in
    *.pem|*.key|*.p12|*.pfx|*.jks|*.keystore|*.env|*.sarif|*.har|*.pcap|*.pcapng|*.log)
      printf 'admission failure: prohibited artifact path: %s\n' "$file" >&2
      failed=1
      continue
      ;;
    */screenshots/*|*/screen-recordings/*|*/working-review/*|*/raw-audit/*|*/scan-dumps/*)
      printf 'admission failure: prohibited evidence path: %s\n' "$file" >&2
      failed=1
      continue
      ;;
  esac

  if [[ ! -f "$file" ]] || ! grep -Iq . "$file"; then
    continue
  fi
  if grep -n -E -- "$secret_pattern" "$file"; then
    printf 'admission failure: possible secret marker in: %s\n' "$file" >&2
    failed=1
  fi
done < <(git ls-files -co --exclude-standard -z)

if (( failed != 0 )); then
  printf '%s\n' 'public admission check failed; move sensitive material to the approved private process' >&2
  exit 1
fi

printf '%s\n' 'public admission check passed for tracked and untracked repository files'
