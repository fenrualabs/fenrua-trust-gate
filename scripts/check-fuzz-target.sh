#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$repository_root"

manifest="fuzz/Cargo.toml"
lockfile="fuzz/Cargo.lock"
approved="ci/approved-fuzz-lock-packages.txt"
target="fuzz/fuzz_targets/bounded_json_r2.rs"
corpus="fuzz/corpus/bounded_json_r2"
corpus_ignore="fuzz/corpus/.gitignore"

for required in "$manifest" "$lockfile" "$approved" "$target" "$corpus_ignore"; do
  if [[ ! -f "$required" ]]; then
    printf 'Fuzz-target failure: missing required file: %s\n' "$required" >&2
    exit 1
  fi
done

if ! grep -Fq 'cargo-fuzz = true' "$manifest"; then
  printf '%s\n' 'Fuzz-target failure: cargo-fuzz metadata is missing' >&2
  exit 1
fi

if ! grep -Fq 'libfuzzer-sys = "=0.4.13"' "$manifest"; then
  printf '%s\n' 'Fuzz-target failure: libfuzzer-sys must remain exact-pinned' >&2
  exit 1
fi

if grep -n 'source = "git+' "$lockfile"; then
  printf '%s\n' 'Fuzz-target failure: fuzz lockfile contains a Git source' >&2
  exit 1
fi

temporary_actual="$(mktemp)"
trap 'rm -f "$temporary_actual"' EXIT
awk '
  /^\[\[package\]\]$/ { package_name = ""; next }
  /^name = / { gsub(/"/, "", $3); package_name = $3; next }
  /^version = / && package_name != "" { gsub(/"/, "", $3); print package_name "@" $3 }
' "$lockfile" | sort > "$temporary_actual"

if ! diff -u "$approved" "$temporary_actual"; then
  printf '%s\n' 'Fuzz-target failure: update the inventory and approved fuzz package set through review' >&2
  exit 1
fi

for seed in manifest.json policy-allow.json request-offline.json revocations-current.json duplicate-key.json unpaired-surrogate.json; do
  if [[ ! -f "$corpus/$seed" ]] || ! grep -Fqx "!bounded_json_r2/$seed" "$corpus_ignore"; then
    printf 'Fuzz-target failure: missing tracked curated seed: %s\n' "$seed" >&2
    exit 1
  fi
done

if ! cmp -s "$corpus/manifest.json" fixtures/r2/manifest.json; then
  printf '%s\n' 'Fuzz-target failure: manifest seed diverges from the synthetic fixture' >&2
  exit 1
fi
if ! cmp -s "$corpus/policy-allow.json" fixtures/r2/policy-allow.json; then
  printf '%s\n' 'Fuzz-target failure: policy seed diverges from the synthetic fixture' >&2
  exit 1
fi
if ! cmp -s "$corpus/request-offline.json" fixtures/r2/request-offline.json; then
  printf '%s\n' 'Fuzz-target failure: request seed diverges from the synthetic fixture' >&2
  exit 1
fi
if ! cmp -s "$corpus/revocations-current.json" fixtures/r2/revocations-current.json; then
  printf '%s\n' 'Fuzz-target failure: revocation seed diverges from the synthetic fixture' >&2
  exit 1
fi

for marker in parse_json canonical_document parse_r2_document EntityManifest AuthorityPolicy ToolCallRequest RevocationSet; do
  if ! grep -Fq "$marker" "$target"; then
    printf 'Fuzz-target failure: target omits required boundary marker: %s\n' "$marker" >&2
    exit 1
  fi
done

printf '%s\n' 'Fuzz target: exact isolated lockfile, curated seeds, and R2 boundary markers verified'
