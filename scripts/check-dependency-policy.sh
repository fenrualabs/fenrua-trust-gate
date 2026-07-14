#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"

if [[ ! -f Cargo.lock ]]; then
  printf '%s\n' 'dependency policy failure: Cargo.lock is required' >&2
  exit 1
fi

if grep -R -n -E '(^|[[:space:]])git[[:space:]]*=' --include='Cargo.toml' --exclude-dir=target .; then
  printf '%s\n' 'dependency policy failure: Git dependencies are prohibited' >&2
  exit 1
fi

if grep -n 'source = "git+' Cargo.lock; then
  printf '%s\n' 'dependency policy failure: lockfile contains a Git source' >&2
  exit 1
fi

if ! grep -Fq 'sha2 = "=0.10.9"' Cargo.toml; then
  printf '%s\n' 'dependency policy failure: the direct sha2 pin is not exact' >&2
  exit 1
fi

temporary_actual="$(mktemp)"
trap 'rm -f "$temporary_actual"' EXIT
awk '
  /^\[\[package\]\]$/ { package_name = ""; next }
  /^name = / { gsub(/"/, "", $3); package_name = $3; next }
  /^version = / && package_name != "" { gsub(/"/, "", $3); print package_name "@" $3 }
' Cargo.lock | sort > "$temporary_actual"

if ! diff -u ci/approved-lock-packages.txt "$temporary_actual"; then
  printf '%s\n' 'dependency policy failure: update the inventory and approved package set through review' >&2
  exit 1
fi

cargo metadata --locked --format-version 1 --no-deps >/dev/null
printf '%s\n' 'dependency policy: exact approved lockfile package set verified'
