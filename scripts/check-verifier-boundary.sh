#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"

dependency_tree="$(cargo tree -p fenrua-verify --edges normal --locked)"
if grep -Fq 'fenrua-gate ' <<<"$dependency_tree"; then
  printf '%s\n' 'verifier boundary failure: fenrua-verify must not depend on fenrua-gate' >&2
  exit 1
fi

printf '%s\n' 'verifier boundary: fenrua-verify has no fenrua-gate dependency'
