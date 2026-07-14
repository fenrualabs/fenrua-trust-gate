#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./scripts/check-public-admission.sh
./scripts/check-dependency-policy.sh
./scripts/check-verifier-boundary.sh
./scripts/check-r2-contract.sh
./scripts/check-fuzz-target.sh
./scripts/check-vulnerability-management.sh
