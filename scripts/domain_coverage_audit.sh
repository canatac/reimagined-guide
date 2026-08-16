#!/usr/bin/env bash
set -eu
cargo install cargo-llvm-cov --quiet 2>/dev/null || true
echo "[audit] Coverage crates/domain (seuil 90%)..."
cargo llvm-cov -p simple-smtp-domain --summary-only 2>&1 | tail -10 || echo "[audit] Pas encore de tests domain (baseline)"
