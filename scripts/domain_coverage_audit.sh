#!/usr/bin/env bash
set -eu

THRESHOLD=${DOMAIN_COVERAGE_THRESHOLD:-90}

cargo install cargo-llvm-cov --quiet
echo "[audit] Coverage crates/domain (seuil ${THRESHOLD}%)..."

OUT=$(cargo llvm-cov -p simple-smtp-domain --summary-only 2>&1)
echo "$OUT" | tail -20

PCT=$(echo "$OUT" | awk '/TOTAL/ {gsub("%","",$NF); v=$NF} END {print v}')

if [ -z "${PCT}" ]; then
  echo "[audit] ❌ Impossible d'extraire la couverture Domain"
  exit 1
fi

PCT_INT=$(printf '%.0f' "$PCT")
if [ "$PCT_INT" -lt "$THRESHOLD" ]; then
  echo "[audit] ❌ Couverture Domain insuffisante: ${PCT}% < ${THRESHOLD}%"
  exit 1
fi

echo "[audit] ✅ Couverture Domain conforme: ${PCT}% >= ${THRESHOLD}%"
