#!/usr/bin/env bash
set -eu

THRESHOLD=${DOMAIN_COVERAGE_THRESHOLD:-90}

cargo install cargo-llvm-cov --quiet
echo "[audit] Coverage crates/domain (seuil ${THRESHOLD}%)..."

set +e
OUT=$(cargo llvm-cov -p simple-smtp-domain --summary-only 2>&1)
RC=$?
set -e
echo "$OUT" | tail -20

if [ "$RC" -ne 0 ]; then
  echo "[audit] ❌ cargo llvm-cov a échoué (exit=${RC})"
  exit 1
fi

PCT=$(echo "$OUT" | awk '
  /TOTAL/ {
    n=0
    for (i=1; i<=NF; i++) {
      if ($i ~ /^[0-9]+(\.[0-9]+)?%$/) {
        n++
        pct[n]=$i
      }
    }
    if (n >= 3) {
      v=pct[3]
    } else if (n >= 1) {
      v=pct[n]
    }
  }
  END {
    gsub("%", "", v)
    print v
  }
')

if [ -z "${PCT}" ] || ! printf '%s' "$PCT" | grep -Eq '^[0-9]+(\.[0-9]+)?$'; then
  echo "[audit] ❌ Impossible d'extraire la couverture Domain"
  exit 1
fi

PCT_INT=$(printf '%.0f' "$PCT")
if [ "$PCT_INT" -lt "$THRESHOLD" ]; then
  echo "[audit] ❌ Couverture Domain insuffisante: ${PCT}% < ${THRESHOLD}%"
  exit 1
fi

echo "[audit] ✅ Couverture Domain conforme: ${PCT}% >= ${THRESHOLD}%"
