#!/usr/bin/env bash
set -eu

if ! command -v lizard >/dev/null 2>&1; then
  if command -v pip >/dev/null 2>&1; then
    pip install --quiet lizard 2>/dev/null || true
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m pip install --quiet lizard 2>/dev/null || true
  fi
fi

if ! command -v lizard >/dev/null 2>&1; then
  echo "[audit] ERROR: lizard non disponible (pip/python3 -m pip introuvable)"
  exit 2
fi

echo "[audit] Scan CCN Rust crates/domain/src/ (seuil 8)..."
# lizard -T seuil sur cyclomatic_complexity (nom correct depuis lizard 1.17+)
set +e
RESULT=$(lizard -l rust -T cyclomatic_complexity=8 crates/domain/src/ --warnings_only 2>&1)
RC=$?
set -e
VIOL=$(echo "$RESULT" | grep -cE "warning:" || true)
echo "$RESULT" | tail -20
echo "[audit] Fonctions CCN > 8 : $VIOL"

if [ "$RC" -ne 0 ] || [ "$VIOL" -gt 0 ]; then
  echo "[audit] ❌ CCN > 8 détecté"
  exit 1
fi

echo "[audit] ✅ CCN conforme (<=8)"
