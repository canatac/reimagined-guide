#!/usr/bin/env bash
set -eu
pip install --quiet lizard 2>/dev/null || true
echo "[audit] Scan CCN Rust src/ + crates/domain/src/ (seuil 8)..."
# lizard -T seuil sur cyclomatic_complexity (nom correct depuis lizard 1.17+)
RESULT=$(lizard -l rust -T cyclomatic_complexity=8 src/ crates/domain/src/ --warnings_only 2>&1 || true)
VIOL=$(echo "$RESULT" | grep -cE "^\s*[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+" || echo 0)
echo "$RESULT" | tail -20
echo "[audit] Fonctions CCN > 8 : $VIOL"
