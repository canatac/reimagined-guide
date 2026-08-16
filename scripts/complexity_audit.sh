#!/usr/bin/env bash
set -eu
pip install --quiet lizard 2>/dev/null || true
echo "[audit] Scan CCN Rust src/ + crates/domain/src/ (seuil 8)..."
RESULT=$(lizard -l rust -T CCN=8 src/ crates/domain/src/ 2>&1 || true)
VIOL=$(echo "$RESULT" | grep -E "^\s*[0-9]+\s+\S+\s+[0-9]+" | awk '$3 > 8' | wc -l || echo 0)
echo "$RESULT" | tail -20
echo "[audit] Fonctions CCN > 8 : $VIOL"
