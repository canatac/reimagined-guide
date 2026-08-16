#!/usr/bin/env bash
set -eu
DOMAIN_TRAITS=$(grep -c "^pub trait\|^#\[async_trait" crates/domain/src/*.rs 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
LOGIC_TRAITS=$(grep -c "^pub trait\|^#\[async_trait" src/logic/traits.rs 2>/dev/null || echo 0)
echo "[audit] Ports dans crates/domain : $DOMAIN_TRAITS"
echo "[audit] Ports encore dans src/logic/traits.rs : $LOGIC_TRAITS"
echo "[audit] Objectif : logic_traits = 0, tous migrés vers domain"
