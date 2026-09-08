#!/usr/bin/env bash
set -euo pipefail

count_traits() {
  grep -c "^pub trait\|^#\[async_trait" "$1" 2>/dev/null || echo 0
}

DOMAIN_TRAITS=$(grep -c "^pub trait\|^#\[async_trait" crates/domain/src/*.rs 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
LOGIC_TRAITS=$(count_traits src/logic/traits.rs)
BASE_REF=${GITHUB_BASE_REF:-master}
EVENT_NAME=${GITHUB_EVENT_NAME:-}

echo "[audit] Ports dans crates/domain : $DOMAIN_TRAITS"
echo "[audit] Ports encore dans src/logic/traits.rs : $LOGIC_TRAITS"

if [ "$EVENT_NAME" = "pull_request" ]; then
  git fetch --no-tags --depth=1 origin "$BASE_REF"

  if git cat-file -e "origin/$BASE_REF:src/logic/traits.rs" 2>/dev/null; then
    BASE_CONTENT=$(git show "origin/$BASE_REF:src/logic/traits.rs")
    BASE_LOGIC_TRAITS=$(printf '%s' "$BASE_CONTENT" | grep -c "^pub trait\|^#\[async_trait" || true)
  else
    BASE_LOGIC_TRAITS=0
  fi

  echo "[audit] Base($BASE_REF) ports dans src/logic/traits.rs : $BASE_LOGIC_TRAITS"
  echo "[audit] Objectif PR: ne pas augmenter les ports restants côté logic"

  if [ "$LOGIC_TRAITS" -gt "$BASE_LOGIC_TRAITS" ]; then
    echo "[audit] ❌ Régression: ports traits en logic augmentés (${BASE_LOGIC_TRAITS} -> ${LOGIC_TRAITS})"
    exit 1
  fi

  echo "[audit] ✅ Pas de régression sur la migration des ports"
  exit 0
fi

echo "[audit] Objectif master: logic_traits = 0, tous migrés vers domain"
if [ "$LOGIC_TRAITS" -gt 0 ]; then
  echo "[audit] ❌ Migration ports incomplète: traits encore présents dans src/logic/traits.rs"
  exit 1
fi

echo "[audit] ✅ Migration ports conforme"
