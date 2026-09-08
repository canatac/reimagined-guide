#!/usr/bin/env bash
set -euo pipefail

THRESHOLD=${LOC_THRESHOLD:-300}
BASE_REF=${GITHUB_BASE_REF:-master}
EVENT_NAME=${GITHUB_EVENT_NAME:-}

if [ "$EVENT_NAME" = "pull_request" ]; then
  git fetch --no-tags --depth=1 origin "$BASE_REF"
  CANDIDATES=$(git diff --name-only "origin/$BASE_REF...HEAD" -- '*.rs' \
    | grep '^src/' \
    | grep -Ev '/tests/|(^|/)main_tests\.rs$|(^|/)tests\.rs$' \
    || true)
else
  CANDIDATES=$(find src -name '*.rs' -not -path '*/tests/*' -not -name 'main_tests.rs' -not -name 'tests.rs' || true)
fi

if [ -z "$CANDIDATES" ]; then
  echo "✅ Aucun fichier candidat pour le contrôle LOC"
  exit 0
fi

OVER=""
while IFS= read -r file; do
  [ -z "$file" ] && continue
  lines=$(wc -l < "$file")
  if [ "$lines" -gt "$THRESHOLD" ]; then
    OVER+="$(printf '%6s %s\n' "$lines" "$file")"
  fi
done <<< "$CANDIDATES"

if [ -n "$OVER" ]; then
  echo "❌ Fichiers > $THRESHOLD LOC :"
  printf "%s" "$OVER"
  exit 1
fi

echo "✅ Aucun fichier > $THRESHOLD LOC"
