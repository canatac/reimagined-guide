#!/usr/bin/env bash
set -e
THRESHOLD=${LOC_THRESHOLD:-300}
OVER=$(find src -name '*.rs' -not -path '*/tests/*' -not -name 'main_tests.rs' -not -name 'tests.rs' | xargs wc -l 2>/dev/null | awk -v T=$THRESHOLD '$1 > T && $2 != "total"')
if [ -n "$OVER" ]; then
  echo "❌ Fichiers > $THRESHOLD LOC :"
  echo "$OVER"
  exit 1
fi
echo "✅ Aucun fichier > $THRESHOLD LOC"
