#!/usr/bin/env bash
# Architecture guard — Boucle 15
# Empêche Logic (src/logic/*.rs sauf mongo_adapter.rs) d'accéder directement
# au client MongoDB. Tout accès DB doit passer par le port DatabaseInterface
# (self.repo.X), impl réelle dans mongo_adapter.rs.
set -euo pipefail

VIOLATIONS=$(grep -rn "self\.client\." src/logic/ | grep -v "src/logic/mongo_adapter.rs" || true)

if [[ -n "$VIOLATIONS" ]]; then
    echo "❌ Architecture guard: accès direct MongoDB détectés hors de mongo_adapter.rs:"
    echo "$VIOLATIONS"
    echo
    echo "Règle: Logic doit passer via self.repo.X (port DatabaseInterface)."
    echo "Seul mongo_adapter.rs peut manipuler self.client directement."
    exit 1
fi

# Vérifier aussi qu'aucun cfg(not(test)) n'ait été réintroduit dans les
# fichiers *_impl.rs (les blocs métier doivent tous passer par le port).
CFG_VIOLATIONS=$(grep -rn "#\[cfg(not(test))\]" src/logic/email_impl.rs src/logic/mailbox_impl.rs src/logic/calendar_impl.rs 2>/dev/null || true)

if [[ -n "$CFG_VIOLATIONS" ]]; then
    echo "❌ Architecture guard: bloc #[cfg(not(test))] réintroduit dans *_impl.rs:"
    echo "$CFG_VIOLATIONS"
    echo
    echo "Règle: les fichiers *_impl.rs doivent être 100% via port (pas de split cfg)."
    exit 1
fi

echo "✅ Architecture guard: Logic 100% via port DatabaseInterface."
