#!/usr/bin/env bash
# Cycle 18 hexagonal — audit imports externes dans crates/domain/src/
# Objectif : détecter toute dépendance d'infrastructure fuitant dans le domaine.
# Ne bloque pas (exit 0) — usage informatif jusqu'à purge complète.
set -u
DOMAIN_DIR="crates/domain/src"
if [ ! -d "$DOMAIN_DIR" ]; then
  echo "[audit] $DOMAIN_DIR introuvable — skip"
  exit 0
fi

PATTERN='use (actix|mongodb|reqwest|tokio|rustls|lettre|bcrypt|hyper|warp|sqlx|redis)'
echo "[audit] Scan imports EXT dans $DOMAIN_DIR ..."
MATCHES=$(grep -rEn "$PATTERN" "$DOMAIN_DIR" 2>/dev/null || true)
COUNT=$(printf '%s\n' "$MATCHES" | grep -c . || true)

if [ "$COUNT" -gt 0 ]; then
  echo "[audit] ⚠️  $COUNT import(s) EXT détecté(s) :"
  printf '%s\n' "$MATCHES"
else
  echo "[audit] ✅ Domaine pur (0 import EXT)"
fi

echo "[audit] Compteur final : $COUNT"
exit 0
