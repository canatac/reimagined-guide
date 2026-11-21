#!/usr/bin/env bash
# The routes of the Caddyfile of the VM (misfits-web#1192): this repository
# deploys the one Caddyfile; the routes the web and the API expect are checked
# here, by path and upstream port. The auth-sensitive routes of the web go to
# Next.js (its Edge middleware checks the session: misfits-web#722, #723).
set -euo pipefail
file=${1:-Caddyfile}
routes=$(awk '/^[[:space:]]*handle \//{p=$2} /reverse_proxy http:\/\/localhost:/{if(p){split($2,a,":"); print p, a[3]; p=""}}' "$file")
expect() {
  local path=$1 port=$2 got
  got=$(awk -v p="$path" '$1==p{print $2}' <<<"$routes")
  if [ "$got" != "$port" ]; then
    echo "FAIL: $path goes to ${got:-nothing}, expected localhost:$port"
    status=1
  else
    echo "ok: $path -> localhost:$port"
  fi
}
status=0
# Next.js (3001)
expect /api/auth/callback 3001
expect '/api/admin*' 3001
expect '/api/hermes*' 3001
expect '/api/emails*' 3001
expect '/api/external-accounts*' 3001
expect '/api/compose*' 3001
expect '/api/templates*' 3001
# API (8000)
expect '/api/compose/send*' 8000
expect /api/health 8000
expect /api/health/live 8000
expect /api/health/deep 8000
expect '/api/*' 8000
exit $status
