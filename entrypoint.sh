#!/bin/sh
set -e

# When running as root (user: "0" in docker-compose.deploy.yml), Caddy cert
# files are 0600 root:root and unreadable by the unprivileged process.
# Copy them to /tmp with correct ownership, then drop to default_user via gosu.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /tmp/smtp-certs
    if [ -n "${CERT_PATH:-}" ]; then
        cp "$CERT_PATH" /tmp/smtp-certs/server.crt
        chown 10001:10001 /tmp/smtp-certs/server.crt
        chmod 400 /tmp/smtp-certs/server.crt
        export CERT_PATH=/tmp/smtp-certs/server.crt
    fi
    if [ -n "${KEY_PATH:-}" ]; then
        cp "$KEY_PATH" /tmp/smtp-certs/server.key
        chown 10001:10001 /tmp/smtp-certs/server.key
        chmod 400 /tmp/smtp-certs/server.key
        export KEY_PATH=/tmp/smtp-certs/server.key
    fi
    # email_api uses different variable names
    if [ -n "${FULLCHAIN_PATH:-}" ]; then
        cp "$FULLCHAIN_PATH" /tmp/smtp-certs/fullchain.crt
        chown 10001:10001 /tmp/smtp-certs/fullchain.crt
        chmod 400 /tmp/smtp-certs/fullchain.crt
        export FULLCHAIN_PATH=/tmp/smtp-certs/fullchain.crt
    fi
    if [ -n "${PRIVKEY_PATH:-}" ]; then
        cp "$PRIVKEY_PATH" /tmp/smtp-certs/privkey.key
        chown 10001:10001 /tmp/smtp-certs/privkey.key
        chmod 400 /tmp/smtp-certs/privkey.key
        export PRIVKEY_PATH=/tmp/smtp-certs/privkey.key
    fi
    exec gosu default_user "$@"
fi

exec "$@"
