# Stage 1: Builder — cache dependencies separately from app code
FROM rust:1.88 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app dir and non-root user
ARG UID=10001
ARG GID=10001
RUN groupadd --gid ${GID} default_user && \
    useradd --uid ${UID} --gid ${GID} --shell /bin/bash --create-home default_user
RUN mkdir -p /app && chown -R default_user:default_user /app
WORKDIR /app
USER default_user

# --- Cache layer: copy ONLY Cargo.toml + Cargo.lock and fetch deps ---
# This layer is cached unless Cargo.toml changes, so subsequent builds
# only recompile the application crate (seconds), not 445 dependencies (minutes).
COPY --chown=default_user:default_user Cargo.toml Cargo.lock* ./
# Workspace members must be readable even in the dummy layer, otherwise
# `cargo build` fails with "failed to load manifest for dependency simple-smtp-domain".
COPY --chown=default_user:default_user crates/ ./crates/

# Create dummy src so cargo can resolve the crate
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/bin/smtp_server.rs && \
    echo 'fn main() {}' > src/bin/email_api.rs && \
    echo 'fn main() {}' > src/bin/imap_server.rs && \
    echo 'fn main() {}' > src/bin/client.rs && \
    echo 'pub fn lib() {}' > src/lib.rs

# Build dependencies only (this is the slow step, cached on subsequent builds)
RUN cargo build --release --bins 2>/dev/null || true

# --- App layer: copy actual source and build ---
# Remove dummy files
RUN rm -rf src

# Copy real source code and ops (required for include_str! macros referencing ops/openapi/)
COPY --chown=default_user:default_user src/ ./src/
COPY --chown=default_user:default_user ops/ ./ops/
COPY --chown=default_user:default_user i18n/ ./i18n/

# Touch source files to force rebuild of app crates (not deps)
RUN find src/ -name "*.rs" -exec touch {} \; 2>/dev/null; true

# Build the real binaries
ENV CARGO_BUILD_JOBS=4
RUN cargo build --release --bins

# Stage 2: Final image (unchanged from original)
FROM debian:bookworm-slim

ARG UID=10001
ARG GID=10001

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
    libssl3 \
    wget \
    gosu \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid ${GID} default_user && \
    useradd --uid ${UID} --gid ${GID} --shell /bin/bash --create-home default_user

COPY --from=builder /app/target/release/smtp_server /usr/local/bin/smtp_server
COPY --from=builder /app/target/release/email_api /usr/local/bin/email_api
COPY --from=builder /app/target/release/imap_server /usr/local/bin/imap_server

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /app/emails /app/dkim /app/certs && \
    chown -R default_user:default_user /app

# Self-signed certs (override with real certs in prod)
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /app/localhost.key -out /app/localhost.crt -days 365 \
    -subj "/CN=mail.misfits.ai" && \
    chown default_user:default_user /app/localhost.key /app/localhost.crt

USER default_user
WORKDIR /app

# TCP-based probe: avoids sending HTTP traffic to the SMTP port (which would
# cause "500 Syntax error, command unrecognized" log noise).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD nc -z 127.0.0.1 8025 || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["smtp_server"]

ENV USE_MONGODB=false \
    SMTP_PLAIN_ADDR=0.0.0.0:8025 \
    SMTP_TLS_ADDR=0.0.0.0:8465 \
    CERT_PATH=/app/localhost.crt \
    KEY_PATH=/app/localhost.key \
    SMTP_USERNAME=admin \
    SMTP_PASSWORD=changeme \
    RUST_LOG=info

EXPOSE 25 8025 8465 143 993 8000 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8025/ || exit 1

CMD ["smtp_server"]
