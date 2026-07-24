# Stage 1: Builder
FROM rust:1.88 AS builder

ARG USER=default_user
ARG UID=10001
ARG GID=10001

# Create a non-root user and group
RUN groupadd --gid ${GID} ${USER} && \
    useradd --uid ${UID} --gid ${GID} --shell /bin/bash --create-home ${USER}

# Create app directory
RUN mkdir -p /app && chown -R ${USER}:${USER} /app

WORKDIR /app
USER ${USER}

# Copy the application source
COPY --chown=${USER}:${USER} . .

# Set build parallelism to low to avoid OOM kills
ENV CARGO_BUILD_JOBS=2

# Build all binaries using stable Rust
RUN cargo build --release --bins

# Stage 2: Final image
FROM debian:bullseye-slim

ARG USER=default_user
ARG UID=10001
ARG GID=10001

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd --gid ${GID} ${USER} && \
    useradd --uid ${UID} --gid ${GID} --shell /bin/bash --create-home ${USER}

# Copy compiled binaries from the builder stage
COPY --from=builder /app/target/release/smtp_server /usr/local/bin/smtp_server
COPY --from=builder /app/target/release/email_api /usr/local/bin/email_api
COPY --from=builder /app/target/release/imap_server /usr/local/bin/imap_server

# Create DKIM directory and copy keys (if they exist)
RUN mkdir -p /app/dkim/

# Application directory and persistent data volume
RUN mkdir -p /app/emails && chown -R ${USER}:${USER} /app/emails
VOLUME /app/emails 
# The original VOLUME was /data. The README mentions emails are stored in "./emails"
# Let's use /app/emails for clarity, assuming this is the intended data volume.

# Self-signed certs for staging TLS listeners (override with real certs in prod)
USER root
RUN openssl req -x509 -newkey rsa:2048 -nodes       -keyout /app/localhost.key -out /app/localhost.crt -days 365       -subj "/CN=mail.misfits.ai"     && chown ${USER}:${USER} /app/localhost.key /app/localhost.crt     && mkdir -p /app/emails /app/dkim     && chown -R ${USER}:${USER} /app/emails /app/dkim
USER ${USER}
WORKDIR /app

ENV USE_MONGODB=false \
    SMTP_PLAIN_ADDR=0.0.0.0:8025 \
    SMTP_TLS_ADDR=0.0.0.0:8465 \
    CERT_PATH=/app/localhost.crt \
    KEY_PATH=/app/localhost.key \
    SMTP_USERNAME=admin \
    SMTP_PASSWORD=changeme \
    RUST_LOG=info

USER ${USER}
WORKDIR /app

# Expose ports
# SMTP
EXPOSE 25
EXPOSE 8025 
EXPOSE 8465 
# IMAP
EXPOSE 143
EXPOSE 993
# API (defaulting to 8000 as a common practice, email_api.rs uses 8443 for https)
EXPOSE 8000
EXPOSE 8443


# Set default command
# You can run a specific server by overriding the command, e.g., docker run <image_name> email_api
CMD ["smtp_server"]
# Alternatively, to guide the user:
# CMD ["sh", "-c", "echo 'Please specify a binary to run: smtp_server, email_api, or imap_server. Defaulting to smtp_server.' && exec smtp_server"]
