# Stage 1: Builder
FROM rust:1.70 AS builder

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

# Set Rust to nightly and build all binaries
# rustup override set nightly is used because the original Dockerfile had it.
# If specific nightly features are not strictly needed, consider removing this for stability.
RUN rustup override set nightly && \
    cargo build --release --bins

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

# Application directory and persistent data volume
RUN mkdir -p /app/emails && chown -R ${USER}:${USER} /app/emails
VOLUME /app/emails 
# The original VOLUME was /data. The README mentions emails are stored in "./emails"
# Let's use /app/emails for clarity, assuming this is the intended data volume.

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
