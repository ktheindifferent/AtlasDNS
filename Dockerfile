# =============================================================================
# Stage 1: Build
# =============================================================================
FROM rust:bookworm AS builder

ARG CODE_VERSION=20260327_000000
ENV CODE_VERSION=${CODE_VERSION}

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/atlas

# Cache dependency builds: copy manifests first, create dummy src
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/bin/atlas.rs && \
    echo 'fn main() {}' > src/bin/atlas-cli.rs && \
    echo 'fn main() {}' > src/bin/atlas-admin.rs && \
    echo 'fn main() {}' > src/bin/atlasdns-check.rs && \
    echo 'fn main() {}' > src/bin/atlasdns-backup.rs && \
    echo 'fn main() {}' > src/bin/atlasdns-feeder.rs && \
    echo '' > src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy real source and build
COPY src ./src
RUN cargo build --release --bin atlas --bin atlasdns-feeder

# =============================================================================
# Stage 2: Runtime (Alpine for minimal image size)
# =============================================================================
FROM alpine:3.19 AS runtime

RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    libstdc++ \
    curl \
    tini

# Create unprivileged user
RUN addgroup -S atlasdns && adduser -S -G atlasdns -u 1001 atlasdns

# Create directories
RUN mkdir -p /opt/atlas/certs /opt/atlas/zones /opt/atlas/data \
    && chown -R atlasdns:atlasdns /opt/atlas

# Copy binaries from builder
COPY --from=builder /usr/src/atlas/target/release/atlas /usr/local/bin/atlas
COPY --from=builder /usr/src/atlas/target/release/atlasdns-feeder /usr/local/bin/atlasdns-feeder

# Entrypoint script
COPY <<'ENTRYPOINT' /usr/local/bin/docker-entrypoint.sh
#!/bin/sh
set -e

RUST_LOG=${RUST_LOG:-info}
export RUST_LOG

ARGS=""

ZONES_DIR=${ZONES_DIR:-/opt/atlas/zones}
ARGS="$ARGS --zones-dir $ZONES_DIR"

[ -n "$FORWARD_ADDRESS" ] && ARGS="$ARGS --forward-address $FORWARD_ADDRESS"

if [ "$SSL_ENABLED" = "true" ]; then
    ARGS="$ARGS --ssl"
    [ -n "$ACME_PROVIDER" ]  && ARGS="$ARGS --acme-provider $ACME_PROVIDER"
    [ -n "$ACME_EMAIL" ]     && ARGS="$ARGS --acme-email $ACME_EMAIL"
    [ -n "$ACME_DOMAINS" ]   && ARGS="$ARGS --acme-domains $ACME_DOMAINS"
fi

[ -n "$EXTRA_ARGS" ] && ARGS="$ARGS $EXTRA_ARGS"

echo "Starting Atlas DNS Server"
exec /usr/local/bin/atlas $ARGS
ENTRYPOINT
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /opt/atlas

# DNS (UDP+TCP), HTTP API, DoH
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 5353/tcp
EXPOSE 8080/tcp

# Health check every 30s, allow 5s startup grace
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["/usr/local/bin/docker-entrypoint.sh"]
