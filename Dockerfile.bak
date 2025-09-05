# Build stage
FROM rust:bookworm AS builder

# Code version argument - automatically updated by atlas_bug_fix command
ARG CODE_VERSION=20250905_071700
ENV CODE_VERSION=${CODE_VERSION}
RUN echo "Code version: ${CODE_VERSION}"

# Cache bust: 2025-01-03-v3
ARG CACHE_BUST=3

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/atlas

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Code version for runtime
ARG CODE_VERSION=20250905_071700
ENV CODE_VERSION=${CODE_VERSION}

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create user for running the server
RUN useradd -m -u 1001 atlas

# Create necessary directories
RUN mkdir -p /opt/atlas/certs /opt/atlas/zones \
    && chown -R atlas:atlas /opt/atlas

# Copy binary from builder
COPY --from=builder /usr/src/atlas/target/release/atlas /usr/local/bin/atlas

# Create entrypoint script while still root
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Set default RUST_LOG if not provided\n\
RUST_LOG=${RUST_LOG:-debug}\n\
export RUST_LOG\n\
\n\
# Build command arguments\n\
ARGS=""\n\
\n\
# Add zones directory (default if not set)\n\
ZONES_DIR=${ZONES_DIR:-/opt/atlas/zones}\n\
ARGS="$ARGS --zones-dir $ZONES_DIR"\n\
\n\
# Add forward address if provided\n\
if [ ! -z "$FORWARD_ADDRESS" ]; then\n\
    ARGS="$ARGS --forward-address $FORWARD_ADDRESS"\n\
fi\n\
\n\
# Add SSL configuration if enabled\n\
if [ "$SSL_ENABLED" = "true" ]; then\n\
    ARGS="$ARGS --ssl"\n\
    \n\
    # Add ACME configuration if provided\n\
    if [ ! -z "$ACME_PROVIDER" ]; then\n\
        ARGS="$ARGS --acme-provider $ACME_PROVIDER"\n\
    fi\n\
    \n\
    if [ ! -z "$ACME_EMAIL" ]; then\n\
        ARGS="$ARGS --acme-email $ACME_EMAIL"\n\
    fi\n\
    \n\
    if [ ! -z "$ACME_DOMAINS" ]; then\n\
        ARGS="$ARGS --acme-domains $ACME_DOMAINS"\n\
    fi\n\
fi\n\
\n\
# Execute atlas with arguments\n\
echo "Starting Atlas DNS Server with arguments: $ARGS"\n\
exec /usr/local/bin/atlas $ARGS' > /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

# Set working directory
WORKDIR /opt/atlas

# Note: Running as root is required for binding to port 53
# In a container environment, this is acceptable as the container provides isolation

# Expose DNS ports (TCP and UDP) and web interface ports
EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 5380
EXPOSE 5343

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]