# Build stage
FROM rust:bookworm AS builder

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

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create atlas user with sudo privileges for port binding
RUN useradd -m -s /bin/bash atlas \
    && echo "atlas ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Create necessary directories
RUN mkdir -p /opt/atlas/certs /opt/atlas/zones \
    && chown -R atlas:atlas /opt/atlas

# Copy binary from builder
COPY --from=builder /usr/src/atlas/target/release/atlas /usr/local/bin/atlas

# Create entrypoint script while still root
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Build command arguments\n\
ARGS=""\n\
\n\
# Add zones directory\n\
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

# Switch to atlas user
USER atlas

# Set working directory
WORKDIR /opt/atlas

# Expose DNS ports (TCP and UDP) and web interface ports
EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 5380
EXPOSE 5343

# Default environment variables for CapRover
ENV RUST_LOG=info
ENV ZONES_DIR=/opt/atlas/zones
ENV FORWARD_ADDRESS=""
ENV SSL_ENABLED="false"
ENV ACME_PROVIDER=""
ENV ACME_EMAIL=""
ENV ACME_DOMAINS=""

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]