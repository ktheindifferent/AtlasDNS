#!/bin/bash
# Automatic version updater for Atlas DNS
# Updates Dockerfile with current timestamp version

set -e

# Generate version timestamp in format YYYYMMDD_HHMMSS
VERSION=$(date +"%Y%m%d_%H%M%S")

echo "🕐 Updating Atlas DNS to version: $VERSION"

# Update Dockerfile build stage
sed -i.bak "s/^ARG CODE_VERSION=.*/ARG CODE_VERSION=${VERSION}/" Dockerfile

# Verify the update
if grep -q "ARG CODE_VERSION=${VERSION}" Dockerfile; then
    echo "✅ Dockerfile updated successfully"
    echo "   Build stage: ARG CODE_VERSION=${VERSION}"
    echo "   Runtime stage: ARG CODE_VERSION=${VERSION}"
else
    echo "❌ Failed to update Dockerfile"
    exit 1
fi

# Update the second occurrence (runtime stage)
sed -i.bak "s/^ARG CODE_VERSION=.*/ARG CODE_VERSION=${VERSION}/2" Dockerfile

echo "🚀 Version ${VERSION} ready for deployment"
echo "   The /api/version endpoint will return: {\"code_version\":\"${VERSION}\",\"package_version\":\"0.0.1\"}"