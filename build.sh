#!/bin/bash
set -e

# This is a simple build script for development
# For releases with proper version information, use release.sh

# Create dist directory
mkdir -p dist/dev

# Build for current platform
echo "Building development version..."
go build \
	-o "dist/dev/jsweb" \
	./...

echo "✓ Built dist/dev/jsweb"
echo "For production builds with versioning, use ./release.sh <version>"
