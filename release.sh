#!/usr/bin/env bash
set -e

# Check if version is provided
if [[ -z "$1" ]]; then
  echo "usage: $0 <version>"
  echo "example: $0 v1.0.0"
  exit 1
fi

VERSION=$1

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "GitHub CLI (gh) is not installed. Please install it first."
    echo "Visit: https://cli.github.com/ for installation instructions"
    exit 1
fi

# Check if user is authenticated with GitHub
if ! gh auth status &> /dev/null; then
    echo "Please authenticate with GitHub first using: gh auth login"
    exit 1
fi

# Get commit information
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Create dist directory
mkdir -p dist

# Build for different platforms with version information
build() {
    local GOOS=$1
    local GOARCH=$2
    local output_name="jsweb"
    
    if [ "$GOOS" = "windows" ]; then
        output_name="${output_name}.exe"
    fi
    
    echo "Building for $GOOS/$GOARCH..."
    
    # Build with version information embedded via ldflags
    GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "-X main.Version=$VERSION -X main.BuildDate=$BUILD_DATE -X main.GitCommit=$COMMIT" \
        -o "dist/${GOOS}_${GOARCH}/${output_name}" \
        ./...
    
    # Create zip archive for the platform
    pushd dist/${GOOS}_${GOARCH} > /dev/null
    zip -q ../../dist/jsweb-${VERSION}-${GOOS}-${GOARCH}.zip ${output_name}
    popd > /dev/null
    
    echo "✓ Built and packaged dist/jsweb-${VERSION}-${GOOS}-${GOARCH}.zip"
}

# Build for all platforms
echo "Building release $VERSION (commit: $COMMIT, date: $BUILD_DATE)..."
build "darwin" "amd64"
build "darwin" "arm64"
build "linux" "amd64"
build "linux" "arm64"
build "windows" "amd64"

# Create temporary file for release notes
TEMP_NOTES=$(mktemp)
echo "# Release Notes for $VERSION" > "$TEMP_NOTES"
echo "" >> "$TEMP_NOTES"
echo "## What's New in This Release" >> "$TEMP_NOTES"
echo "" >> "$TEMP_NOTES"
echo "### Features" >> "$TEMP_NOTES"
echo "- " >> "$TEMP_NOTES"
echo "" >> "$TEMP_NOTES"
echo "### Bug Fixes" >> "$TEMP_NOTES"
echo "- " >> "$TEMP_NOTES"
echo "" >> "$TEMP_NOTES"
echo "### Improvements" >> "$TEMP_NOTES"
echo "- " >> "$TEMP_NOTES"

# Open editor for release notes
${EDITOR:-vi} "$TEMP_NOTES"

# Create git tag
echo "Creating git tag $VERSION..."
git tag -a "$VERSION" -m "Release $VERSION"
git push origin "$VERSION"

# Create the release
echo "Creating GitHub release $VERSION..."
gh release create "$VERSION" \
    --repo nautical/jsweb \
    --title "Release $VERSION" \
    --notes-file "$TEMP_NOTES" \
    dist/jsweb-${VERSION}-*.zip

# Clean up
rm "$TEMP_NOTES"
echo "Release $VERSION has been created successfully!" 