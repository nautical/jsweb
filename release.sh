#!/usr/bin/env bash

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

# Build the binaries first
./build.sh

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

# Create the release
echo "Creating release $VERSION..."
gh release create "$VERSION" \
    --repo nautical/jsweb \
    --title "Release $VERSION" \
    --notes-file "$TEMP_NOTES" \
    build/*

# Clean up
rm "$TEMP_NOTES"

echo "Release $VERSION has been created successfully!" 