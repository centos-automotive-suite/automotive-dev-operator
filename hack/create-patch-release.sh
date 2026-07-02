#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

show_help() {
    cat << EOF
Usage: $0 <version>

Create a patch release on an existing release branch.

Arguments:
  version    Patch version to release (e.g., 0.0.2, 1.0.1)

Examples:
  $0 0.0.2   # Creates v0.0.2 tag on release-0.0.x branch
  $0 1.0.1   # Creates v1.0.1 tag on release-1.0.x branch

What this script does:
1. Validates the version format
2. Switches to the appropriate release-X.Y.x branch
3. Updates the Makefile VERSION
4. Creates a commit for the patch release
5. Creates and pushes a git tag
6. Provides next steps

Note: The release branch (release-X.Y.x) must already exist.
Use create-release-branch.sh to create new release branches.

EOF
}

# Check arguments
if [[ $# -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
    exit 0
fi

VERSION=$1

# Validate version format (semantic versioning)
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_error "Invalid version format: $VERSION"
    log_info "Version must be in format X.Y.Z (e.g., 0.0.2, 1.0.1)"
    exit 1
fi

# Parse version components
IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"
RELEASE_BRANCH="release-${MAJOR}.${MINOR}.x"

# Validate this is a patch release (patch > 0)
if [[ $PATCH -eq 0 ]]; then
    log_error "Use create-release-branch.sh for initial releases (X.Y.0)"
    log_info "This script is for patch releases (X.Y.1, X.Y.2, etc.)"
    exit 1
fi

log_info "Creating patch release for version $VERSION"
echo "Release branch: $RELEASE_BRANCH"
echo ""

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    log_error "Not in a git repository"
    exit 1
fi

# Fetch latest changes to ensure we have current remote refs
log_info "Fetching latest changes..."
git fetch origin

# Check if release branch exists (locally or remotely)
if git rev-parse --verify "$RELEASE_BRANCH" > /dev/null 2>&1; then
    # Local branch exists
    log_info "Found local release branch: $RELEASE_BRANCH"
elif git rev-parse --verify "origin/$RELEASE_BRANCH" > /dev/null 2>&1; then
    # Remote branch exists, create local tracking branch
    log_info "Found remote release branch, creating local tracking branch: $RELEASE_BRANCH"
    git checkout -b "$RELEASE_BRANCH" "origin/$RELEASE_BRANCH"
else
    # Neither local nor remote branch exists
    log_error "Release branch $RELEASE_BRANCH does not exist locally or remotely"
    log_info "Use create-release-branch.sh to create the release branch first"
    exit 1
fi

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    log_error "Uncommitted changes found. Please commit or stash them first."
    git status --short
    exit 1
fi

# Check if tag already exists
if git rev-parse --verify "v$VERSION" > /dev/null 2>&1; then
    log_error "Tag v$VERSION already exists"
    exit 1
fi

# Ensure we're on the release branch and up to date
if [[ $(git branch --show-current) != "$RELEASE_BRANCH" ]]; then
    log_info "Switching to release branch: $RELEASE_BRANCH"
    git checkout "$RELEASE_BRANCH"
fi

if [[ $(git rev-list HEAD...origin/$RELEASE_BRANCH --count) -gt 0 ]]; then
    log_warn "Release branch is behind origin. Pulling latest changes..."
    git pull origin "$RELEASE_BRANCH"
fi

# Update VERSION file
log_info "Updating VERSION file to $VERSION"
echo "$VERSION" > VERSION

# Verify the change
if [[ "$(cat VERSION)" != "$VERSION" ]]; then
    log_error "Failed to update VERSION file"
    exit 1
fi

# Show what changed since last tag
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [[ -n "$LAST_TAG" ]]; then
    log_info "Changes since $LAST_TAG:"
    git log --oneline "$LAST_TAG"..HEAD
    echo ""
fi

# Commit the version update
log_info "Committing version update..."
git add VERSION
git commit -m "Release $VERSION

- Update VERSION file to $VERSION
- Patch release $VERSION"

# Create and push the tag
log_info "Creating and pushing tag v$VERSION..."
git tag -a "v$VERSION" -m "Release $VERSION"
git push origin "v$VERSION"

# Push the updated branch
log_info "Pushing updated release branch..."
git push origin "$RELEASE_BRANCH"

log_success "Patch release v$VERSION created successfully!"
echo ""

log_info "Next steps:"
echo "1. The GitHub Actions will now build and release v$VERSION"
echo "2. Monitor the release workflow: https://github.com/$(git config remote.origin.url | sed 's/.*github.com[:/]\([^.]*\).*/\1/')/actions"
echo "3. For the next patch release (${MAJOR}.${MINOR}.$((PATCH + 1))):"
echo "   - Cherry-pick more fixes to $RELEASE_BRANCH"
echo "   - Run: ./hack/create-patch-release.sh ${MAJOR}.${MINOR}.$((PATCH + 1))"
echo ""
echo "Current branch: $RELEASE_BRANCH"
echo "Release tag: v$VERSION"
echo ""

# Show recent commits
git log --oneline -5