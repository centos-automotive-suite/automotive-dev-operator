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

Create a new release branch for the given version.

Arguments:
  version    Version for the release branch (e.g., 0.0.1, 1.0.0)

Examples:
  $0 0.0.1   # Creates release-0.0.x branch for 0.0.1 release
  $0 1.0.0   # Creates release-1.0.x branch for 1.0.0 release

What this script does:
1. Validates the version format
2. Creates release-X.Y.x branch from main
3. Updates the VERSION file
4. Creates an initial commit
5. Pushes the branch to origin
6. Creates a git tag for the version
7. Provides next steps

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
    log_info "Version must be in format X.Y.Z (e.g., 0.0.1, 1.0.0)"
    exit 1
fi

# Parse version components
IFS='.' read -r MAJOR MINOR _PATCH <<< "$VERSION"
RELEASE_BRANCH="release-${MAJOR}.${MINOR}.x"

log_info "Creating release branch for version $VERSION"
echo "Release branch: $RELEASE_BRANCH"
echo ""

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    log_error "Not in a git repository"
    exit 1
fi

# Check if main branch exists and we can access it
if ! git rev-parse --verify main > /dev/null 2>&1; then
    log_error "Main branch not found"
    exit 1
fi

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    log_error "Uncommitted changes found. Please commit or stash them first."
    git status --short
    exit 1
fi

# Fetch latest changes and tags from origin to ensure up-to-date refs
log_info "Fetching latest changes and tags..."
git fetch --prune --tags origin

# Check if release branch already exists (locally or remotely)
if git rev-parse --verify "refs/heads/$RELEASE_BRANCH" > /dev/null 2>&1; then
    log_error "Release branch $RELEASE_BRANCH already exists locally"
    exit 1
fi

if git rev-parse --verify "refs/remotes/origin/$RELEASE_BRANCH" > /dev/null 2>&1; then
    log_error "Release branch $RELEASE_BRANCH already exists on origin"
    exit 1
fi

# Check if tag already exists (locally or remotely)
if git rev-parse --verify "refs/tags/v$VERSION" > /dev/null 2>&1; then
    log_error "Tag v$VERSION already exists locally"
    exit 1
fi

if git ls-remote --tags origin "v$VERSION" | grep -q "refs/tags/v$VERSION"; then
    log_error "Tag v$VERSION already exists on origin"
    exit 1
fi

# Switch to main and ensure it's up to date
log_info "Switching to main branch..."
git checkout main

log_info "Fetching latest changes..."
git fetch origin

if [[ $(git rev-list HEAD...origin/main --count) -gt 0 ]]; then
    log_warn "Main branch is behind origin/main. Pulling latest changes..."
    git pull origin main
fi

# Create and switch to release branch
log_info "Creating release branch: $RELEASE_BRANCH"
git checkout -b "$RELEASE_BRANCH"

# Update VERSION file
log_info "Updating VERSION file to $VERSION"
echo "$VERSION" > VERSION

# Verify the change
if [[ "$(cat VERSION)" != "$VERSION" ]]; then
    log_error "Failed to update VERSION file"
    exit 1
fi

# Commit the version update
log_info "Committing version update..."
git add VERSION
git commit -m "Release $VERSION

- Update VERSION file to $VERSION
- Prepare for $VERSION release"

# Create and push the branch
log_info "Pushing release branch to origin..."
git push -u origin "$RELEASE_BRANCH"

# Create and push the tag
log_info "Creating and pushing tag v$VERSION..."
git tag -a "v$VERSION" -m "Release $VERSION"
git push origin "v$VERSION"

log_success "Release branch $RELEASE_BRANCH created successfully!"
echo ""

log_info "Next steps:"
echo "1. The GitHub Actions will now build and release v$VERSION"
echo "2. Monitor the release workflow: https://github.com/$(git config remote.origin.url | sed 's/.*github.com[:/]\([^.]*\).*/\1/')/actions"
echo "3. For patch releases (${MAJOR}.${MINOR}.X+1):"
echo "   - Cherry-pick fixes to $RELEASE_BRANCH"
echo "   - Update VERSION file"
echo "   - Tag the new patch version"
echo ""
echo "Current branch: $RELEASE_BRANCH"
echo "Release tag: v$VERSION"
echo ""

# Show branch info
git log --oneline -5