#!/bin/bash
# prepare-release.sh - Prepare a new release for community-operators-prod
#
# Usage: ./hack/prepare-release.sh <version>
# Example: ./hack/prepare-release.sh 0.1.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Validate version format (semantic versioning)
validate_version() {
    local version=$1
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Invalid version format: $version. Must be semantic versioning (e.g., 0.1.0)"
    fi
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    command -v operator-sdk &> /dev/null || log_error "operator-sdk not found. Install from https://sdk.operatorframework.io/"
    command -v make &> /dev/null || log_error "make not found"
    command -v git &> /dev/null || log_error "git not found"

    # Check for uncommitted changes
    if [[ -n $(git -C "$ROOT_DIR" status --porcelain) ]]; then
        log_warn "You have uncommitted changes. Consider committing before release."
    fi

    log_success "Prerequisites check passed"
}

update_version() {
    local version=$1
    log_info "Updating VERSION file to $version..."

    echo "$version" > "$ROOT_DIR/VERSION"

    log_success "Version updated in VERSION file"
}

generate_bundle() {
    local version=$1
    local image_tag="${IMAGE_TAG:-quay.io/rh-sdv-cloud/automotive-dev-operator:v${version}}"

    log_info "Generating bundle for version $version..."
    log_info "Using image: $image_tag"

    cd "$ROOT_DIR"

    make bundle VERSION="$version" IMG="$image_tag"

    log_success "Bundle generated"
}

validate_bundle() {
    log_info "Validating bundle for OperatorHub..."

    cd "$ROOT_DIR"

    # Standard validation
    operator-sdk bundle validate ./bundle

    # OperatorHub-specific validation
    operator-sdk bundle validate ./bundle --select-optional name=operatorhubv2
    operator-sdk bundle validate ./bundle --select-optional name=capabilities
    operator-sdk bundle validate ./bundle --select-optional name=categories
    log_success "Bundle validation passed"
}

prepare_community_operators() {
    local version=$1

    log_info "Preparing community-operators-prod structure..."

    cd "$ROOT_DIR"
    make community-operators-bundle VERSION="$version"

    log_success "Community operators structure prepared"
    echo ""
    log_info "Next steps:"
    echo "  1. Fork https://github.com/redhat-openshift-ecosystem/community-operators-prod"
    echo "  2. Copy community-operators-prod/ to your fork"
    echo "  3. Create a PR with title: operator automotive-dev-operator ($version)"
}

update_catalog() {
    local version=$1
    log_info "Updating catalog configuration for version $version..."

    cd "$ROOT_DIR"
    make catalog-update VERSION="$version"

    log_success "Catalog updated"
}

bump_dev_version() {
    local version=$1
    local major minor _
    IFS='.' read -r major minor _ <<< "$version"
    local next_minor=$((minor + 1))
    local dev_version="${major}.${next_minor}.0-dev"

    log_info "Bumping version to $dev_version for next development cycle..."

    echo "$dev_version" > "$ROOT_DIR/VERSION"

    log_success "Version bumped to $dev_version in VERSION file"
    echo ""
    log_info "Commit this change on main after tagging the release:"
    echo "  git add VERSION"
    echo "  git commit -m 'chore: bump version to $dev_version for next development cycle'"
}

# Generate release notes with changelog from git log
generate_release_notes() {
    local version=$1
    local notes_file="$ROOT_DIR/RELEASE_NOTES_v${version}.md"

    log_info "Generating release notes..."

    cd "$ROOT_DIR"
    local prev_tag
    prev_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    local changelog=""
    if [[ -n "$prev_tag" ]]; then
        changelog=$(git log --pretty=format:"- %s" "$prev_tag"..HEAD --no-merges)
    else
        changelog=$(git log --pretty=format:"- %s" --no-merges)
    fi

    cat > "$notes_file" << EOF
# Automotive Dev Operator v${version}

## Highlights

<!-- Add main highlights here -->

## Changes

${changelog}

## Breaking Changes

<!-- List any breaking changes, or "None" -->

## Installation

### Via OLM (OperatorHub)

The operator is available on OpenShift OperatorHub. Search for "CentOS Automotive Suite".

### Direct Installation

\`\`\`bash
kubectl apply -f https://github.com/centos-automotive-suite/automotive-dev-operator/releases/download/v${version}/install-v${version}.yaml
\`\`\`

### CLI Tool

Download the \`caib\` CLI for your platform:

- [Linux AMD64](https://github.com/centos-automotive-suite/automotive-dev-operator/releases/download/v${version}/caib-v${version}-amd64)
- [Linux ARM64](https://github.com/centos-automotive-suite/automotive-dev-operator/releases/download/v${version}/caib-v${version}-arm64)
- [macOS ARM64](https://github.com/centos-automotive-suite/automotive-dev-operator/releases/download/v${version}/caib-v${version}-darwin)

## Container Images

- Operator: \`quay.io/rh-sdv-cloud/automotive-dev-operator:v${version}\`
- Bundle: \`quay.io/rh-sdv-cloud/automotive-dev-operator-bundle:v${version}\`

EOF

    log_success "Release notes template created: $notes_file"
}

main() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <version>"
        echo "       $0 post-release <version>"
        echo ""
        echo "Example: $0 0.1.0              # Prepare release"
        echo "         $0 post-release 0.1.0  # Bump to next dev version"
        exit 1
    fi

    if [[ "$1" == "post-release" ]]; then
        if [[ $# -lt 2 ]]; then
            log_error "Usage: $0 post-release <released-version>"
        fi
        validate_version "$2"
        bump_dev_version "$2"
        return
    fi

    local version=$1

    echo ""
    echo "=========================================="
    echo " Automotive Dev Operator Release Prep"
    echo " Version: $version"
    echo "=========================================="
    echo ""

    validate_version "$version"
    check_prerequisites
    update_version "$version"
    generate_bundle "$version"
    validate_bundle
    update_catalog "$version"
    prepare_community_operators "$version"
    generate_release_notes "$version"

    echo ""
    echo "=========================================="
    log_success "Release preparation complete!"
    echo "=========================================="
    echo ""
    echo "To complete the release:"
    echo "  1. Review and commit changes"
    echo "  2. Tag the release: git tag v$version"
    echo "  3. Push: git push origin main --tags"
    echo "  4. GitHub Actions will build and publish images"
    echo "  5. Submit PR to community-operators-prod"
    echo "  6. Post-release version bump PR will be created automatically by CI"
    echo ""
}

main "$@"
