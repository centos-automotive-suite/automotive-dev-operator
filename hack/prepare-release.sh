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
    log_info "Updating VERSION to $version in Makefile..."

    sed -i.bak "s/^VERSION ?= .*/VERSION ?= $version/" "$ROOT_DIR/Makefile"
    rm -f "$ROOT_DIR/Makefile.bak"

    log_success "Version updated in Makefile"
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
    local output_dir="${COMMUNITY_OPERATORS_DIR:-$ROOT_DIR/community-operators-prod}"
    local operator_dir="$output_dir/operators/automotive-dev-operator"
    local version_dir="$operator_dir/$version"

    log_info "Preparing community-operators-prod structure..."
    log_info "Output directory: $output_dir"

    # Create directory structure
    mkdir -p "$version_dir/manifests"
    mkdir -p "$version_dir/metadata"

    # Copy manifests (CSVs and CRDs)
    cp -r "$ROOT_DIR/bundle/manifests/"* "$version_dir/manifests/"

    # Copy metadata
    cp -r "$ROOT_DIR/bundle/metadata/"* "$version_dir/metadata/"

    # Create ci.yaml if it doesn't exist
    if [[ ! -f "$operator_dir/ci.yaml" ]]; then
        cat > "$operator_dir/ci.yaml" << 'EOF'
# Update graph mode for OLM
# Options: semver-mode (default), semver-skippatch-mode, replaces-mode
updateGraph: semver-mode
EOF
        log_info "Created ci.yaml with semver-mode"
    fi

    log_success "Community operators structure prepared at: $version_dir"
    echo ""
    log_info "Next steps:"
    echo "  1. Fork https://github.com/redhat-openshift-ecosystem/community-operators-prod"
    echo "  2. Copy $version_dir to your fork under operators/automotive-dev-operator/"
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

    sed -i.bak "s/^VERSION ?= .*/VERSION ?= $dev_version/" "$ROOT_DIR/Makefile"
    rm -f "$ROOT_DIR/Makefile.bak"

    log_success "Version bumped to $dev_version in Makefile"
    echo ""
    log_info "Commit this change on main after tagging the release:"
    echo "  git add Makefile"
    echo "  git commit -m 'chore: bump version to $dev_version for next development cycle'"
}

# Generate release notes template
generate_release_notes() {
    local version=$1
    local notes_file="$ROOT_DIR/RELEASE_NOTES_v${version}.md"

    log_info "Generating release notes template..."

    cat > "$notes_file" << EOF
# Automotive Dev Operator v${version}

## Highlights

<!-- Add main highlights here -->

## Changes

<!-- List changes here, e.g.:
- Added support for bootc container builds
- Improved build performance
- Fixed issue with artifact cleanup
-->

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
    echo "  6. Bump to next dev version: $0 post-release $version"
    echo ""
}

main "$@"
