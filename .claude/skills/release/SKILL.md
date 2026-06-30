---
name: release
description: Run the full release workflow for a new version. Handles prepare, release branch, and community-operators PR.
allowed-tools:
  - Bash
  - Read
  - Edit
  - Write
  - AskUserQuestion
---

# Release Workflow

Orchestrates the full release of a new version. Runs all phases sequentially with confirmation gates.

Post-release version bump is automated by CI (`post-release.yml`). This skill handles: prepare, create release branch, and submit community-operators PR.

## Parameters

`$ARGUMENTS` contains the version to release (required, format: X.Y.Z).

Supports `--dry-run` flag: `/release --dry-run 0.3.0`. In dry-run mode, run pre-flight normally but only **print** what each subsequent phase would do — never execute scripts, push, commit, or create PRs.

Parse arguments:
```bash
DRY_RUN=false
VERSION=""
for arg in $ARGUMENTS; do
  if [[ "$arg" == "--dry-run" ]]; then
    DRY_RUN=true
  else
    VERSION="$arg"
  fi
done
```

If `DRY_RUN` is true, prefix all phase headers with `[DRY-RUN]` and replace execution steps with printed summaries of what would happen.

## Safety Rules

- **NEVER push or create PRs without explicit user confirmation**
- **NEVER commit directly to main** -- always use branches + PRs
- All commits MUST include `Signed-off-by` runner's trailer
- All commits MUST include `Assisted-by: <model>` trailer

## Phase 1: Pre-flight

Runs the same in both normal and dry-run mode — all checks are read-only.

```bash
# Validate version format
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: Invalid version format. Must be X.Y.Z (e.g., 0.2.0)"
  exit 1
fi

# Must be on main
BRANCH=$(git branch --show-current)
if [[ "$BRANCH" != "main" ]]; then
  echo "ERROR: Must be on main branch (currently on $BRANCH)"
  exit 1
fi

# Must be up to date
git fetch origin
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
if [[ "$LOCAL" != "$REMOTE" ]]; then
  echo "WARNING: Local main differs from origin/main"
  echo "Run: git pull origin main"
fi

# Check VERSION file has -dev suffix
CURRENT_VERSION=$(cat VERSION)
if [[ ! "$CURRENT_VERSION" =~ -dev$ ]]; then
  echo "WARNING: VERSION file is '$CURRENT_VERSION' (expected *-dev)"
fi

# Check prerequisites
MISSING=""
for cmd in operator-sdk opm make gh; do
  command -v $cmd &>/dev/null || MISSING="$MISSING $cmd"
done
if [[ -n "$MISSING" ]]; then
  echo "ERROR: Missing required tools:$MISSING"
  exit 1
fi

# Check no conflicting release branch or tag
MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)
RELEASE_BRANCH="release-${MAJOR}.${MINOR}.x"
git rev-parse --verify "refs/remotes/origin/$RELEASE_BRANCH" 2>/dev/null && \
  echo "WARNING: Remote branch $RELEASE_BRANCH already exists"
if git ls-remote --tags origin "v${VERSION}" 2>/dev/null | grep -q .; then
  echo "ERROR: Tag v${VERSION} already exists on remote"
  exit 1
fi
```

Report pre-flight results. Ask user to confirm before proceeding.

## Phase 2: Prepare Release

**Dry-run:** Print what would run, skip execution:
```text
[DRY-RUN] Would run: ./hack/prepare-release.sh <VERSION>
[DRY-RUN] Expected outputs:
  - bundle/manifests/, bundle/metadata/
  - catalog/automotive-dev-operator.yaml
  - community-operators-prod/operators/automotive-dev-operator/<VERSION>/
  - RELEASE_NOTES_v<VERSION>.md (with changelog from git log)
```

**Normal mode:** Run the prepare-release script which generates bundle, catalog, community-operators structure, and release notes.

```bash
./hack/prepare-release.sh "$VERSION"
```

Verify outputs exist:
- `bundle/manifests/` and `bundle/metadata/`
- `catalog/automotive-dev-operator.yaml`
- `community-operators-prod/operators/automotive-dev-operator/$VERSION/`
- `RELEASE_NOTES_v${VERSION}.md`
- `com.redhat.openshift.versions` annotation in `community-operators-prod/.../metadata/annotations.yaml`

Report what was generated. Ask user: "Ready to create release branch and tag?"

## Phase 3: Create Release Branch

**Dry-run:** Print what would happen:
```text
[DRY-RUN] Would run: ./hack/create-release-branch.sh <VERSION>
[DRY-RUN] This creates branch release-X.Y.x, commits VERSION, pushes branch + tag v<VERSION>
[DRY-RUN] CI will then: build images, create GitHub release, auto-bump VERSION on main
```

**Normal mode:**

Run the release branch script:

```bash
./hack/create-release-branch.sh "$VERSION"
```

This creates `release-X.Y.x` branch, commits VERSION, pushes branch + tag. CI will:
1. Build and push all images on tag push
2. Create GitHub release with CLI binaries and install manifest
3. Auto-bump VERSION to next dev version on main (`post-release.yml`)

Report: "Release branch and tag pushed. CI building images."

## Phase 4: Community Operators PR

Submit the operator bundle to the community-operators-prod catalog.

**Dry-run:** Print what would happen:
```text
[DRY-RUN] Would check for fork of community-operators-prod
[DRY-RUN] Would clone/update fork at ~/dev/community-operators-prod
[DRY-RUN] Would create branch: automotive-dev-operator-<VERSION>
[DRY-RUN] Would copy bundle and commit
[DRY-RUN] Would push to fork and create PR to redhat-openshift-ecosystem/community-operators-prod
```

**Normal mode:**

### 4a. Clone or update fork

```bash
COMM_OPS_DIR="$HOME/dev/community-operators-prod"

if [ ! -d "$COMM_OPS_DIR" ]; then
  FORK=$(gh repo list --fork --json nameWithOwner,name --jq '.[] | select(.name == "community-operators-prod") | .nameWithOwner')
  if [ -z "$FORK" ]; then
    echo "ERROR: No fork of community-operators-prod found. Fork it first:"
    echo "  gh repo fork redhat-openshift-ecosystem/community-operators-prod"
    exit 1
  fi
  gh repo clone "$FORK" "$COMM_OPS_DIR" -- --depth=1
fi
```

### 4b. Sync and create branch

```bash
REPO_ROOT="$(pwd)"
cd "$COMM_OPS_DIR"

git remote get-url upstream 2>/dev/null || \
  git remote add upstream https://github.com/redhat-openshift-ecosystem/community-operators-prod.git

git fetch upstream
git checkout main 2>/dev/null || git checkout -b main upstream/main
git reset --hard upstream/main

git checkout -b "automotive-dev-operator-${VERSION}"
```

### 4c. Copy bundle and commit

```bash
OPERATOR_DIR="$COMM_OPS_DIR/operators/automotive-dev-operator"
SOURCE_DIR="$REPO_ROOT/community-operators-prod/operators/automotive-dev-operator"

mkdir -p "$OPERATOR_DIR/${VERSION}"
cp -r "${SOURCE_DIR}/${VERSION}/"* "$OPERATOR_DIR/${VERSION}/"

if [ -f "${SOURCE_DIR}/ci.yaml" ] && [ ! -f "$OPERATOR_DIR/ci.yaml" ]; then
  cp "${SOURCE_DIR}/ci.yaml" "$OPERATOR_DIR/ci.yaml"
fi

git add "operators/automotive-dev-operator/"
git commit -sm "operator automotive-dev-operator (${VERSION})"
```

Ask user: "Community-operators commit ready. Push to fork and create PR?"

On confirmation:

```bash
git push origin "automotive-dev-operator-${VERSION}"

gh pr create \
  --repo redhat-openshift-ecosystem/community-operators-prod \
  --head "$(gh api user --jq '.login'):automotive-dev-operator-${VERSION}" \
  --title "operator automotive-dev-operator (${VERSION})" \
  --body "Submitting automotive-dev-operator version ${VERSION} to community operators catalog."
```

Return to the operator repo directory after this phase.

## Phase 5: Summary

Report final status:
- Release branch: `release-X.Y.x`
- Tag: `v$VERSION`
- CI status: link to GitHub Actions runs
- Community-operators PR: link
- Note: post-release version bump is handled by CI (`post-release.yml`)

## Troubleshooting

### Community operators pipeline fails on `check_api_version_constraints`
Missing `com.redhat.openshift.versions` in `metadata/annotations.yaml`. The `make community-operators-bundle` target handles this. If not, add manually:
```bash
echo '  com.redhat.openshift.versions: v4.18-v4.21' >> metadata/annotations.yaml
```

### CI race condition (retag before build)
Fixed in PR #330. The `retag-on-release` job now depends on build jobs via `needs`.

### Community-operators PR push fails
Ensure you have a fork of `redhat-openshift-ecosystem/community-operators-prod` and `gh` is authenticated. The skill auto-detects your fork via `gh repo list --fork`.
