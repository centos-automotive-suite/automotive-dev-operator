#!/usr/bin/env bash
set -euo pipefail

# setup-crc.sh — Full CRC setup and operator deployment in one command.
#
# Linux:  sudo bash hack/crc/setup-crc.sh <pull-secret-path> [--sanity]
# macOS:  bash hack/crc/setup-crc.sh <pull-secret-path> [--sanity]
#
# Options:
#   --sanity : Run end-to-end build test after validation
#
# This script runs:
#   1. 01-prep-host.sh (as root on Linux, normal user on macOS)
#   2. 02-deploy-operator.sh (as 'developer' on Linux, normal user on macOS)
#   3. 03-crc-operator-sanity.sh        (sanity checks, + e2e build test if --sanity)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OS="$(uname -s)"
CRC_USER="developer"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}>>> $*${NC}"; }
ok()    { echo -e "${GREEN}$*${NC}"; }
fail()  { echo -e "${RED}$*${NC}"; exit 1; }

E2E_FLAG=""
PULL_SECRET=""
for arg in "$@"; do
    if [[ "$arg" == "--sanity" ]]; then
        E2E_FLAG="--sanity"
    elif [[ -z "$PULL_SECRET" ]]; then
        PULL_SECRET="$arg"
    fi
done

[[ -n "$PULL_SECRET" ]] || fail "Usage: $0 <pull-secret-path> [--sanity]"
[[ -f "$PULL_SECRET" ]] || fail "Pull secret not found: $PULL_SECRET"
PULL_SECRET="$(cd "$(dirname "$PULL_SECRET")" && pwd)/$(basename "$PULL_SECRET")"

###############################################################################
# Phase 1 — System prep & CRC setup
###############################################################################
info "Phase 1/3: System preparation and CRC setup"
bash "$SCRIPT_DIR/01-prep-host.sh" "$PULL_SECRET"

###############################################################################
# Phase 2 — Deploy operator
###############################################################################
info "Phase 2/3: Building and deploying operator"
if [[ "$OS" == "Linux" ]]; then
    USER_HOME=$(eval echo "~${CRC_USER}")
    PULL_SECRET_DEST="$USER_HOME/pull-secret.txt"
    DEPLOY_DIR="$USER_HOME/$(basename "$REPO_DIR")"

    if [[ "$REPO_DIR" != "$DEPLOY_DIR" ]]; then
        info "Copying repo to $DEPLOY_DIR (developer user cannot access $REPO_DIR)..."
        rm -rf "$DEPLOY_DIR"
        cp -a "$REPO_DIR" "$DEPLOY_DIR"
        chown -R "${CRC_USER}:${CRC_USER}" "$DEPLOY_DIR"
    fi

    echo "${CRC_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/crc-deploy
    chmod 0440 /etc/sudoers.d/crc-deploy
    trap 'rm -f /etc/sudoers.d/crc-deploy' EXIT

    DEPLOY_DIR_Q=$(printf '%q' "$DEPLOY_DIR")
    PULL_SECRET_DEST_Q=$(printf '%q' "$PULL_SECRET_DEST")

    su - "$CRC_USER" -c "
        source ~/.crc_env 2>/dev/null || true
        cd $DEPLOY_DIR_Q
        bash hack/crc/02-deploy-operator.sh $PULL_SECRET_DEST_Q
    "

    trap - EXIT
    rm -f /etc/sudoers.d/crc-deploy
else
    cd "$REPO_DIR"
    bash "$SCRIPT_DIR/02-deploy-operator.sh" "$PULL_SECRET"
fi

###############################################################################
# Phase 3 — Validate
###############################################################################
info "Phase 3/3: Validating deployment"
if [[ "$OS" == "Linux" ]]; then
    su - "$CRC_USER" -c "
        source ~/.crc_env 2>/dev/null || true
        eval \$(crc oc-env)
        cd $DEPLOY_DIR_Q
        bash hack/crc/03-crc-operator-sanity.sh $E2E_FLAG
    "
else
    cd "$REPO_DIR"
    bash "$SCRIPT_DIR/03-crc-operator-sanity.sh" $E2E_FLAG
fi

echo ""
ok "Setup complete. CRC cluster with operator is ready."
echo ""
if [[ "$OS" == "Linux" ]]; then
    echo "  To use the cluster, switch to the developer user:"
    echo "    su - $CRC_USER"
    echo "    cd $DEPLOY_DIR"
    echo ""
fi
