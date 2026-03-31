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
#   1. 01-prep-host.sh                  (as root on Linux, normal user on macOS)
#   2. 04-expose-default-registry.sh    (as root on Linux, normal user on macOS)
#   3. 02-deploy-operator.sh            (as SUDO_USER on Linux, normal user on macOS)
#   4. 03-crc-operator-sanity.sh        (sanity checks, + e2e build test if --sanity)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OS="$(uname -s)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}>>> $*${NC}"; }
ok()    { echo -e "${GREEN}$*${NC}"; }
fail()  { echo -e "${RED}$*${NC}"; exit 1; }

if [[ "$OS" == "Linux" ]]; then
    [[ $EUID -eq 0 ]] || fail "On Linux, run with sudo: sudo bash $0 <pull-secret-path> [--sanity]"
    export CRC_USER="${CRC_USER:-${SUDO_USER:-}}"
    [[ -n "$CRC_USER" ]] || fail "Cannot determine non-root user. Set CRC_USER or run via sudo."
    id "$CRC_USER" &>/dev/null || fail "User '$CRC_USER' does not exist."
fi

E2E_FLAG=""
PULL_SECRET="${PULL_SECRET:-}"
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
    USER_HOME=$(getent passwd "$CRC_USER" | cut -d: -f6)
    REPO_DIR_FOR_USER="$REPO_DIR"
    # If the repo is not readable+writable(write access is needed by deploy-catalog.sh) by CRC_USER, copy it for the target user.
    if ! su - "$CRC_USER" -c "test -r $(printf '%q' "$REPO_DIR") && test -w $(printf '%q' "$REPO_DIR")"; then
        REPO_DIR_FOR_USER="$USER_HOME/automotive-dev-operator"
        info "Repository path is not accessible to ${CRC_USER}. Copying repo to ${REPO_DIR_FOR_USER}..."
        mkdir -p "$REPO_DIR_FOR_USER"
        cp -a "$REPO_DIR"/. "$REPO_DIR_FOR_USER"/
        chown -R "$CRC_USER":"$CRC_USER" "$REPO_DIR_FOR_USER"
    fi
    REPO_DIR_Q=$(printf '%q' "$REPO_DIR_FOR_USER")

    info "Exposing external registry route (requires root)..."
    bash "$SCRIPT_DIR/04-expose-default-registry.sh"

    su - "$CRC_USER" -c "
        source ~/.crc_env 2>/dev/null || true
        cd $REPO_DIR_Q
        bash hack/crc/02-deploy-operator.sh
    "
else
    cd "$REPO_DIR"
    info "Exposing external registry route..."
    bash "$SCRIPT_DIR/04-expose-default-registry.sh"
    bash "$SCRIPT_DIR/02-deploy-operator.sh"
fi

###############################################################################
# Phase 3 — Validate
###############################################################################
info "Phase 3/3: Validating deployment"
if [[ "$OS" == "Linux" ]]; then
    su - "$CRC_USER" -c "
        source ~/.crc_env 2>/dev/null || true
        eval \$(crc oc-env)
        cd $REPO_DIR_Q
        bash hack/crc/03-crc-operator-sanity.sh $E2E_FLAG
    "
else
    cd "$REPO_DIR"
    bash "$SCRIPT_DIR/03-crc-operator-sanity.sh" $E2E_FLAG
fi

echo ""
ok "Setup complete. CRC cluster with operator is ready."
echo ""
