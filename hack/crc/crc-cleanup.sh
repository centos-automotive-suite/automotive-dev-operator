#!/bin/bash
set -euo pipefail

# CRC (OpenShift Local) Cleanup — Linux x86_64 & macOS
# Linux:  sudo bash crc-cleanup.sh [--full]
# macOS:  bash crc-cleanup.sh [--full]
#
# --full : remove CRC binary, user (Linux), brew cask (macOS), and ~/.crc cache

###############################################################################
# Configuration
###############################################################################
CRC_USER="developer"
FULL=false
[[ "${1:-}" == "--full" ]] && FULL=true

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}>>> $*${NC}"; }
ok()    { echo -e "${GREEN}✅  $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠️   $*${NC}"; }
fail()  { echo -e "${RED}❌  $*${NC}"; exit 1; }
line()  { echo "========================================="; }

OS="$(uname)"

line
echo "   CRC Cleanup — $([ "$FULL" = true ] && echo "FULL" || echo "Standard")"
line

###############################################################################
# macOS
###############################################################################
if [[ "$OS" == "Darwin" ]]; then
    [[ $EUID -eq 0 ]] && fail "Do NOT run as root on macOS."

    if ! command -v crc &>/dev/null; then
        warn "CRC binary not found — skipping stop/delete/cleanup."
    else
        info "[1/3] Stopping CRC cluster..."
        crc stop 2>/dev/null || warn "Cluster was not running."

        info "[2/3] Deleting CRC VM..."
        crc delete -f 2>/dev/null || warn "No VM to delete."

        info "[3/3] Running crc cleanup..."
        crc cleanup 2>/dev/null || warn "Nothing to clean up."
    fi

    if [[ "$FULL" == true ]]; then
        info "Full cleanup: removing CRC binary and cache..."
        if brew list --cask crc &>/dev/null 2>&1; then
            brew uninstall --cask crc && ok "Homebrew cask removed."
        elif [[ -f /usr/local/bin/crc ]]; then
            sudo rm -f /usr/local/bin/crc && ok "Binary removed."
        fi
        rm -rf "$HOME/.crc" && ok "$HOME/.crc cache removed."
    fi

    ok "macOS cleanup complete."

###############################################################################
# Linux
###############################################################################
elif [[ "$OS" == "Linux" ]]; then
    [[ $EUID -eq 0 ]] || fail "Run as root on Linux: sudo bash $0 $*"

    if id "$CRC_USER" &>/dev/null; then
        TARGET_UID=$(id -u "$CRC_USER")
        USER_HOME=$(eval echo "~${CRC_USER}")

        info "[1/4] Stopping CRC cluster as '$CRC_USER'..."
        su - "$CRC_USER" -c "
            export XDG_RUNTIME_DIR=/run/user/${TARGET_UID}
            export DBUS_SESSION_BUS_ADDRESS=unix:path=\$XDG_RUNTIME_DIR/bus
            crc stop 2>/dev/null || true
        " || warn "Cluster was not running."

        info "[2/4] Deleting CRC VM as '$CRC_USER'..."
        su - "$CRC_USER" -c "
            export XDG_RUNTIME_DIR=/run/user/${TARGET_UID}
            export DBUS_SESSION_BUS_ADDRESS=unix:path=\$XDG_RUNTIME_DIR/bus
            crc delete -f 2>/dev/null || true
        " || warn "No VM to delete."

        info "[3/4] Running crc cleanup as '$CRC_USER'..."
        echo "${CRC_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/crc-temp
        chmod 0440 /etc/sudoers.d/crc-temp
        trap 'rm -f /etc/sudoers.d/crc-temp' EXIT
        su - "$CRC_USER" -c "
            export XDG_RUNTIME_DIR=/run/user/${TARGET_UID}
            export DBUS_SESSION_BUS_ADDRESS=unix:path=\$XDG_RUNTIME_DIR/bus
            crc cleanup 2>/dev/null || true
        " || warn "Nothing to clean up."
        trap - EXIT
        rm -f /etc/sudoers.d/crc-temp
    else
        warn "User '$CRC_USER' does not exist — skipping CRC commands."
    fi

    if [[ "$FULL" == true ]]; then
        info "[4/4] Full cleanup: removing user, binary, sudoers, and cache..."

        rm -f /etc/sudoers.d/crc-temp /etc/sudoers.d/crc-deploy 2>/dev/null && ok "Stale sudoers files removed."

        if id "$CRC_USER" &>/dev/null; then
            USER_HOME=${USER_HOME:-$(eval echo "~${CRC_USER}")}
            loginctl disable-linger "$CRC_USER" 2>/dev/null || true
            killall -u "$CRC_USER" 2>/dev/null || true
            sleep 1
            userdel -r "$CRC_USER" 2>/dev/null && ok "User '$CRC_USER' removed."
            if [[ -d "$USER_HOME" ]]; then
                rm -rf "$USER_HOME" && ok "Home directory $USER_HOME removed."
            fi
        fi

        sed -i "/^${CRC_USER}:/d" /etc/subuid 2>/dev/null || true
        sed -i "/^${CRC_USER}:/d" /etc/subgid 2>/dev/null || true

        for crc_path in /usr/local/bin/crc "$HOME/bin/crc" /usr/bin/crc; do
            if [[ -f "$crc_path" ]]; then
                rm -f "$crc_path" && ok "CRC binary removed: $crc_path"
            fi
        done

        if [[ -d "/root/.crc" ]]; then
            rm -rf /root/.crc && ok "/root/.crc cache removed."
        fi
    else
        info "[4/4] Skipped — pass --full to remove user, binary, and cache."
    fi

    ok "Linux cleanup complete."

###############################################################################
# Unsupported
###############################################################################
else
    fail "Unsupported OS: $OS"
fi

line
echo ""
if [[ "$FULL" == true ]]; then
    ok "Full cleanup done. CRC has been completely removed."
else
    ok "Standard cleanup done. VM destroyed, system config reverted."
    echo "   Run again with --full to also remove the binary and ~/.crc cache."
fi
echo ""
line
