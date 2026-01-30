#!/usr/bin/env bash
set -euo pipefail

# ---- Config ---------------------------------------------------------------

HOOKS_DIR="/usr/share/containers/oci/hooks.d"
HOOK_NAME="oci-demo-hook.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BIN_DIR="${BIN_DIR:-$ROOT_DIR/bin}"
HOOK_TEMPLATE="$ROOT_DIR/hook.json"

# ---- Helpers --------------------------------------------------------------

err() {
  echo "Error: $*" >&2
  exit 1
}

info() {
  echo "==> $*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (use sudo)"
  fi
}

# ---- Main -----------------------------------------------------------------

require_root

OCI_HOOK_BIN="$BIN_DIR/oci-hook"

[ -x "$OCI_HOOK_BIN" ] || err "oci-hook binary not found or not executable: $OCI_HOOK_BIN"
[ -f "$HOOK_TEMPLATE" ] || err "hook.json template not found: $HOOK_TEMPLATE"

info "Installing OCI hook configuration"
mkdir -p "$HOOKS_DIR"

sed "s|__OCI_HOOK_PATH__|$OCI_HOOK_BIN|g" "$HOOK_TEMPLATE" \
  > "$HOOKS_DIR/$HOOK_NAME"

info "Installed $HOOKS_DIR/$HOOK_NAME"
info "OCI hook binary: $OCI_HOOK_BIN"

info "Installation complete"
