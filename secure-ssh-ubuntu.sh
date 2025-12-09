#!/usr/bin/env bash

# Harden SSH on an Ubuntu VPS by enforcing key-only auth and optional port change.
# Requires: sudo/root, OpenSSH server installed, optional UFW for firewall rules.

set -euo pipefail

# Basic configuration (edit these for a quick setup).
# Env vars (SSH_PORT, SSH_USER_HOME, SSH_AUTHORIZED_KEY) still override.
SSH_PORT_DEFAULT="2007"
SSH_USER_HOME_DEFAULT="/root"
SSH_AUTHORIZED_KEY_DEFAULT="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN7QdvL/98G/s7MsjScpWAKnQZFp1hwbcZTHfwuLJk6T amator_godkeys"

log_info()    { echo "[INFO] $*"; }
log_warn()    { echo "[WARN] $*" >&2; }
log_error()   { echo "[ERROR] $*" >&2; }
log_success() { echo "[OK] $*"; }

fail() {
  log_error "$*"
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Please run as root (try: sudo $0)"
  fi
}

usage() {
  cat <<'EOF'
Usage: sudo ./secure-ssh-ubuntu.sh

Environment variables:
  SSH_AUTHORIZED_KEY   Required. Public key string to authorize.
  SSH_PORT             Optional. SSH port to enforce (default: 22).
  SSH_USER_HOME        Optional. Home directory whose authorized_keys is managed
                       (default: /root).
EOF
}

configure_ssh_security() {
  log_info "Securing SSH access"

  if [[ -z "${SSH_AUTHORIZED_KEY:-}" ]]; then
    fail "SSH_AUTHORIZED_KEY is empty; refusing to disable password auth."
  fi

  if [[ ! "${SSH_PORT}" =~ ^[0-9]+$ ]] || ((SSH_PORT < 1 || SSH_PORT > 65535)); then
    fail "SSH_PORT must be an integer between 1 and 65535. Got: ${SSH_PORT}"
  fi

  if [[ ! -d "${SSH_USER_HOME}" ]]; then
    fail "SSH_USER_HOME path ${SSH_USER_HOME} does not exist."
  fi

  local ssh_user ssh_group
  ssh_user=$(stat -c '%U' "${SSH_USER_HOME}")
  ssh_group=$(stat -c '%G' "${SSH_USER_HOME}")

  local ssh_dir="${SSH_USER_HOME}/.ssh"
  local authorized_keys="${ssh_dir}/authorized_keys"
  local sshd_config_snippet="/etc/ssh/sshd_config.d/99-secure-ssh.conf"

  mkdir -p "${ssh_dir}"
  chmod 700 "${ssh_dir}"
  chown "${ssh_user}:${ssh_group}" "${ssh_dir}"

  if [[ -f "${authorized_keys}" ]] && grep -qxF "${SSH_AUTHORIZED_KEY}" "${authorized_keys}"; then
    log_warn "Provided SSH key already present in ${authorized_keys}"
  else
    echo "${SSH_AUTHORIZED_KEY}" >> "${authorized_keys}"
    log_info "Added provided SSH key to ${authorized_keys}"
  fi
  chmod 600 "${authorized_keys}"
  chown "${ssh_user}:${ssh_group}" "${authorized_keys}"

  log_info "Applying hardened sshd configuration (port ${SSH_PORT}, key-only auth)"
  mkdir -p /etc/ssh/sshd_config.d
  cat >"${sshd_config_snippet}" <<EOF
# Managed by secure-ssh-ubuntu.sh - custom SSH configuration
Port ${SSH_PORT}
Protocol 2
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
AllowAgentForwarding yes
AllowTcpForwarding yes
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

  if sshd -t -f /etc/ssh/sshd_config; then
    local ssh_socket_unit="ssh.socket"
    local ssh_service_unit="ssh.service"
    local socket_present=false

    if systemctl list-unit-files --type=socket 2>/dev/null | awk '{print $1}' | grep -qx "${ssh_socket_unit}"; then
      socket_present=true
      systemctl stop "${ssh_socket_unit}" 2>/dev/null || true
      systemctl disable "${ssh_socket_unit}" 2>/dev/null || true
      systemctl mask "${ssh_socket_unit}" 2>/dev/null || true
      log_info "Disabled ${ssh_socket_unit} to allow custom SSH port ${SSH_PORT}"
    fi

    systemctl enable "${ssh_service_unit}" 2>/dev/null || true

    if systemctl restart "${ssh_service_unit}" 2>/dev/null; then
      log_info "Restarted ${ssh_service_unit} on port ${SSH_PORT}"
    else
      log_warn "SSH restart failed; attempting to recover via ${ssh_socket_unit}"
      if [[ "${socket_present}" == true ]]; then
        systemctl unmask "${ssh_socket_unit}" 2>/dev/null || true
        systemctl enable "${ssh_socket_unit}" 2>/dev/null || true
        systemctl start "${ssh_socket_unit}" 2>/dev/null || true
      fi
      fail "Could not restart SSH service; please check logs."
    fi
  else
    fail "sshd configuration invalid; aborting to avoid lockout."
  fi

  if ! ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${SSH_PORT}$"; then
    if systemctl list-unit-files --type=socket 2>/dev/null | awk '{print $1}' | grep -qx "ssh.socket"; then
      systemctl unmask ssh.socket 2>/dev/null || true
      systemctl enable ssh.socket 2>/dev/null || true
      systemctl start ssh.socket 2>/dev/null || true
    fi
    fail "sshd is not listening on port ${SSH_PORT} after restart; check sshd logs."
  fi

  if command -v ufw >/dev/null 2>&1; then
    # Reset SSH rules: drop defaults, then allow the configured port once
    for port in "${SSH_PORT}" 22; do
      while true; do
        RULE_NUM=$(ufw status numbered 2>/dev/null | grep -E " ${port}(/tcp)? " | awk -F'[][]' '{print $2}' | head -n1 || true)
        if [[ -z "${RULE_NUM}" ]]; then
          break
        fi
        yes | ufw delete "${RULE_NUM}" >/dev/null 2>&1 || true
      done
    done

    ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || log_warn "Failed to allow SSH port ${SSH_PORT} via UFW"
  fi

  log_success "SSH secured on port ${SSH_PORT} with key-based authentication"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_root

  # Resolve configuration: env vars take precedence over editable defaults above.
  SSH_PORT="${SSH_PORT:-${SSH_PORT_DEFAULT}}"
  SSH_USER_HOME="${SSH_USER_HOME:-${SSH_USER_HOME_DEFAULT}}"
  SSH_AUTHORIZED_KEY="${SSH_AUTHORIZED_KEY:-${SSH_AUTHORIZED_KEY_DEFAULT}}"

  configure_ssh_security
}

main "$@"

