#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

LOG_DIR="/var/log/wordops-bootstrap"
LOG_FILE="${LOG_DIR}/install.log"
DEFAULT_PHP_VERSION="8.4"
SCRIPT_VERSION="0.1.7"
SSH_PORT="2007"
SSH_USER_HOME="/root"
SSH_AUTHORIZED_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN7QdvL/98G/s7MsjScpWAKnQZFp1hwbcZTHfwuLJk6T amator_godkeys"

# Colors (only if terminal supports it)
if [[ -t 1 ]]; then
  readonly RED='\033[0;31m'
  readonly GREEN='\033[0;32m'
  readonly YELLOW='\033[1;33m'
  readonly BLUE='\033[0;34m'
  readonly CYAN='\033[0;36m'
  readonly BOLD='\033[1m'
  readonly NC='\033[0m' # No Color
else
  readonly RED=''
  readonly GREEN=''
  readonly YELLOW=''
  readonly BLUE=''
  readonly CYAN=''
  readonly BOLD=''
  readonly NC=''
fi

# Step counter
STEP_COUNT=0
TOTAL_STEPS=8
START_TIME=$(date +%s)

# Display colored text to terminal (stdout goes through tee which strips ANSI for log)
log() {
  local timestamp message
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  message="$*"
  # Use printf with %b to interpret escape sequences (ANSI colors)
  printf '%s %b\n' "${timestamp}" "${message}"
}

log_info() {
  local message="[INFO] $*"
  log "${BLUE}${message}${NC}"
}

log_success() {
  local message="[✓] $*"
  log "${GREEN}${message}${NC}"
}

log_warning() {
  local message="[WARN] $*"
  log "${YELLOW}${message}${NC}"
}

# Run a command and keep going on failure (logs warning for visibility)
run_or_warn() {
  local cmd_display="$*"
  if ! "$@"; then
    log_warning "Command failed (continuing): ${cmd_display}"
    return 0
  fi
}

log_error() {
  local message="[ERROR] $*"
  log "${RED}${message}${NC}"
}

log_step() {
  STEP_COUNT=$((STEP_COUNT + 1))
  local message="[STEP ${STEP_COUNT}/${TOTAL_STEPS}] $*"
  log "${CYAN}${BOLD}${message}${NC}"
}

log_section() {
  local separator="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  echo ""
  echo -e "${timestamp} ${BOLD}${CYAN}${separator}${NC}"
  echo -e "${timestamp} ${BOLD}${CYAN}  $*${NC}"
  echo -e "${timestamp} ${BOLD}${CYAN}${separator}${NC}"
  echo ""
}

get_elapsed_time() {
  local current_time elapsed
  current_time=$(date +%s)
  elapsed=$((current_time - START_TIME))
  local hours=$((elapsed / 3600))
  local minutes=$(((elapsed % 3600) / 60))
  local seconds=$((elapsed % 60))
  
  if [[ ${hours} -gt 0 ]]; then
    printf "%dh %dm %ds" "${hours}" "${minutes}" "${seconds}"
  elif [[ ${minutes} -gt 0 ]]; then
    printf "%dm %ds" "${minutes}" "${seconds}"
  else
    printf "%ds" "${seconds}"
  fi
}

fail() {
  log_error "$1"
  echo ""
  log_error "Installation failed after $(get_elapsed_time). Check ${LOG_FILE} for details."
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Please run this script as root (sudo)."
  fi
}

check_os() {
  log_step "Checking OS compatibility"
  if [[ ! -f /etc/os-release ]]; then
    fail "Cannot detect operating system version."
  fi

  # shellcheck disable=SC1091
  source /etc/os-release

  if [[ "${ID,,}" != "ubuntu" ]]; then
    fail "This installer supports Ubuntu only. Detected: ${ID:-unknown}"
  fi

  local major="${VERSION_ID%%.*}"
  if [[ "${major}" != "24" ]]; then
    fail "Ubuntu 24.x is required. Detected VERSION_ID=${VERSION_ID:-unknown}"
  fi

  log_success "OS check passed (Ubuntu ${VERSION_ID})"
}

# Strip ANSI escape sequences from text
strip_ansi() {
  sed 's/\x1b\[[0-9;]*m//g' 2>/dev/null || sed 's/\033\[[0-9;]*m//g' 2>/dev/null || cat
}

setup_logging() {
  mkdir -p "${LOG_DIR}"
  touch "${LOG_FILE}"
  chmod 600 "${LOG_FILE}"
  
  # Redirect stdout/stderr: keep colors for terminal, strip ANSI codes for log file
  exec > >(tee >(strip_ansi >> "${LOG_FILE}"))
  exec 2>&1
  
  log_info "Logging to ${LOG_FILE}"
}

prepare_environment() {
  log_step "Preparing environment"
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  # Force unbuffered output for all commands
  export PYTHONUNBUFFERED=1
  export PYTHONIOENCODING=utf-8
}

update_system() {
  log_step "Updating system packages"
  
  log_info "Updating apt package index..."
  apt-get update -qq

  # Check if there are packages available for upgrade
  if apt list --upgradable 2>/dev/null | grep -q "upgradable"; then
    log_info "Upgrading installed packages (this may take a while)..."
    apt-get -y full-upgrade -qq
  else
    log_warning "System is already up-to-date. Skipping upgrade."
  fi

  log_info "Cleaning up unused packages..."
  apt-get -y autoremove -qq
  apt-get -y autoclean -qq

  log_success "System update completed"
}

is_package_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

install_prerequisites() {
  log_step "Installing prerequisite packages"
  
  # Only install what's needed to download and run the WordOps installer
  # The WordOps installer itself will handle installing all its dependencies
  local packages=(
    ca-certificates  # Required for HTTPS downloads
    wget             # Required to download the installer script
  )

  local missing_packages=()
  for package in "${packages[@]}"; do
    if ! is_package_installed "${package}"; then
      missing_packages+=("${package}")
    fi
  done

  if [[ ${#missing_packages[@]} -eq 0 ]]; then
    log_warning "Prerequisites already installed. Skipping."
    return
  fi

  log_info "Installing missing packages: ${missing_packages[*]}"
  apt-get -y install "${missing_packages[@]}" -qq

  log_success "Prerequisites installed"
}

install_wordops() {
  log_step "Installing WordOps"
  
  if command -v wo >/dev/null 2>&1; then
    log_warning "WordOps already installed (wo command found). Skipping installer."
    return
  fi

  log_info "Downloading WordOps installer from https://wops.cc..."
  local installer
  installer="$(mktemp)"
  wget -O "${installer}" "https://wops.cc"

  log_info "Running WordOps installer (this may take several minutes)..."
  bash "${installer}" --force
  rm -f "${installer}"

  if ! command -v wo >/dev/null 2>&1; then
    fail "WordOps installation failed (wo command not found)."
  fi

  log_success "WordOps installation completed"
}

install_stack() {
  log_step "Installing WordOps stack components"
  
  if ! command -v wo >/dev/null 2>&1; then
    fail "WordOps is not installed. Cannot install stack components."
  fi

  local php_flag_version="${DEFAULT_PHP_VERSION//./}"
  local components=(
    "--nginx"
    "--php${php_flag_version}"
    "--mysql"
    "--wpcli"
    "--fail2ban"
    "--ufw"
    "--ngxblocker"
    "--brotli"
  )

  for component in "${components[@]}"; do
    wo stack install "${component}" >/dev/null 2>&1 || true
  done
}

harden_nginx_defaults() {
  log_step "Hardening Nginx default site"

  if ! command -v nginx >/dev/null 2>&1; then
    log_warning "Nginx is not installed; skipping default-site hardening."
    return
  fi

  rm -rf /var/www/22222 || true
  rm -f /etc/nginx/sites-available/22222 /etc/nginx/sites-enabled/22222 || true
  rm -rf /var/www/html || true

  cat >/etc/nginx/sites-available/default <<'EOF'
# Default catch-all: close connection without serving content
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    return 444;
}

# This server block handles HTTPS requests with no valid SSL config
server {
    listen 443 default_server;
    listen [::]:443 default_server;
    return 444;  # closes connection with no response
}
EOF

  ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

  if nginx -t; then
    systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || log_warning "Nginx reload failed; please reload manually."
    log_success "Nginx default site hardened"
  else
    fail "Nginx config test failed. Check ${LOG_FILE} for details."
  fi
}

configure_ssh_security() {
  log_step "Securing SSH access"

  local ssh_dir="${SSH_USER_HOME}/.ssh"
  local authorized_keys="${ssh_dir}/authorized_keys"

  mkdir -p "${ssh_dir}"
  chmod 700 "${ssh_dir}"

  if [[ -f "${authorized_keys}" ]] && grep -qxF "${SSH_AUTHORIZED_KEY}" "${authorized_keys}"; then
    log_warning "Provided SSH key already present in ${authorized_keys}"
  else
    echo "${SSH_AUTHORIZED_KEY}" >> "${authorized_keys}"
    log_info "Added provided SSH key to ${authorized_keys}"
  fi
  chmod 600 "${authorized_keys}"

  log_info "Hardening SSH via WordOps (disables password auth and root password login)"
  run_or_warn wo secure --ssh --force
  log_info "Setting SSH port to ${SSH_PORT} via WordOps"
  run_or_warn wo secure --sshport "${SSH_PORT}"

  if command -v ufw >/dev/null 2>&1; then
    # Remove IPv4 and IPv6 rules for target SSH port and WordOps defaults (22, 22222)
    for port in "${SSH_PORT}" 22 22222; do
      while true; do
        # Grab the first matching rule number (handles v4/v6 and tcp entries)
        RULE_NUM=$(ufw status numbered | grep -E " ${port}(/tcp)? " | awk -F'[][]' '{print $2}' | head -n1)
        if [[ -z "${RULE_NUM}" ]]; then
          break
        fi
        run_or_warn yes | ufw delete "${RULE_NUM}" >/dev/null 2>&1
      done
    done
    run_or_warn ufw reload
  fi
  
  log_success "SSH secured on port ${SSH_PORT} with key-based authentication"
}


summarize() {
  local elapsed_time
  elapsed_time=$(get_elapsed_time)
  
  echo ""
  log_section "Installation Complete"
  
  log_success "WordOps bootstrap completed successfully in ${elapsed_time}"
  echo ""
  
  log_info "${BOLD}Next steps:${NC}"
  echo ""
  echo -e "  ${CYAN}1.${NC} Verify WordOps status:"
  echo -e "     ${GREEN}wo info${NC}"
  echo ""
  echo -e "  ${CYAN}2.${NC} Create a test site:"
  echo -e "     ${GREEN}wo site create example.com --wp${NC}"
  echo ""
  log_info "SSH hardened by WordOps on port ${SSH_PORT}; key saved to ${SSH_USER_HOME}/.ssh/authorized_keys"
  
  log_info "Installation log saved to: ${BOLD}${LOG_FILE}${NC}"
  echo ""
}

main() {
  require_root
  setup_logging
  
  echo ""
  log_section "WordOps Automatic Installation for Ubuntu 24 (v${SCRIPT_VERSION})"
  log_info "This script will install and configure WordOps on your system"
  log_info "Estimated time: 5-15 minutes (depending on system speed)"
  echo ""
  
  trap 'fail "Installation interrupted."' INT TERM
  trap 'fail "A command failed. Check the log for details."' ERR

  check_os
  prepare_environment
  update_system
  install_prerequisites
  install_wordops
  install_stack
  configure_ssh_security
  harden_nginx_defaults
  summarize
}

main "$@"

