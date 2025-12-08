#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

LOG_DIR="/var/log/wordops-bootstrap"
LOG_FILE="${LOG_DIR}/install.log"
DEFAULT_PHP_VERSION="8.4"
SCRIPT_VERSION="0.1.9"
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

update_wpcommon_robots_rule() {
  local conf="/etc/nginx/common/wpcommon-php84.conf"
  local tmp

  if [[ ! -f "${conf}" ]]; then
    log_warning "Skipping robots rule update; ${conf} not found."
    return
  fi

  # Avoid duplicate rewrites if already updated
  if grep -Fq "location ~ ^/.*robots.*\\.txt$" "${conf}"; then
    log_info "Robots rule already updated in ${conf}"
    return
  fi

  if ! grep -Fq 'location = /robots.txt {' "${conf}"; then
    log_warning "Expected robots block not found in ${conf}; no changes applied."
    return
  fi

  tmp=$(mktemp)

  if sed '/^location = \/robots.txt {$/,/^}/c\
location ~ ^/.*robots.*\\.txt$ {\
# Some WordPress plugin gererate robots.txt file\
# Refer #340 issue\
    rewrite ^/robots.txt$ /?robots=1 last;\
    rewrite ^/([^/]+?)-robots([0-9]+)?.txt$ /?robots=$1&robots_n=$2 last;\
    try_files $uri $uri/ /index.php?$args @robots;\
    access_log off;\
    log_not_found off;\
}' "${conf}" > "${tmp}"; then
    mv "${tmp}" "${conf}"
    log_success "Updated robots rule in ${conf}"
  else
    rm -f "${tmp}"
    fail "Failed to update robots rule in ${conf}"
  fi
}

append_wpcommon_sitemap_rules() {
  local conf="/etc/nginx/common/wpcommon-php84.conf"

  if [[ ! -f "${conf}" ]]; then
    log_warning "Skipping sitemap rules append; ${conf} not found."
    return
  fi

  if grep -Fq "Sitemap rewrite rules from XML Sitemap Generator for Google plugin" "${conf}"; then
    log_info "Sitemap rules already present in ${conf}"
    return
  fi

  {
    echo ""
    cat <<'EOF'
# Sitemap rewrite rules from XML Sitemap Generator for Google plugin
rewrite ^/.*-misc?\.xml$ "/index.php?xml_sitemap=params=$2" last;
rewrite ^/.*-misc?\.xml\.gz$ "/index.php?xml_sitemap=params=$2;zip=true" last;
rewrite ^/.*-misc?\.html$ "/index.php?xml_sitemap=params=$2;html=true" last;
rewrite ^/.*-misc?\.html\.gz$ "/index.php?xml_sitemap=params=$2;html=true;zip=true" last;
rewrite ^/.*-sitemap.*(?:\d\{1,4\}(?!-misc)|-misc)?\.xml$ "/index.php?xml_sitemap=params=$2" last;
rewrite ^/.*-sitemap.*(?:\d\{1,4\}(?!-misc)|-misc)?\.xml\.gz$ "/index.php?xml_sitemap=params=$2;zip=true" last;
rewrite ^/.*-sitemap.*(?:\d\{1,4\}(?!-misc)|-misc)?\.html$ "/index.php?xml_sitemap=params=$2;html=true" last;
rewrite ^/.*-sitemap.*(?:\d\{1,4\}(?!-misc)|-misc)?\.html\.gz$ "/index.php?xml_sitemap=params=$2;html=true;zip=true" last;
EOF
  } >> "${conf}" || fail "Failed to append sitemap rewrite rules to ${conf}"

  log_success "Appended sitemap rewrite rules to ${conf}"
}

configure_nginx_defaults() {
  log_step "Configuring Nginx default site"

  if ! command -v nginx >/dev/null 2>&1; then
    log_warning "Nginx is not installed; skipping default-site configuring."
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
  update_wpcommon_robots_rule
  append_wpcommon_sitemap_rules

  if nginx -t; then
    systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || log_warning "Nginx reload failed; please reload manually."
    log_success "Nginx default site hardened"
  else
    fail "Nginx config test failed. Check ${LOG_FILE} for details."
  fi
}

configure_ssh_security() {
  log_step "Securing SSH access"

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
  local sshd_config_snippet="/etc/ssh/sshd_config.d/99-wo-bootstrap.conf"

  mkdir -p "${ssh_dir}"
  chmod 700 "${ssh_dir}"
  chown "${ssh_user}:${ssh_group}" "${ssh_dir}"

  if [[ -f "${authorized_keys}" ]] && grep -qxF "${SSH_AUTHORIZED_KEY}" "${authorized_keys}"; then
    log_warning "Provided SSH key already present in ${authorized_keys}"
  else
    echo "${SSH_AUTHORIZED_KEY}" >> "${authorized_keys}"
    log_info "Added provided SSH key to ${authorized_keys}"
  fi
  chmod 600 "${authorized_keys}"
  chown "${ssh_user}:${ssh_group}" "${authorized_keys}"

  log_info "Applying hardened sshd configuration (port ${SSH_PORT}, key-only auth)"
  mkdir -p /etc/ssh/sshd_config.d
  cat >"${sshd_config_snippet}" <<EOF
# Managed by WordOps bootstrap - custom SSH configuring
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
      log_warning "SSH restart failed; attempting to recover via ${ssh_socket_unit}"
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
    for port in "${SSH_PORT}" 22 22222; do
      while true; do
        RULE_NUM=$(ufw status numbered 2>/dev/null | grep -E " ${port}(/tcp)? " | awk -F'[][]' '{print $2}' | head -n1 || true)
        if [[ -z "${RULE_NUM}" ]]; then
          break
        fi
        yes | ufw delete "${RULE_NUM}" >/dev/null 2>&1 || true
      done
    done

    ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || log_warning "Failed to allow SSH port ${SSH_PORT} via UFW"
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
  log_info "SSH hardened on port ${SSH_PORT}; key saved to ${SSH_USER_HOME}/.ssh/authorized_keys"
  
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
  configure_nginx_defaults

  update_system # update wordops packages and dependencies
  summarize
}

main "$@"

