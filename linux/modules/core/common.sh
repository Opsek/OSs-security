#!/usr/bin/env bash

set -euo pipefail

HARDEN_LOG_FILE="/var/log/linux-harden.log"
HARDEN_BACKUP_DIR_BASE="/var/backups/linux-harden"
HARDEN_VERBOSE="${HARDEN_VERBOSE:-false}"

# Profile settings and configurations
declare -A PROFILE_SETTINGS

# Initialize minimal profile with basic security measures
init_minimal_profile() {
    log_info "Initializing minimal security profile"
    PROFILE_SETTINGS["PROFILE_NAME"]="minimal"
    PROFILE_SETTINGS["PASSWORD_MAX_DAYS"]=365
    PROFILE_SETTINGS["PASSWORD_MIN_DAYS"]=1
    PROFILE_SETTINGS["PASSWORD_WARN_AGE"]=7
    PROFILE_SETTINGS["SSH_PORT"]="22"
    PROFILE_SETTINGS["SSH_PERMIT_ROOT_LOGIN"]="no"
    PROFILE_SETTINGS["SSH_PASSWORD_AUTH"]="yes"
    PROFILE_SETTINGS["FIREWALL_DEFAULT_POLICY"]="accept"
    PROFILE_SETTINGS["IPV6_ENABLED"]="yes"
    PROFILE_SETTINGS["AUDITD_ENABLED"]="no"
    PROFILE_SETTINGS["FAIL2BAN_ENABLED"]="no"
}

# Initialize recommended profile with balanced security
init_recommended_profile() {
    log_info "Initializing recommended security profile"
    PROFILE_SETTINGS["PROFILE_NAME"]="recommended"
    PROFILE_SETTINGS["PASSWORD_MAX_DAYS"]=90
    PROFILE_SETTINGS["PASSWORD_MIN_DAYS"]=7
    PROFILE_SETTINGS["PASSWORD_WARN_AGE"]=14
    PROFILE_SETTINGS["SSH_PORT"]="22"
    PROFILE_SETTINGS["SSH_PERMIT_ROOT_LOGIN"]="no"
    PROFILE_SETTINGS["SSH_PASSWORD_AUTH"]="no"
    PROFILE_SETTINGS["FIREWALL_DEFAULT_POLICY"]="drop"
    PROFILE_SETTINGS["IPV6_ENABLED"]="yes"
    PROFILE_SETTINGS["AUDITD_ENABLED"]="yes"
    PROFILE_SETTINGS["FAIL2BAN_ENABLED"]="no"
}


get_paranoid_ssh_port() {
    local port_file="/etc/ssh/paranoid_ssh_port"
    local port
    local max_attempts=20
    local attempt=0

    # If a port was previously selected, return it if free
    if [[ -f "$port_file" ]]; then
        port=$(cat "$port_file")
        if ! ss -ltn | awk '{print $4}' | grep -q ":$port$"; then
            echo "$port"
            return 0
        else
            log_warn "Stored SSH port $port is in use — selecting a new port"
        fi
    fi

    # Try picking a free random port
    while (( attempt < max_attempts )); do
        port=$(shuf -i 20000-60000 -n 1)
        if ! ss -ltn | awk '{print $4}' | grep -q ":$port$"; then
            echo "$port" | tee "$port_file"
            return 0
        fi
        ((attempt++))
    done

    log_error "Failed to find a free SSH port after $max_attempts attempts"
    return 1
}


# Initialize paranoid profile with maximum security
init_paranoid_profile() {
    log_info "Initializing paranoid security profile"
    PROFILE_SETTINGS["PROFILE_NAME"]="paranoid"
    PROFILE_SETTINGS["PASSWORD_MAX_DAYS"]=30
    PROFILE_SETTINGS["PASSWORD_MIN_DAYS"]=21
    PROFILE_SETTINGS["PASSWORD_WARN_AGE"]=14
        # Pick a safe SSH port
    PROFILE_SETTINGS["SSH_PORT"]="$(get_paranoid_ssh_port)" || {
        log_error "Cannot initialize paranoid profile without a valid SSH port"
        return 1
    }
    PROFILE_SETTINGS["SSH_PERMIT_ROOT_LOGIN"]="no"
    PROFILE_SETTINGS["SSH_PASSWORD_AUTH"]="no"
    PROFILE_SETTINGS["FIREWALL_DEFAULT_POLICY"]="drop"
    PROFILE_SETTINGS["IPV6_ENABLED"]="no"
    PROFILE_SETTINGS["AUDITD_ENABLED"]="yes"
    PROFILE_SETTINGS["FAIL2BAN_ENABLED"]="yes"
}

# Initialize profile settings based on selected profile
init_profile() {
    local profile="${1:-recommended}"
    log_info "Setting up hardening profile: $profile"
    
    case "$profile" in
        minimal)
            init_minimal_profile
            ;;
        recommended)
            init_recommended_profile
            ;;
        paranoid)
            init_paranoid_profile
            ;;
        *)
            log_error "Unknown profile: $profile"
            return 1
            ;;
    esac
    
    export HARDEN_PROFILE="$profile"
    log_info "Profile $profile initialized successfully"
}

# Get a setting value from the current profile
get_profile_setting() {
    local key="$1"
    if [[ -z "${PROFILE_SETTINGS[$key]:-}" ]]; then
        log_error "Profile setting not found: $key"
        return 1
    fi
    echo "${PROFILE_SETTINGS[$key]}"
}

require_root() {
  log_info "Checking for root privileges"
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    log_error "This script must be run as root (sudo) to perform system hardening"
    return 1
  fi
  log_info "Root privileges confirmed - proceeding with hardening"
}

ts() { date +"%Y-%m-%dT%H:%M:%S%z"; }

log_setup() {
  mkdir -p "$(dirname "$HARDEN_LOG_FILE")"
  touch "$HARDEN_LOG_FILE" || true
}

log() {
  local level="$1"; shift
  local msg="$*"
  echo "$(ts) [$level] $msg" | tee -a "$HARDEN_LOG_FILE" >&2
}

log_info() { log INFO "$*"; }
log_warn() { log WARN "$*"; }
log_error() { log ERROR "$*"; }
log_verbose() { 
    if [[ "${HARDEN_VERBOSE}" == "true" ]]; then
        log INFO "$*"
    fi
}

# Function to log section headers with visual separation
log_section() {
    echo
    echo "==============================================================================="
    log INFO "=== $* ==="
    echo "==============================================================================="
    echo
}

backup_file() {
    local file="$1"
    local stamp="$RUN_STAMP"
    local rel dest_dir dest_file

    rel="${file#/}"
    dest_dir="$HARDEN_BACKUP_DIR_BASE/$stamp/$(dirname "$rel")"
    dest_file="$dest_dir/$(basename "$file")"

    log_verbose "Ensuring backup exists for: $file"
    mkdir -p "$dest_dir"

    if [[ ! -f "$file" ]]; then
        log_verbose "File $file does not exist — no backup needed"
        return 0
    fi

    if [[ -e "$dest_file" ]]; then
        log_verbose "Backup already exists — preserving original: $dest_file"
        return 0
    fi

    cp -a "$file" "$dest_file" || true
    log_verbose "Backup created: $dest_file"
}

apply_line() {
  # Ensure a key=value or config line exists (replace or append)
  local file="$1"; shift
  local pattern="$1"; shift
  local line="$1"; shift
  log_verbose "Configuring setting in $file: $line"
  if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
    log_info "[dry-run] ensure '$pattern' in $file -> $line"
    return 0
  fi
  backup_file "$file"
  touch "$file"
  if grep -Eq "^$pattern" "$file"; then
    sed -ri "s|^$pattern.*|$line|" "$file"
  else
    printf '%s\n' "$line" >> "$file"
  fi
}

ensure_owner_perm() {
  local path="$1" owner="$2" group="$3" mode="$4"
  if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
    log_info "[dry-run] chown $owner:$group $path && chmod $mode $path"
    return 0
  fi
  backup_file "$path"
  chown "$owner:$group" "$path" 2>/dev/null || true
  chmod "$mode" "$path" 2>/dev/null || true
}

pkg_install() {
  local pkgs=("$@")
  log_verbose "Installing packages: ${pkgs[*]}"
  case "$PLATFORM_FAMILY" in
    debian)
      if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run]apt-get install -y ${pkgs[*]}"
      else
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
      fi
      ;;
    rhel)
      if command -v dnf >/dev/null 2>&1; then
        if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
          log_info "[dry-run] dnf install -y ${pkgs[*]}"
        else
          dnf install -y "${pkgs[@]}"
        fi
      else
        if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
          log_info "[dry-run] yum install -y ${pkgs[*]}"
        else
          yum install -y "${pkgs[@]}"
        fi
      fi
      ;;
    fedora)
      if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
        log_info "[dry-run] dnf install -y ${pkgs[*]}"
      else
        dnf install -y "${pkgs[@]}"
      fi
      ;;
    *)
      log_warn "Unknown package manager for family $PLATFORM_FAMILY"
      ;;
  esac
}

service_enable_start() {
  local svc="$1"
  log_info "Enabling and starting service: $svc"
  if systemctl is-enabled "$svc" >/dev/null 2>&1; then
    :
  else
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
      log_info "[dry-run] systemctl enable $svc"
    else
      systemctl enable "$svc" || true
    fi
  fi
  if systemctl is-active "$svc" >/dev/null 2>&1; then
    :
  else
    if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
      log_info "[dry-run] systemctl start $svc"
    else
      systemctl start "$svc" || true
    fi
  fi
}

detect_platform() {
  log_info "Detecting Linux distribution and version"
  PLATFORM_ID="unknown"
  PLATFORM_VERSION=""
  PLATFORM_FAMILY="unknown"
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    PLATFORM_ID="${ID:-unknown}"
    PLATFORM_VERSION="${VERSION_ID:-}"
  fi
  case "$PLATFORM_ID" in
    debian|ubuntu|raspbian) PLATFORM_FAMILY="debian" ;;
    rhel|centos|almalinux|rocky) PLATFORM_FAMILY="rhel" ;;
    fedora) PLATFORM_FAMILY="fedora" ;;
    *) PLATFORM_FAMILY="unknown" ;;
  esac
}

init_runtime() {
  log_info "Initializing hardening environment"
  log_setup
  RUN_STAMP="$(date +%Y%m%d-%H%M%S)"
  log_info "Creating backup directory for this session"
  mkdir -p "$HARDEN_BACKUP_DIR_BASE/$RUN_STAMP"
  log_info "Backup directory created: $HARDEN_BACKUP_DIR_BASE/$RUN_STAMP"
}

sysctl_apply() {
  local key="$1" value="$2"
  log_info "Applying kernel parameter: $key = $value"
  if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
    log_info "[dry-run] sysctl -w $key=$value and persist in /etc/sysctl.d/99-harden.conf"
    return 0
  fi
  backup_file /etc/sysctl.conf
  mkdir -p /etc/sysctl.d
  apply_line /etc/sysctl.d/99-harden.conf "${key//./\\.}\s*=" "$key = $value"
  sysctl -w "$key=$value" || true
}

sed_comment_out() {
  local file="$1" pattern="$2"
  if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
    log_info "[dry-run] Comment out matching '$pattern' in $file"
    return 0
  fi
  backup_file "$file"
  sed -ri "/$pattern/ s/^/# /" "$file" 2>/dev/null || true
}

ensure_sshd_conf() {
  local key="$1" value="$2"
  local file="/etc/ssh/sshd_config"
  if [[ "${HARDEN_DRY_RUN:-false}" == "true" ]]; then
    log_info "Setting SSH configuration: $key = $value"
    return 0
  fi
  log_info "Setting SSH configuration: $key = $value"
  mkdir -p /etc/ssh
  apply_line "$file" "${key//\//\/}" "$key $value"
}


