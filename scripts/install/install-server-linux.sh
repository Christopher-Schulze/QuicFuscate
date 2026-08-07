#!/usr/bin/env bash
# Description: Install QuicFuscate server on Linux (binary, assets, config, systemd).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-server-linux.sh --cert PATH --key PATH [--binary PATH | --build] [options]

QuicFuscate Linux server installer (systemd + FHS layout).

This script installs:
- quicfuscate binary -> /usr/local/bin/quicfuscate
- admin web assets   -> /usr/share/quicfuscate/admin-web
- config             -> /etc/quicfuscate/quicfuscate.toml (created if missing)
- env file           -> /etc/quicfuscate/quicfuscate.env (created if missing)
- qkey registry key  -> /etc/quicfuscate/qkey-registry.key (created if no key source exists)
- qkey registry      -> /var/lib/quicfuscate/qkeys.json
- systemd unit       -> /etc/systemd/system/quicfuscate.service

Required:
  --cert PATH         TLS certificate (PEM)
  --key PATH          TLS private key (PEM)

Optional:
  --binary PATH       Prebuilt quicfuscate binary to install (recommended)
  --build             Build quicfuscate from source (requires Rust toolchain)
  --assets PATH       Source admin web assets directory (default: ./assets/web-admin)
  --config PATH       Config destination (default: /etc/quicfuscate/quicfuscate.toml)
  --listen ADDR       QUIC listen addr (default: 0.0.0.0:4433)
  --admin-web ADDR    Admin web bind (default: 127.0.0.1:9000)
  --admin-user USER   Admin username (default: admin)
  --admin-password PW Admin password (default: random)
  --qkey-ttl SECS     Default QKey TTL seconds (default: 0, disables expiration)
  --no-start          Do not start/enable the service

Example:
  sudo ./scripts/install/install-server-linux.sh \
    --binary ./target/release/quicfuscate \
    --cert /etc/letsencrypt/live/example/fullchain.pem \
    --key  /etc/letsencrypt/live/example/privkey.pem
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_root() {
  if [[ "${EUID:-$(id -u)}" != "0" ]]; then
    echo "error: must run as root" >&2
    exit 1
  fi
}

# Emit exactly PASSWORD_LENGTH characters from PASSWORD_ALPHABET, or fail with a diagnostic.
#
# The previous fallback piped `tr -dc` into `head -c 24` under `set -o pipefail`. `head` closes the
# pipe once it has its bytes, so `tr` takes SIGPIPE and the pipeline fails, aborting an install
# whose only defect was a missing OpenSSL. `tr` character classes are also locale sensitive, so a
# non-C locale could reject bytes or admit unexpected ones.
#
# This reads a bounded amount of entropy directly, maps each byte into the alphabet with shell
# arithmetic, and never depends on a pipeline exit status or on the active locale.
PASSWORD_LENGTH=24
PASSWORD_ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

random_password() {
  if need_cmd openssl; then
    local generated
    generated="$(openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-"$PASSWORD_LENGTH")"
    if [[ ${#generated} -eq $PASSWORD_LENGTH ]]; then
      printf '%s' "$generated"
      return 0
    fi
    echo "warning: openssl produced ${#generated} usable characters; using /dev/urandom" >&2
  fi

  if [[ ! -r /dev/urandom ]]; then
    echo "error: cannot generate an administrator password: /dev/urandom is unreadable" >&2
    return 1
  fi

  local alphabet_len=${#PASSWORD_ALPHABET}
  # Reject bytes at or above the largest multiple of the alphabet size so every character is
  # equally likely; without that the low indices would be slightly favoured.
  local ceiling=$(( 256 - (256 % alphabet_len) ))
  local password=""
  local attempts=0
  local max_attempts=$(( PASSWORD_LENGTH * 64 ))

  while [[ ${#password} -lt $PASSWORD_LENGTH ]]; do
    attempts=$(( attempts + 1 ))
    if [[ $attempts -gt $max_attempts ]]; then
      echo "error: exhausted entropy attempts while generating an administrator password" >&2
      return 1
    fi
    local octal
    # LC_ALL=C keeps od's numeric output locale independent.
    octal="$(LC_ALL=C od -An -N1 -tu1 /dev/urandom 2>/dev/null | tr -d ' \n')"
    if [[ -z "$octal" ]]; then
      echo "error: short read from /dev/urandom while generating an administrator password" >&2
      return 1
    fi
    if [[ $octal -ge $ceiling ]]; then
      continue
    fi
    local index=$(( octal % alphabet_len ))
    password+="${PASSWORD_ALPHABET:index:1}"
  done

  printf '%s' "$password"
}

# Serialize a value for a systemd EnvironmentFile assignment.
#
# systemd accepts a double-quoted value with backslash escapes. A literal line break cannot be
# represented at all: it would terminate the assignment and the remainder would be parsed as a new
# key, so hostile or merely surprising input could change which paths and arguments the unit
# starts with. Reject those rather than writing something that parses differently from what the
# installer reported.
systemd_env_value() {
  local name="$1" value="$2"
  case "$value" in
    *$'\n'*|*$'\r'*)
      echo "error: $name contains a line break and cannot be written to an EnvironmentFile" >&2
      return 1
      ;;
  esac
  # Backslash first, so the escape introduced for the quote is not escaped again.
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

ensure_group() {
  local group="$1"
  if getent group "$group" >/dev/null 2>&1; then
    return 0
  fi
  if need_cmd groupadd; then
    groupadd --system "$group"
    return 0
  fi
  if need_cmd addgroup; then
    addgroup --system "$group"
    return 0
  fi
  echo "error: cannot create group '$group' (need groupadd or addgroup)" >&2
  exit 1
}

ensure_user() {
  local user="$1"
  local group="$1"
  if id -u "$user" >/dev/null 2>&1; then
    local prim_group
    prim_group="$(id -gn "$user" 2>/dev/null || true)"
    if [[ -n "$prim_group" && "$prim_group" != "$group" ]]; then
      echo "warn: user '$user' has primary group '$prim_group', expected '$group'" >&2
    fi
    return 0
  fi
  if need_cmd useradd; then
    useradd --system \
            --gid "$group" \
            --home-dir /var/lib/quicfuscate \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$user"
    return 0
  fi
  if need_cmd adduser; then
    adduser --system \
            --group "$group" \
            --no-create-home \
            --home /var/lib/quicfuscate \
            --shell /usr/sbin/nologin \
            --disabled-password \
            "$user"
    return 0
  fi
  echo "error: cannot create user '$user' (need useradd or adduser)" >&2
  exit 1
}

validate_prerequisites() {
  local no_start="$1"
  local missing=()
  if ! need_cmd iptables; then missing+=("iptables"); fi
  if ! need_cmd ip;       then missing+=("iproute2 (ip)"); fi
  for command_name in cat chmod chown cp cut dd dirname find getent grep head id install mkdir sleep tr; do
    if ! need_cmd "$command_name"; then missing+=("$command_name"); fi
  done
  if [[ "$no_start" != "1" ]] && ! need_cmd systemctl; then
    missing+=("systemctl")
  fi
  if [[ "$no_start" != "1" ]] && ! need_cmd journalctl; then
    missing+=("journalctl")
  fi
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "error: missing prerequisites:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    echo "hint: on Debian/Ubuntu: apt-get install iptables iproute2 systemd" >&2
    echo "hint: on RHEL/Fedora:   dnf install iptables iproute systemd" >&2
    exit 1
  fi
}

validate_account_state() {
  local user="$1"
  local group="$2"

  if ! getent group "$group" >/dev/null 2>&1 \
    && ! need_cmd groupadd \
    && ! need_cmd addgroup; then
    echo "error: cannot create group '$group' (need groupadd or addgroup)" >&2
    exit 1
  fi

  if ! id -u "$user" >/dev/null 2>&1; then
    if ! need_cmd useradd && ! need_cmd adduser; then
      echo "error: cannot create user '$user' (need useradd or adduser)" >&2
      exit 1
    fi
    return 0
  fi

  local primary_group
  primary_group="$(id -gn "$user" 2>/dev/null || true)"
  if [[ "$primary_group" != "$group" ]]; then
    echo "error: user '$user' has primary group '$primary_group', expected '$group'" >&2
    exit 1
  fi
}

validate_existing_qkey_state() {
  local env_path="$1"
  local key_path="$2"

  if [[ -f "$env_path" ]] \
    && grep -Eq '^[[:space:]]*QUICFUSCATE_QKEY_ENC_KEY=' "$env_path" \
    && grep -Eq '^[[:space:]]*QUICFUSCATE_QKEY_ENC_KEY_FILE=' "$env_path"; then
    echo "error: env file configures conflicting QKey registry key sources" >&2
    exit 1
  fi
  if [[ -L "$key_path" ]]; then
    echo "error: refusing symlink QKey registry key file: $key_path" >&2
    exit 1
  fi
  if [[ -e "$key_path" && ! -f "$key_path" ]]; then
    echo "error: QKey registry key path is not a regular file: $key_path" >&2
    exit 1
  fi
}

validate_toml_if_supported() {
  local config_path="$1"
  if need_cmd python3 \
    && python3 -c 'import tomllib' >/dev/null 2>&1 \
    && ! python3 -c \
      'import sys,tomllib; tomllib.load(open(sys.argv[1],"rb"))' \
      "$config_path" >/dev/null 2>&1; then
    echo "error: config is not valid TOML: $config_path" >&2
    exit 1
  fi
}

copy_tree() {
  local src="$1"
  local dst="$2"
  mkdir -p "$dst"
  cp -a "$src/." "$dst/"
}

main() {
  local script_path="${BASH_SOURCE[0]}"
  local script_dir
  if [[ "$script_path" == */* ]]; then
    script_dir="$(cd "${script_path%/*}" && pwd)"
  else
    script_dir="$(pwd)"
  fi

  local binary=""
  local build="0"
  local assets=""
  local cert=""
  local key=""
  local listen="0.0.0.0:4433"
  local admin_web="127.0.0.1:9000"
  local admin_user="admin"
  local admin_password=""
  local qkey_ttl="0"
  local no_start="0"

  local config_dst="/etc/quicfuscate/quicfuscate.toml"
  local env_dst="/etc/quicfuscate/quicfuscate.env"
  local admin_credentials_dst="/etc/quicfuscate/admin-credentials"
  local web_dst="/usr/share/quicfuscate/admin-web"
  local state_dir="/var/lib/quicfuscate"
  local qkey_store="/var/lib/quicfuscate/qkeys.json"
  local qkey_key_file="/etc/quicfuscate/qkey-registry.key"
  local unit_dst="/etc/systemd/system/quicfuscate.service"
  local template=""
  local unit_template=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --binary) binary="${2:-}"; shift 2 ;;
      --build) build="1"; shift ;;
      --assets) assets="${2:-}"; shift 2 ;;
      --cert) cert="${2:-}"; shift 2 ;;
      --key) key="${2:-}"; shift 2 ;;
      --config) config_dst="${2:-}"; shift 2 ;;
      --listen) listen="${2:-}"; shift 2 ;;
      --admin-web) admin_web="${2:-}"; shift 2 ;;
      --admin-user) admin_user="${2:-}"; shift 2 ;;
      --admin-password) admin_password="${2:-}"; shift 2 ;;
      --qkey-ttl) qkey_ttl="${2:-}"; shift 2 ;;
      --no-start) no_start="1"; shift ;;
      *) echo "error: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
  done

  require_root
  validate_prerequisites "$no_start"

  # Bundle-friendly defaults:
  # - If invoked from an extracted bundle, the typical layout is:
  #   ops/install-server-linux.sh
  #   ../bin/quicfuscate
  #   ../share/admin-web
  if [[ -z "$assets" ]]; then
    for candidate in \
      "${script_dir}/../share/admin-web" \
      "./share/admin-web" \
      "./assets/web-admin"
    do
      if [[ -f "$candidate/index.html" ]]; then
        assets="$candidate"
        break
      fi
    done
    [[ -n "$assets" ]] || assets="./assets/web-admin"
  fi

  if [[ -z "$binary" && "$build" != "1" ]]; then
    for candidate in \
      "${script_dir}/../bin/quicfuscate" \
      "./bin/quicfuscate" \
      "./target/release/quicfuscate"
    do
      if [[ -f "$candidate" ]]; then
        binary="$candidate"
        break
      fi
    done
  fi

  if [[ -z "$cert" || -z "$key" ]]; then
    echo "error: --cert and --key are required" >&2
    usage
    exit 1
  fi
  if [[ ! -f "$cert" ]]; then echo "error: cert not found: $cert" >&2; exit 1; fi
  if [[ ! -f "$key" ]]; then echo "error: key not found: $key" >&2; exit 1; fi

  if [[ -z "$binary" && "$build" != "1" ]]; then
    echo "error: provide --binary PATH (recommended) or use --build" >&2
    usage
    exit 1
  fi

  if [[ ! -f "$config_dst" ]]; then
    for candidate in \
      "${script_dir}/server-linux.default.toml" \
      "${script_dir}/../config/server-linux.default.toml" \
      "./config/server-linux.default.toml"
    do
      if [[ -f "$candidate" ]]; then
        template="$candidate"
        break
      fi
    done
    if [[ -z "$template" ]]; then
      echo "error: missing server config template (server-linux.default.toml)" >&2
      echo "hint: expected near installer script, or at ./config/server-linux.default.toml" >&2
      exit 1
    fi
  fi

  for candidate in \
    "${script_dir}/quicfuscate-server.service" \
    "${script_dir}/../install/quicfuscate-server.service" \
    "./scripts/install/quicfuscate-server.service"
  do
    if [[ -f "$candidate" ]]; then
      unit_template="$candidate"
      break
    fi
  done
  if [[ -z "$unit_template" ]]; then
    echo "error: missing unit template (quicfuscate-server.service)" >&2
    echo "hint: expected near installer script, or at ./scripts/install/quicfuscate-server.service" >&2
    exit 1
  fi

  if [[ ! -d "$(dirname "$unit_dst")" ]]; then
    echo "error: systemd unit directory is missing: $(dirname "$unit_dst")" >&2
    exit 1
  fi
  if [[ ! -f "$assets/index.html" ]]; then
    echo "error: admin web assets missing: $assets/index.html" >&2
    echo "hint: run ./scripts/build/build-web-admin.sh first, or pass --assets PATH" >&2
    exit 1
  fi
  validate_account_state "quicfuscate" "quicfuscate"
  validate_existing_qkey_state "$env_dst" "$qkey_key_file"
  if [[ -f "$config_dst" ]]; then
    validate_toml_if_supported "$config_dst"
  else
    validate_toml_if_supported "$template"
  fi

  if [[ "$build" == "1" ]]; then
    if ! need_cmd cargo; then
      echo "error: --build requires cargo (Rust toolchain)" >&2
      exit 1
    fi
    (cd "$(pwd)" && cargo build --release --bin quicfuscate)
    binary="./target/release/quicfuscate"
  fi

  if [[ ! -f "$binary" ]]; then
    echo "error: binary not found: $binary" >&2
    exit 1
  fi

  ensure_group "quicfuscate"
  ensure_user  "quicfuscate"

  local log_dir="/var/log/quicfuscate"
  mkdir -p /etc/quicfuscate "$state_dir" "$log_dir" /usr/share/quicfuscate

  # Shared bootstrap/runtime state: root initializes it, then the daemon owns
  # atomic updates after dropping to the dedicated quicfuscate group.
  chown root:quicfuscate "$state_dir"
  chmod 0770 "$state_dir"

  # Config dir: the daemon atomically persists admin auth and panel edits here.
  chown root:quicfuscate /etc/quicfuscate
  chmod 0770 /etc/quicfuscate

  # Log dir: server writes audit + runtime logs here.
  chown quicfuscate:quicfuscate "$log_dir"
  chmod 0750 "$log_dir"

  install -m 0755 "$binary" /usr/local/bin/quicfuscate

  mkdir -p "$web_dst"
  copy_tree "$assets" "$web_dst"

  if [[ ! -f "$config_dst" ]]; then
    install -m 0640 "$template" "$config_dst"
    chown root:quicfuscate "$config_dst" || true
  fi

  if [[ -z "$admin_password" ]]; then
    admin_password="$(random_password)"
  fi

  local qkey_key_source_configured="0"
  if [[ -f "$env_dst" ]]; then
    if grep -Eq '^[[:space:]]*QUICFUSCATE_QKEY_ENC_(KEY|KEY_FILE)=' "$env_dst"; then
      qkey_key_source_configured="1"
    fi
  fi

  if [[ "$qkey_key_source_configured" == "0" ]]; then
    if [[ ! -e "$qkey_key_file" ]]; then
      umask 0077
      dd if=/dev/urandom of="$qkey_key_file" bs=32 count=1 status=none
    fi
    chown root:quicfuscate "$qkey_key_file"
    chmod 0640 "$qkey_key_file"
  fi

  if [[ ! -f "$env_dst" ]]; then
    # Restrict before any secret reaches the file, not after.
    ( umask 0177; : >"$env_dst" )
    chmod 0640 "$env_dst"
    chown root:quicfuscate "$env_dst"

    {
      printf '# QuicFuscate service environment.\n'
      printf '# This file contains admin credentials. Keep permissions tight.\n\n'
      printf 'QUICFUSCATE_LISTEN=%s\n' "$(systemd_env_value QUICFUSCATE_LISTEN "$listen")"
      printf 'QUICFUSCATE_CERT=%s\n' "$(systemd_env_value QUICFUSCATE_CERT "$cert")"
      printf 'QUICFUSCATE_KEY=%s\n' "$(systemd_env_value QUICFUSCATE_KEY "$key")"
      printf 'QUICFUSCATE_CONFIG=%s\n' "$(systemd_env_value QUICFUSCATE_CONFIG "$config_dst")"
      printf 'QUICFUSCATE_ADMIN_WEB=%s\n' "$(systemd_env_value QUICFUSCATE_ADMIN_WEB "$admin_web")"
      printf 'QUICFUSCATE_ADMIN_WEB_ROOT=%s\n' \
        "$(systemd_env_value QUICFUSCATE_ADMIN_WEB_ROOT "$web_dst")"
      printf 'QUICFUSCATE_ADMIN_USER=%s\n' \
        "$(systemd_env_value QUICFUSCATE_ADMIN_USER "$admin_user")"
      printf 'QUICFUSCATE_ADMIN_PASSWORD=%s\n' \
        "$(systemd_env_value QUICFUSCATE_ADMIN_PASSWORD "$admin_password")"
      printf 'QUICFUSCATE_QKEY_STORE=%s\n' \
        "$(systemd_env_value QUICFUSCATE_QKEY_STORE "$qkey_store")"
      printf 'QUICFUSCATE_QKEY_TTL_SECS=%s\n' \
        "$(systemd_env_value QUICFUSCATE_QKEY_TTL_SECS "$qkey_ttl")"
      printf 'QUICFUSCATE_QKEY_ENC_KEY_FILE=%s\n' \
        "$(systemd_env_value QUICFUSCATE_QKEY_ENC_KEY_FILE "$qkey_key_file")"
    } >"$env_dst"

    # Credential handoff is a root-only file, never terminal output. Printing the password left it
    # in scrollback, install logs, and CI artifacts, which contradicts the documented contract that
    # secrets must not appear in logs.
    ( umask 0177; : >"$admin_credentials_dst" )
    chmod 0600 "$admin_credentials_dst"
    chown root:root "$admin_credentials_dst"
    {
      printf '# QuicFuscate administrator credentials.\n'
      printf '# Read once, store in your password manager, then delete this file.\n'
      printf 'user=%s\n' "$admin_user"
      printf 'password=%s\n' "$admin_password"
    } >"$admin_credentials_dst"
    echo "admin credentials written to $admin_credentials_dst (mode 0600, root only)"
    echo "read them once, store them securely, then remove that file"
  else
    echo "info: env file exists, not overwriting: $env_dst"
    if [[ "$qkey_key_source_configured" == "0" ]]; then
      printf '\n# Authenticated QKey registry encryption key.\nQUICFUSCATE_QKEY_ENC_KEY_FILE=%s\n' \
        "$qkey_key_file" >>"$env_dst"
    fi
  fi

  if [[ ! -f "$qkey_store" ]]; then
    mkdir -p "$(dirname "$qkey_store")"
    printf "[]\n" >"$qkey_store"
    chown root:quicfuscate "$qkey_store"
    chmod 0640 "$qkey_store"
  fi

  install -m 0644 "$unit_template" "$unit_dst"

  if need_cmd systemctl; then
    systemctl daemon-reload
    if [[ "$no_start" != "1" ]]; then
      if ! systemctl enable --now quicfuscate.service; then
        echo "error: quicfuscate.service failed to start" >&2
        systemctl status --no-pager quicfuscate.service || true
        journalctl -u quicfuscate.service -n 50 --no-pager || true
        exit 1
      fi
      sleep 1
      if ! systemctl is-active --quiet quicfuscate.service; then
        echo "error: quicfuscate.service failed to start" >&2
        systemctl status --no-pager quicfuscate.service || true
        journalctl -u quicfuscate.service -n 50 --no-pager || true
        exit 1
      fi
      echo "quicfuscate.service is active."
    else
      echo "info: service installed but not started (--no-start)"
    fi
  else
    echo "warn: systemctl not found; unit installed at $unit_dst" >&2
  fi
}

main "$@"
