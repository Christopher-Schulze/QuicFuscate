#!/usr/bin/env bash
# Description: Native disposable Debian and AlmaLinux installer lifecycle proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

OUTPUT_DIR=""
TOOL_VERSIONS_FILE="$PROJECT_ROOT/config/tool-versions.env"
if [[ ! -f "$TOOL_VERSIONS_FILE" ]]; then
  echo "FAIL: missing tool-version owner: $TOOL_VERSIONS_FILE" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$TOOL_VERSIONS_FILE"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-1.97.1}"
ASSETS_DIR="$PROJECT_ROOT/assets/web-admin"
PREBUILT_BINARY=""
ARTIFACT_ORIGIN="almalinux-9-build"
WORK_ROOT=""
ACTIVE_MACHINE=""
ACTIVE_NSPAWN_PID=""
OWNED_MACHINES=()
ALMA_KEY_FINGERPRINT="BF18AC2876178908D6E71267D36CB86CB86B3716"

usage() {
  cat <<'EOF'
Usage: test-linux-installer.sh --output-dir PATH [options]

Builds the release server on AlmaLinux 9, then reuses that exact artifact in
booted AlmaLinux 9 and Debian 12 systemd-nspawn guests. The output directory
must not exist. Docker and redirected production paths are not used.

Options:
  --assets PATH             Real prebuilt admin-web publish tree
  --prebuilt-binary PATH    Reuse a prior AlmaLinux-built diagnostic artifact
  --rust-toolchain VERSION  Exact stable Rust version (default: 1.97.1)
EOF
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

delete_generated_tree() {
  local path="$1"
  local allowed_prefix="$2"
  case "$path" in
    "$allowed_prefix"*)
      sudo -n find "$path" -xdev -depth -delete 2>/dev/null || true
      ;;
    *)
      fail "refusing generated-tree cleanup outside $allowed_prefix: $path"
      ;;
  esac
}

stop_active_machine() {
  if [[ -z "$ACTIVE_MACHINE" ]]; then
    return 0
  fi

  sudo -n machinectl poweroff "$ACTIVE_MACHINE" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! sudo -n machinectl show "$ACTIVE_MACHINE" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  sudo -n machinectl terminate "$ACTIVE_MACHINE" >/dev/null 2>&1 || true
  if [[ -n "$ACTIVE_NSPAWN_PID" ]]; then
    wait "$ACTIVE_NSPAWN_PID" 2>/dev/null || true
  fi
  ACTIVE_MACHINE=""
  ACTIVE_NSPAWN_PID=""
}

cleanup() {
  local status=$?
  trap - EXIT
  stop_active_machine || true
  if [[ -n "$WORK_ROOT" ]]; then
    delete_generated_tree "$WORK_ROOT" "/tmp/qf-todo541-linux-installer."
  fi
  exit "$status"
}
trap cleanup EXIT

require_host() {
  [[ "$(uname -s)" == "Linux" ]] || fail "native installer proof requires Linux"
  [[ "${EUID:-$(id -u)}" != "0" ]] \
    || fail "run as an unprivileged user with passwordless sudo"
  sudo -n true || fail "passwordless sudo is required"
  [[ "$(ps -p 1 -o comm= | tr -d ' ')" == "systemd" ]] \
    || fail "host PID 1 must be systemd"
  [[ -c /dev/net/tun ]] || fail "host lacks /dev/net/tun"

  local command_name
  for command_name in \
    awk bash chroot cp curl debootstrap df dirname dnf du find getent gpg grep \
    machinectl mkdir ps realpath rpm seq sha256sum shellcheck sort \
    systemd-machine-id-setup systemd-nspawn systemd-run tail tar tee tr uname
  do
    need_cmd "$command_name" || fail "host prerequisite missing: $command_name"
  done
  [[ -r /usr/share/keyrings/debian-archive-keyring.gpg ]] \
    || fail "Debian archive keyring is missing"
}

resolve_architecture() {
  case "$(uname -m)" in
    x86_64)
      RPM_ARCH="x86_64"
      DEBIAN_ARCH="amd64"
      RUST_HOST="x86_64-unknown-linux-gnu"
      ;;
    aarch64|arm64)
      RPM_ARCH="aarch64"
      DEBIAN_ARCH="arm64"
      RUST_HOST="aarch64-unknown-linux-gnu"
      ;;
    *)
      fail "unsupported native architecture: $(uname -m)"
      ;;
  esac
}

verify_capacity() {
  local available_bytes
  available_bytes="$(df --output=avail -B1 / | awk 'NR == 2 {print $1}')"
  [[ "$available_bytes" =~ ^[0-9]+$ ]] || fail "cannot determine free disk space"
  if (( available_bytes < 8589934592 )); then
    fail "need at least 8 GiB free for two root filesystems and one bounded release build"
  fi
  df -h /
}

run_static_checks() {
  local bundle_builder="$PROJECT_ROOT/scripts/build/build-server-bundle.sh"
  local installer="$PROJECT_ROOT/scripts/install/install-server-linux.sh"
  local guest_suite="$PROJECT_ROOT/scripts/tests/suites/test-linux-installer-guest.sh"
  local host_suite="$PROJECT_ROOT/scripts/tests/suites/test-linux-installer.sh"

  bash -n "$bundle_builder"
  bash -n "$installer"
  bash -n "$guest_suite"
  bash -n "$host_suite"
  shellcheck -S warning "$bundle_builder" "$installer" "$guest_suite" "$host_suite"
  verify_random_password_contract "$installer"
  verify_systemd_env_serialization "$installer"
  verify_installer_never_prints_credentials "$installer"
  verify_unit_quotes_expansions "$PROJECT_ROOT/scripts/install/quicfuscate-server.service"
  printf 'bash_syntax=PASS\nshellcheck_warning=PASS\nrandom_password_contract=PASS\nsystemd_env_serialization=PASS\ncredential_output=PASS\nunit_quoted_expansions=PASS\n' \
    >"$OUTPUT_DIR/static-checks.txt"
}

# Prove that every value written into the systemd EnvironmentFile round-trips exactly.
#
# The installer previously wrote raw values through a here-document, so whitespace, quotes,
# backslashes, or a line break could change parsing and start the unit with different paths and
# arguments than the installer reported.
verify_systemd_env_serialization() {
  local installer="$1"
  local harness="$OUTPUT_DIR/systemd-env-harness.sh"

  {
    printf 'set -euo pipefail\n'
    sed -n '/^systemd_env_value() {/,/^}$/p' "$installer"
    cat <<'HARNESS'

# Decode a double-quoted systemd environment value the way systemd does: backslash escapes one
# character, and the surrounding quotes are removed.
decode() {
  local raw="$1" out="" i=0 ch
  raw="${raw#\"}"
  raw="${raw%\"}"
  while (( i < ${#raw} )); do
    ch="${raw:i:1}"
    if [[ "$ch" == "\\" ]]; then
      i=$(( i + 1 ))
      out+="${raw:i:1}"
    else
      out+="$ch"
    fi
    i=$(( i + 1 ))
  done
  printf '%s' "$out"
}

roundtrip() {
  local label="$1" value="$2" encoded decoded
  encoded="$(systemd_env_value "$label" "$value")"
  decoded="$(decode "$encoded")"
  if [[ "$decoded" != "$value" ]]; then
    echo "error: $label did not round-trip: [$value] -> $encoded -> [$decoded]" >&2
    exit 1
  fi
}

roundtrip PLAIN 'simple'
roundtrip SPACES '/etc/quic fuscate/server.crt'
roundtrip QUOTES 'pa"ss'
roundtrip BACKSLASH 'pa\ss'
roundtrip BOTH 'a\"b'
roundtrip DOLLAR 'p$w0rd'
roundtrip SEMICOLON 'a;b c'
roundtrip TICK 'a`b'

# A line break cannot be represented and must be rejected, not silently written.
if systemd_env_value NEWLINE "$(printf 'a\nb')" >/dev/null 2>&1; then
  echo "error: a value containing a newline must be rejected" >&2
  exit 1
fi
if systemd_env_value CARRIAGE "$(printf 'a\rb')" >/dev/null 2>&1; then
  echo "error: a value containing a carriage return must be rejected" >&2
  exit 1
fi
echo "systemd_env_serialization=PASS"
HARNESS
  } >"$harness"

  bash "$harness" >"$OUTPUT_DIR/systemd-env.txt"
}

# Unquoted ${VAR} in ExecStart is split on whitespace by systemd, so a value containing a space
# would become two arguments and the unit would start with arguments the installer never reported.
verify_unit_quotes_expansions() {
  local unit="$1"
  local unquoted
  unquoted="$(grep -nE '^[[:space:]]*--[a-z-]+ \$\{[A-Z_]+\}' "$unit" || true)"
  if [[ -n "$unquoted" ]]; then
    echo "error: systemd unit expands variables unquoted in ExecStart:" >&2
    echo "$unquoted" >&2
    return 1
  fi
  printf 'unit_quoted_expansions=PASS\n' >"$OUTPUT_DIR/unit-expansions.txt"
}

# The installer must never echo a credential. docs/DOCUMENTATION.md states secrets must not appear
# in logs, and terminal output lands in scrollback, install logs, and CI artifacts.
verify_installer_never_prints_credentials() {
  local installer="$1"
  if grep -nE '^[[:space:]]*echo .*\$\{?admin_password' "$installer"; then
    echo "error: installer echoes the administrator password" >&2
    return 1
  fi
  if grep -nE '^[[:space:]]*(echo|printf) .*(pass:|password:)[^=]*\$' "$installer"; then
    echo "error: installer prints a credential value" >&2
    return 1
  fi
  printf 'credential_output=PASS\n' >"$OUTPUT_DIR/credential-output.txt"
}

# Exercise the installer's password generator directly, on the host, without installing anything.
#
# The fallback runs on systems without OpenSSL during a privileged install, so a failure there
# leaves the service unconfigured. It must produce exactly the documented length and alphabet under
# `pipefail` and under a non-C locale, and it must do so repeatedly.
verify_random_password_contract() {
  local installer="$1"
  local harness="$OUTPUT_DIR/random-password-harness.sh"

  {
    printf 'set -euo pipefail\n'
    printf 'need_cmd() { command -v "$1" >/dev/null 2>&1; }\n'
    sed -n '/^PASSWORD_LENGTH=/,/^}$/p' "$installer"
    cat <<'HARNESS'

expect_password() {
  local label="$1" value="$2"
  if [[ ${#value} -ne $PASSWORD_LENGTH ]]; then
    echo "error: $label produced ${#value} characters, expected $PASSWORD_LENGTH" >&2
    exit 1
  fi
  case "$value" in
    *[!A-Za-z0-9]*)
      echo "error: $label produced a character outside the documented alphabet" >&2
      exit 1
      ;;
  esac
}

# OpenSSL path, when the host has it.
if command -v openssl >/dev/null 2>&1; then
  expect_password "openssl path" "$(random_password)"
fi

# Fallback path: hide OpenSSL and force a non-C locale.
need_cmd() { return 1; }
export LC_ALL=de_DE.UTF-8
for _ in 1 2 3 4 5; do
  expect_password "urandom fallback" "$(random_password)"
done

# Distribution sanity: repeated generation must span most of the alphabet rather than a few bytes.
sample=""
for _ in $(seq 1 84); do sample+="$(random_password)"; done
distinct="$(printf '%s' "$sample" | fold -w1 | sort -u | wc -l | tr -d ' ')"
if [[ "$distinct" -lt 55 ]]; then
  echo "error: fallback covered only $distinct of 62 alphabet characters" >&2
  exit 1
fi
echo "random_password_contract=PASS distinct=$distinct"
HARNESS
  } >"$harness"

  bash "$harness" >"$OUTPUT_DIR/random-password.txt"
}

verify_alma_key() {
  local key_path="$1"
  local gnupg_home="$2"
  local fingerprint

  mkdir "$gnupg_home"
  chmod 0700 "$gnupg_home"
  curl --fail --location --silent --show-error \
    https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9 \
    --output "$key_path"
  fingerprint="$(
    GNUPGHOME="$gnupg_home" \
      gpg --batch --with-colons --import-options show-only --import "$key_path" \
      2>/dev/null \
      | while IFS=: read -r record _ _ _ _ _ _ _ _ value _; do
          if [[ "$record" == "fpr" ]]; then
            printf '%s\n' "$value"
            break
          fi
        done
  )"
  [[ "$fingerprint" == "$ALMA_KEY_FINGERPRINT" ]] \
    || fail "unexpected AlmaLinux 9 key fingerprint: $fingerprint"
  printf '%s\n' "$fingerprint" >"$OUTPUT_DIR/almalinux-key-fingerprint.txt"
  sha256sum "$key_path" >"$OUTPUT_DIR/almalinux-key.sha256"
}

alma_dnf() {
  local install_root="$1"
  shift
  sudo -n dnf -q -y \
    --installroot "$install_root" \
    --releasever 9 \
    --forcearch "$RPM_ARCH" \
    --setopt=reposdir=/dev/null \
    --setopt=install_weak_deps=False \
    --setopt=keepcache=False \
    --repofrompath \
      "alma-baseos,https://repo.almalinux.org/almalinux/9/BaseOS/${RPM_ARCH}/os/" \
    --repofrompath \
      "alma-appstream,https://repo.almalinux.org/almalinux/9/AppStream/${RPM_ARCH}/os/" \
    --repo alma-baseos \
    --repo alma-appstream \
    --setopt=alma-baseos.gpgcheck=1 \
    --setopt=alma-baseos.repo_gpgcheck=0 \
    --setopt="alma-baseos.gpgkey=file://${ALMA_KEY_PATH}" \
    --setopt=alma-appstream.gpgcheck=1 \
    --setopt=alma-appstream.repo_gpgcheck=0 \
    --setopt="alma-appstream.gpgkey=file://${ALMA_KEY_PATH}" \
    "$@"
}

bootstrap_alma_runtime() {
  local rootfs="$1"
  mkdir "$rootfs"
  alma_dnf "$rootfs" install \
    almalinux-release systemd dbus iproute iptables openssl python3 \
    shadow-utils coreutils findutils grep gawk util-linux procps-ng \
    ca-certificates
  sudo -n systemd-machine-id-setup --root="$rootfs" >/dev/null
  sudo -n rpm --root "$rootfs" -qa \
    --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    | sort >"$OUTPUT_DIR/almalinux-9-packages.txt"
}

bootstrap_debian_runtime() {
  local rootfs="$1"
  mkdir "$rootfs"
  sudo -n debootstrap \
    --arch="$DEBIAN_ARCH" \
    --variant=minbase \
    --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
    --include=systemd,systemd-sysv,dbus,iproute2,iptables,openssl,python3,passwd,procps,ca-certificates,gawk,util-linux \
    bookworm "$rootfs" https://deb.debian.org/debian
  sudo -n systemd-machine-id-setup --root="$rootfs" >/dev/null
  sudo -n chroot "$rootfs" dpkg-query -W \
    -f='${binary:Package} ${Version}\n' \
    | sort >"$OUTPUT_DIR/debian-12-packages.txt"
}

prepare_alma_build_root() {
  local runtime_root="$1"
  local build_root="$2"
  mkdir "$build_root"
  sudo -n cp -a "$runtime_root/." "$build_root/"
  alma_dnf "$build_root" install \
    gcc gcc-c++ make cmake perl pkgconf-pkg-config git clang
}

install_verified_rust_toolchain() {
  local build_root="$1"
  local tool_dir="$WORK_ROOT/rustup"
  local rustup_init="$tool_dir/rustup-init"

  mkdir "$tool_dir"
  curl --fail --location --silent --show-error \
    "https://static.rust-lang.org/rustup/dist/${RUST_HOST}/rustup-init" \
    --output "$rustup_init"
  curl --fail --location --silent --show-error \
    "https://static.rust-lang.org/rustup/dist/${RUST_HOST}/rustup-init.sha256" \
    --output "$tool_dir/rustup-init.sha256"
  chmod 0755 "$rustup_init"
  (
    cd "$tool_dir"
    sha256sum --check rustup-init.sha256
  ) >"$OUTPUT_DIR/rustup-init-checksum.txt"
  sha256sum "$rustup_init" >>"$OUTPUT_DIR/rustup-init-checksum.txt"

  sudo -n systemd-nspawn \
    --quiet \
    --directory="$build_root" \
    --register=no \
    --bind-ro="$rustup_init:/tmp/rustup-init" \
    --setenv=RUSTUP_HOME=/opt/rustup \
    --setenv=CARGO_HOME=/opt/cargo \
    /tmp/rustup-init \
      -y \
      --profile minimal \
      --default-toolchain "$RUST_TOOLCHAIN"
}

build_release_artifact() {
  local build_root="$1"
  local target_dir="$WORK_ROOT/cargo-target"
  local target_kib

  mkdir "$target_dir"
  df -h /
  du -sh "$target_dir"
  target_kib="$(du -sk "$target_dir" | awk '{print $1}')"
  if (( target_kib >= 12582912 )); then
    fail "fresh disposable Cargo target unexpectedly exceeds 12 GiB"
  fi

  sudo -n systemd-nspawn \
    --quiet \
    --directory="$build_root" \
    --register=no \
    --bind-ro="$PROJECT_ROOT:/workspace" \
    --bind="$target_dir:/workspace-target" \
    --setenv=RUSTUP_HOME=/opt/rustup \
    --setenv=CARGO_HOME=/opt/cargo \
    --setenv=CARGO_BUILD_JOBS=2 \
    --setenv=CARGO_INCREMENTAL=0 \
    --setenv=RUSTFLAGS=-Dwarnings \
    /opt/cargo/bin/cargo build \
      --manifest-path /workspace/Cargo.toml \
      --target-dir /workspace-target \
      --release \
      --locked \
      --jobs 2 \
      --bin quicfuscate \
    2>&1 | tee "$OUTPUT_DIR/almalinux-release-build.log"

  local built_binary="$target_dir/release/quicfuscate"
  [[ -x "$built_binary" ]] || fail "release binary missing after AlmaLinux build"
  RELEASE_BINARY="$OUTPUT_DIR/quicfuscate-server"
  cp "$built_binary" "$RELEASE_BINARY"
  chmod 0755 "$RELEASE_BINARY"
  sha256sum "$RELEASE_BINARY" >"$OUTPUT_DIR/quicfuscate-server.sha256"
  du -sh "$target_dir" >"$OUTPUT_DIR/cargo-target-size.txt"
}

use_prebuilt_artifact() {
  [[ -x "$PREBUILT_BINARY" ]] \
    || fail "prebuilt binary is missing or not executable: $PREBUILT_BINARY"
  ARTIFACT_ORIGIN="prebuilt-diagnostic"
  RELEASE_BINARY="$OUTPUT_DIR/quicfuscate-server"
  cp "$PREBUILT_BINARY" "$RELEASE_BINARY"
  chmod 0755 "$RELEASE_BINARY"
  sha256sum "$RELEASE_BINARY" >"$OUTPUT_DIR/quicfuscate-server.sha256"
}

record_alma_binary_compatibility() {
  local alma_root="$1"
  {
    sudo -n systemd-nspawn \
      --quiet \
      --directory="$alma_root" \
      --register=no \
      --bind-ro="$RELEASE_BINARY:/tmp/quicfuscate" \
      /usr/bin/ldd /tmp/quicfuscate
  } >"$OUTPUT_DIR/almalinux-build-ldd.txt"
}

build_server_bundle() {
  local bundle_out="$WORK_ROOT/bundle"
  local stage_count

  mkdir "$bundle_out"
  "$PROJECT_ROOT/scripts/build/build-server-bundle.sh" \
    --binary "$RELEASE_BINARY" \
    --assets "$ASSETS_DIR" \
    --out-dir "$bundle_out" \
    --name todo541-linux-installer \
    >"$OUTPUT_DIR/bundle-build.txt"
  mapfile -t bundle_stages < <(
    find "$bundle_out" -mindepth 1 -maxdepth 1 -type d -print
  )
  stage_count="${#bundle_stages[@]}"
  [[ "$stage_count" == "1" ]] \
    || fail "expected one bundle stage, found $stage_count"
  BUNDLE_ROOT="${bundle_stages[0]}"
  BUNDLE_TARBALL="${BUNDLE_ROOT}.tar.gz"
  [[ -f "$BUNDLE_TARBALL" ]] || fail "bundle tarball missing"
  [[ "$(sha256_file "$BUNDLE_ROOT/bin/quicfuscate")" == \
    "$(sha256_file "$RELEASE_BINARY")" ]] \
    || fail "bundle binary differs from AlmaLinux artifact"
  cp "$BUNDLE_TARBALL" "$OUTPUT_DIR/"
  sha256sum "$OUTPUT_DIR/$(basename "$BUNDLE_TARBALL")" \
    >"$OUTPUT_DIR/server-bundle.sha256"
}

wait_for_machine() {
  local machine="$1"
  local state
  for _ in $(seq 1 45); do
    state="$(sudo -n machinectl show "$machine" --property=State --value \
      2>/dev/null || true)"
    if [[ "$state" == "running" ]] \
      && sudo -n systemd-run \
        --machine="$machine" \
        --wait \
        --pipe \
        --quiet \
        --collect \
        /usr/bin/true >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

run_guest_proof() {
  local distro_label="$1"
  local rootfs="$2"
  local evidence_name="$3"
  local machine
  local machine_suffix
  local nspawn_log="$OUTPUT_DIR/${evidence_name}-nspawn.log"

  machine_suffix="$(printf '%s-%s' "$$" "$RANDOM" | tr -cd '0-9-')"
  ACTIVE_MACHINE="qf541-${evidence_name}-${machine_suffix}"
  machine="$ACTIVE_MACHINE"
  OWNED_MACHINES+=("$machine")
  [[ ${#ACTIVE_MACHINE} -le 64 ]] || fail "machine name exceeds 64 characters"
  if sudo -n machinectl show "$ACTIVE_MACHINE" >/dev/null 2>&1; then
    fail "machine name already exists: $ACTIVE_MACHINE"
  fi
  [[ ! -e "$OUTPUT_DIR/$evidence_name" ]] \
    || fail "guest evidence already exists: $evidence_name"

  (
    exec sudo -n systemd-nspawn \
      --quiet \
      --directory="$rootfs" \
      --machine="$ACTIVE_MACHINE" \
      --boot \
      --private-network \
      --register=yes \
      --link-journal=no \
      --console=pipe \
      --capability=CAP_NET_ADMIN,CAP_NET_RAW,CAP_NET_BIND_SERVICE \
      --bind=/dev/net/tun \
      --bind-ro="$BUNDLE_ROOT:/bundle" \
      --bind-ro="$PROJECT_ROOT/scripts/tests/suites/test-linux-installer-guest.sh:/proof/test-linux-installer-guest.sh" \
      --bind="$OUTPUT_DIR:/evidence"
  ) >"$nspawn_log" 2>&1 &
  ACTIVE_NSPAWN_PID=$!

  if ! wait_for_machine "$ACTIVE_MACHINE"; then
    tail -100 "$nspawn_log" >&2
    fail "systemd guest did not become ready: $ACTIVE_MACHINE"
  fi

  sudo -n systemd-run \
    --machine="$ACTIVE_MACHINE" \
    --wait \
    --pipe \
    --quiet \
    --collect \
    /proof/test-linux-installer-guest.sh \
      --bundle-root /bundle \
      --output-dir "/evidence/$evidence_name" \
      --distro-label "$distro_label" \
    2>&1 | tee "$OUTPUT_DIR/${evidence_name}-guest.log"

  if ! stop_active_machine; then
    fail "machine failed to stop: $machine"
  fi
  if sudo -n machinectl show "$machine" >/dev/null 2>&1; then
    fail "machine remains registered after stop: $machine"
  fi
}

verify_cross_distro_artifact() {
  local expected
  local alma_hash
  local debian_hash
  expected="$(sha256_file "$BUNDLE_ROOT/bin/quicfuscate")"
  alma_hash="$(awk -F= '$1 == "binary_sha256" {print $2}' \
    "$OUTPUT_DIR/almalinux-9/summary.txt")"
  debian_hash="$(awk -F= '$1 == "binary_sha256" {print $2}' \
    "$OUTPUT_DIR/debian-12/summary.txt")"
  [[ "$alma_hash" == "$expected" ]] \
    || fail "AlmaLinux installed a different artifact"
  [[ "$debian_hash" == "$expected" ]] \
    || fail "Debian installed a different artifact"
  printf 'bundle_binary_sha256=%s\n' "$expected" \
    >"$OUTPUT_DIR/cross-distro-artifact.txt"
  printf 'almalinux_9_binary_sha256=%s\n' "$alma_hash" \
    >>"$OUTPUT_DIR/cross-distro-artifact.txt"
  printf 'debian_12_binary_sha256=%s\n' "$debian_hash" \
    >>"$OUTPUT_DIR/cross-distro-artifact.txt"
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output-dir)
        OUTPUT_DIR="${2:-}"
        shift 2
        ;;
      --rust-toolchain)
        RUST_TOOLCHAIN="${2:-}"
        shift 2
        ;;
      --assets)
        ASSETS_DIR="${2:-}"
        shift 2
        ;;
      --prebuilt-binary)
        PREBUILT_BINARY="${2:-}"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
  done

  [[ -n "$OUTPUT_DIR" ]] || fail "--output-dir is required"
  [[ ! -e "$OUTPUT_DIR" ]] || fail "output path already exists: $OUTPUT_DIR"
  [[ "$RUST_TOOLCHAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail "Rust toolchain must be an exact stable version"
  [[ -f "$ASSETS_DIR/index.html" ]] \
    || fail "admin-web publish tree is missing index.html: $ASSETS_DIR"
  ASSETS_DIR="$(realpath "$ASSETS_DIR")"
  if [[ -n "$PREBUILT_BINARY" ]]; then
    PREBUILT_BINARY="$(realpath "$PREBUILT_BINARY")"
  fi

  require_host
  resolve_architecture
  verify_capacity
  mkdir -p "$(dirname "$OUTPUT_DIR")"
  mkdir "$OUTPUT_DIR"
  OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"
  run_static_checks
  WORK_ROOT="$(mktemp -d /tmp/qf-todo541-linux-installer.XXXXXX)"
  ALMA_KEY_PATH="$WORK_ROOT/RPM-GPG-KEY-AlmaLinux-9"
  verify_alma_key "$ALMA_KEY_PATH" "$WORK_ROOT/gnupg"

  ALMA_RUNTIME_ROOT="$WORK_ROOT/almalinux-9"
  ALMA_BUILD_ROOT="$WORK_ROOT/almalinux-9-build"
  DEBIAN_RUNTIME_ROOT="$WORK_ROOT/debian-12"
  bootstrap_alma_runtime "$ALMA_RUNTIME_ROOT"
  if [[ -n "$PREBUILT_BINARY" ]]; then
    use_prebuilt_artifact
  else
    prepare_alma_build_root "$ALMA_RUNTIME_ROOT" "$ALMA_BUILD_ROOT"
    install_verified_rust_toolchain "$ALMA_BUILD_ROOT"
    build_release_artifact "$ALMA_BUILD_ROOT"
  fi
  record_alma_binary_compatibility "$ALMA_RUNTIME_ROOT"
  build_server_bundle
  bootstrap_debian_runtime "$DEBIAN_RUNTIME_ROOT"

  run_guest_proof "AlmaLinux 9" "$ALMA_RUNTIME_ROOT" "almalinux-9"
  run_guest_proof "Debian 12" "$DEBIAN_RUNTIME_ROOT" "debian-12"
  verify_cross_distro_artifact

  {
    sudo -n machinectl list --no-legend
  } >"$OUTPUT_DIR/machines-after.txt"
  : >"$OUTPUT_DIR/machine-residue.txt"
  for machine in "${OWNED_MACHINES[@]}"; do
    if sudo -n machinectl show "$machine" >/dev/null 2>&1; then
      printf '%s\n' "$machine" >>"$OUTPUT_DIR/machine-residue.txt"
      fail "owned machine residue remains: $machine"
    fi
  done
  {
    printf 'result=PASS\n'
    printf 'rust_toolchain=%s\n' "$RUST_TOOLCHAIN"
    printf 'artifact_origin=%s\n' "$ARTIFACT_ORIGIN"
    printf 'rust_host=%s\n' "$RUST_HOST"
    printf 'rpm_arch=%s\n' "$RPM_ARCH"
    printf 'debian_arch=%s\n' "$DEBIAN_ARCH"
    printf 'almalinux_key_fingerprint=%s\n' "$ALMA_KEY_FINGERPRINT"
    printf 'machine_residue=0\n'
  } >"$OUTPUT_DIR/summary.txt"
  echo "PASS: native Linux installer lifecycle"
}

main "$@"
