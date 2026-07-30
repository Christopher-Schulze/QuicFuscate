#!/usr/bin/env bash
# Description: Disposable-guest proof for the production Linux installer lifecycle.
set -euo pipefail

BUNDLE_ROOT=""
OUTPUT_DIR=""
DISTRO_LABEL=""
HIDDEN_COMMAND_PATHS=()
FIXTURE_DIR=""

usage() {
  cat <<'EOF'
Usage: test-linux-installer-guest.sh --bundle-root PATH --output-dir PATH --distro-label LABEL

Runs destructive installer lifecycle checks only inside a systemd-nspawn guest.
The output directory must be a host-backed bind mount so evidence survives teardown.
EOF
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

assert_file_mode_owner() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(stat -c '%a %U %G' "$path")"
  [[ "$actual" == "$expected" ]] \
    || fail "unexpected metadata for $path: got '$actual', expected '$expected'"
}

record_install_failure_state() {
  local output_path="$1"
  {
    printf '%s\n' 'root_identity:'
    id
    printf '%s\n' 'service_identity:'
    getent passwd quicfuscate || true
    getent group quicfuscate || true
    runuser -u quicfuscate -- id || true
    printf '%s\n' 'managed_path_metadata:'
    stat -c '%n %a %u:%g %U:%G' \
      /var \
      /var/lib \
      /var/lib/quicfuscate \
      /var/lib/quicfuscate/qkeys.json \
      /etc/quicfuscate \
      /etc/quicfuscate/qkey-registry.key \
      2>&1 || true
    printf '%s\n' 'service_identity_properties:'
    systemctl show quicfuscate.service \
      --property=User \
      --property=Group \
      --property=DynamicUser \
      --property=RootDirectory \
      --property=ProtectSystem \
      --property=ReadWritePaths \
      --no-pager 2>&1 || true
    printf '%s\n' 'service_user_registry_access:'
    runuser -u quicfuscate -- \
      stat -c '%n %a %u:%g %U:%G' /var/lib/quicfuscate/qkeys.json 2>&1 || true
  } >"$output_path"
}

restore_hidden_command() {
  local command_path
  for command_path in "${HIDDEN_COMMAND_PATHS[@]}"; do
    if [[ -e "${command_path}.qf-hidden" ]]; then
      mv "${command_path}.qf-hidden" "$command_path"
    fi
  done
  HIDDEN_COMMAND_PATHS=()
}

cleanup_fixture() {
  restore_hidden_command
  if [[ -n "$FIXTURE_DIR" ]]; then
    case "$FIXTURE_DIR" in
      /run/quicfuscate-installer-guest.*)
        find "$FIXTURE_DIR" -depth -type f -delete 2>/dev/null || true
        find "$FIXTURE_DIR" -depth -type l -delete 2>/dev/null || true
        find "$FIXTURE_DIR" -depth -type d -exec rmdir {} \; 2>/dev/null || true
        ;;
    esac
  fi
}
trap cleanup_fixture EXIT

managed_state_is_absent() {
  ! id -u quicfuscate >/dev/null 2>&1 \
    && ! getent group quicfuscate >/dev/null 2>&1 \
    && [[ ! -e /usr/local/bin/quicfuscate ]] \
    && [[ ! -e /usr/share/quicfuscate ]] \
    && [[ ! -e /etc/quicfuscate ]] \
    && [[ ! -e /var/lib/quicfuscate ]] \
    && [[ ! -e /var/log/quicfuscate ]] \
    && [[ ! -e /etc/systemd/system/quicfuscate.service ]]
}

run_installer() {
  "$BUNDLE_ROOT/ops/install-server-linux.sh" \
    --binary "$BUNDLE_ROOT/bin/quicfuscate" \
    --assets "$BUNDLE_ROOT/share/admin-web" \
    --cert "$FIXTURE_DIR/server.crt" \
    --key "$FIXTURE_DIR/server.key" \
    --admin-password 'InstallerProof_541_Strong_29'
}

prove_missing_command_preflight() {
  local command_name="$1"
  local expected_message="$2"
  local log_path="$OUTPUT_DIR/preflight-missing-${command_name}.log"

  local command_path
  HIDDEN_COMMAND_PATHS=()
  while IFS= read -r command_path; do
    [[ -e "$command_path" ]] || continue
    HIDDEN_COMMAND_PATHS+=("$command_path")
    mv "$command_path" "${command_path}.qf-hidden"
  done < <(type -aP "$command_name")
  [[ ${#HIDDEN_COMMAND_PATHS[@]} -gt 0 ]] \
    || fail "cannot hide missing command: $command_name"
  if run_installer >"$log_path" 2>&1; then
    restore_hidden_command
    fail "installer accepted missing command: $command_name"
  fi
  restore_hidden_command
  grep -F "$expected_message" "$log_path" >/dev/null \
    || fail "missing actionable diagnostic for $command_name"
  managed_state_is_absent \
    || fail "missing-$command_name preflight mutated managed state"
}

prove_missing_command_set_preflight() {
  local case_name="$1"
  local expected_message="$2"
  shift 2
  local command_name
  local command_path
  local log_path="$OUTPUT_DIR/preflight-missing-${case_name}.log"

  HIDDEN_COMMAND_PATHS=()
  for command_name in "$@"; do
    while IFS= read -r command_path; do
      [[ -e "$command_path" ]] || continue
      HIDDEN_COMMAND_PATHS+=("$command_path")
      mv "$command_path" "${command_path}.qf-hidden"
    done < <(type -aP "$command_name")
  done
  [[ ${#HIDDEN_COMMAND_PATHS[@]} -gt 0 ]] \
    || fail "cannot hide missing command set: $case_name"
  if run_installer >"$log_path" 2>&1; then
    restore_hidden_command
    fail "installer accepted missing command set: $case_name"
  fi
  restore_hidden_command
  grep -F "$expected_message" "$log_path" >/dev/null \
    || fail "missing actionable diagnostic for $case_name"
  managed_state_is_absent \
    || fail "missing-$case_name preflight mutated managed state"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-root)
      BUNDLE_ROOT="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --distro-label)
      DISTRO_LABEL="${2:-}"
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

[[ -n "$BUNDLE_ROOT" ]] || fail "--bundle-root is required"
[[ -n "$OUTPUT_DIR" ]] || fail "--output-dir is required"
[[ -n "$DISTRO_LABEL" ]] || fail "--distro-label is required"
[[ "${EUID:-$(id -u)}" == "0" ]] || fail "guest proof must run as root"
[[ "$(systemd-detect-virt --container 2>/dev/null || true)" == "systemd-nspawn" ]] \
  || fail "refusing destructive lifecycle outside systemd-nspawn"
[[ "$(ps -p 1 -o comm= | tr -d ' ')" == "systemd" ]] \
  || fail "guest PID 1 is not systemd"
[[ ! -e "$OUTPUT_DIR" ]] || fail "refusing existing output path: $OUTPUT_DIR"

for command_name in getent ip iptables journalctl openssl runuser sha256sum stat systemctl; do
  command -v "$command_name" >/dev/null 2>&1 || fail "guest lacks $command_name"
done
for path in \
  "$BUNDLE_ROOT/bin/quicfuscate" \
  "$BUNDLE_ROOT/ops/install-server-linux.sh" \
  "$BUNDLE_ROOT/ops/quicfuscate-server.service" \
  "$BUNDLE_ROOT/ops/server-linux.default.toml" \
  "$BUNDLE_ROOT/share/admin-web/index.html"
do
  [[ -f "$path" ]] || fail "bundle input missing: $path"
done

mkdir "$OUTPUT_DIR"
FIXTURE_DIR="$(mktemp -d /run/quicfuscate-installer-guest.XXXXXX)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
  -days 1 -subj '/CN=quicfuscate-installer-proof' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$FIXTURE_DIR/server.key" \
  -out "$FIXTURE_DIR/server.crt" >/dev/null 2>&1
chmod 0600 "$FIXTURE_DIR/server.key"

managed_state_is_absent || fail "guest is not clean before preflight tests"
while IFS=: read -r command_name expected_message; do
  prove_missing_command_preflight "$command_name" "$expected_message"
done <<'EOF'
ip:iproute2 (ip)
iptables:iptables
cat:cat
chmod:chmod
chown:chown
cp:cp
cut:cut
dd:dd
dirname:dirname
find:find
getent:getent
grep:grep
head:head
id:id
install:install
mkdir:mkdir
sleep:sleep
tr:tr
systemctl:systemctl
journalctl:journalctl
EOF
prove_missing_command_set_preflight \
  "group-management" \
  "cannot create group 'quicfuscate'" \
  groupadd addgroup
prove_missing_command_set_preflight \
  "user-management" \
  "cannot create user 'quicfuscate'" \
  useradd adduser

if "$BUNDLE_ROOT/ops/install-server-linux.sh" \
  --binary "$FIXTURE_DIR/missing-binary" \
  --assets "$BUNDLE_ROOT/share/admin-web" \
  --cert "$FIXTURE_DIR/server.crt" \
  --key "$FIXTURE_DIR/server.key" \
  >"$OUTPUT_DIR/preflight-missing-binary.log" 2>&1; then
  fail "installer accepted a missing binary"
fi
grep -F 'binary not found:' "$OUTPUT_DIR/preflight-missing-binary.log" >/dev/null \
  || fail "missing actionable diagnostic for absent binary"
managed_state_is_absent || fail "missing-binary preflight mutated managed state"

if "$BUNDLE_ROOT/ops/install-server-linux.sh" \
  --binary "$BUNDLE_ROOT/bin/quicfuscate" \
  --assets "$FIXTURE_DIR/missing-assets" \
  --cert "$FIXTURE_DIR/server.crt" \
  --key "$FIXTURE_DIR/server.key" \
  >"$OUTPUT_DIR/preflight-missing-assets.log" 2>&1; then
  fail "installer accepted missing assets"
fi
grep -F 'admin web assets missing:' "$OUTPUT_DIR/preflight-missing-assets.log" >/dev/null \
  || fail "missing actionable diagnostic for absent assets"
managed_state_is_absent || fail "missing-assets preflight mutated managed state"

if ! run_installer >"$OUTPUT_DIR/install-first.log" 2>&1; then
  record_install_failure_state "$OUTPUT_DIR/install-first-state.txt"
  fail "installer failed during clean install"
fi
systemctl is-active --quiet quicfuscate.service \
  || fail "service is not active after clean install"
[[ "$(systemctl show quicfuscate.service --property=Group --value)" == "quicfuscate" ]] \
  || fail "service bootstrap group is not quicfuscate"

[[ "$(id -gn quicfuscate)" == "quicfuscate" ]] \
  || fail "service user primary group is not quicfuscate"
passwd_entry="$(getent passwd quicfuscate)"
[[ "$(cut -d: -f6 <<<"$passwd_entry")" == "/var/lib/quicfuscate" ]] \
  || fail "service user home is incorrect"
[[ "$(cut -d: -f7 <<<"$passwd_entry")" == "/usr/sbin/nologin" ]] \
  || fail "service user shell is incorrect"

assert_file_mode_owner /var/lib/quicfuscate '770 root quicfuscate'
assert_file_mode_owner /etc/quicfuscate '770 root quicfuscate'
assert_file_mode_owner /var/log/quicfuscate '750 quicfuscate quicfuscate'
assert_file_mode_owner /etc/quicfuscate/quicfuscate.toml '640 root quicfuscate'
assert_file_mode_owner /etc/quicfuscate/quicfuscate.env '640 root quicfuscate'
assert_file_mode_owner /etc/quicfuscate/qkey-registry.key '640 root quicfuscate'
assert_file_mode_owner /etc/quicfuscate/admin-auth.json '600 quicfuscate quicfuscate'
assert_file_mode_owner /var/lib/quicfuscate/qkeys.json '640 root quicfuscate'
assert_file_mode_owner /etc/systemd/system/quicfuscate.service '644 root root'
assert_file_mode_owner /usr/local/bin/quicfuscate '755 root root'
[[ "$(stat -c '%s' /etc/quicfuscate/qkey-registry.key)" == "32" ]] \
  || fail "QKey registry key is not exactly 32 bytes"

[[ "$(sha256_file /usr/local/bin/quicfuscate)" == \
  "$(sha256_file "$BUNDLE_ROOT/bin/quicfuscate")" ]] \
  || fail "installed binary differs from bundle artifact"
[[ "$(sha256_file /usr/share/quicfuscate/admin-web/index.html)" == \
  "$(sha256_file "$BUNDLE_ROOT/share/admin-web/index.html")" ]] \
  || fail "installed admin assets differ from bundle"
[[ "$(sha256_file /etc/systemd/system/quicfuscate.service)" == \
  "$(sha256_file "$BUNDLE_ROOT/ops/quicfuscate-server.service")" ]] \
  || fail "installed systemd unit differs from bundle"
[[ "$(sha256_file /etc/quicfuscate/quicfuscate.toml)" == \
  "$(sha256_file "$BUNDLE_ROOT/ops/server-linux.default.toml")" ]] \
  || fail "installed config differs from bundle template"

printf '\n# operator-preserved-config\n' >>/etc/quicfuscate/quicfuscate.toml
printf '\n# operator-preserved-env\n' >>/etc/quicfuscate/quicfuscate.env
config_hash="$(sha256_file /etc/quicfuscate/quicfuscate.toml)"
env_hash="$(sha256_file /etc/quicfuscate/quicfuscate.env)"
admin_auth_hash="$(sha256_file /etc/quicfuscate/admin-auth.json)"
registry_hash="$(sha256_file /var/lib/quicfuscate/qkeys.json)"
registry_key_hash="$(sha256_file /etc/quicfuscate/qkey-registry.key)"

run_installer >"$OUTPUT_DIR/install-second.log" 2>&1
systemctl is-active --quiet quicfuscate.service \
  || fail "service is not active after idempotent rerun"
[[ "$(sha256_file /etc/quicfuscate/quicfuscate.toml)" == "$config_hash" ]] \
  || fail "rerun changed operator config"
[[ "$(sha256_file /etc/quicfuscate/quicfuscate.env)" == "$env_hash" ]] \
  || fail "rerun changed operator environment"
[[ "$(sha256_file /etc/quicfuscate/admin-auth.json)" == "$admin_auth_hash" ]] \
  || fail "rerun changed persisted admin credentials"
[[ "$(sha256_file /var/lib/quicfuscate/qkeys.json)" == "$registry_hash" ]] \
  || fail "rerun changed operator registry"
[[ "$(sha256_file /etc/quicfuscate/qkey-registry.key)" == "$registry_key_hash" ]] \
  || fail "rerun changed registry encryption key"

cp "$FIXTURE_DIR/server.crt" "$FIXTURE_DIR/server.crt.valid"
cp "$FIXTURE_DIR/server.key" "$FIXTURE_DIR/server.key.valid"
printf 'invalid certificate\n' >"$FIXTURE_DIR/server.crt"
printf 'invalid private key\n' >"$FIXTURE_DIR/server.key"
systemctl stop quicfuscate.service
if run_installer >"$OUTPUT_DIR/install-service-failure.log" 2>&1; then
  fail "installer reported success for a failed service"
fi
grep -F 'quicfuscate.service failed to start' "$OUTPUT_DIR/install-service-failure.log" >/dev/null \
  || fail "installer omitted service failure summary"
grep -E 'invalid|certificate|private key|PEM|failed' \
  "$OUTPUT_DIR/install-service-failure.log" >/dev/null \
  || fail "installer omitted actionable journal detail"
cp "$FIXTURE_DIR/server.crt.valid" "$FIXTURE_DIR/server.crt"
cp "$FIXTURE_DIR/server.key.valid" "$FIXTURE_DIR/server.key"
chmod 0600 "$FIXTURE_DIR/server.key"
systemctl reset-failed quicfuscate.service
run_installer >"$OUTPUT_DIR/install-recovery.log" 2>&1
systemctl is-active --quiet quicfuscate.service \
  || fail "service did not recover after restoring valid credentials"

{
  printf 'distro=%s\n' "$DISTRO_LABEL"
  printf 'os_release=%s\n' "$(tr '\n' ' ' </etc/os-release)"
  printf 'binary_sha256=%s\n' "$(sha256_file /usr/local/bin/quicfuscate)"
  printf 'config_sha256=%s\n' "$(sha256_file /etc/quicfuscate/quicfuscate.toml)"
  printf 'env_sha256=%s\n' "$(sha256_file /etc/quicfuscate/quicfuscate.env)"
  printf 'admin_auth_sha256=%s\n' "$(sha256_file /etc/quicfuscate/admin-auth.json)"
  printf 'qkey_registry_sha256=%s\n' "$(sha256_file /var/lib/quicfuscate/qkeys.json)"
  printf 'qkey_key_sha256=%s\n' "$(sha256_file /etc/quicfuscate/qkey-registry.key)"
  printf 'service_active=1\n'
  printf 'preflight_mutations=0\n'
  printf 'idempotent_preservation=1\n'
  printf 'journal_failure_detail=1\n'
} >"$OUTPUT_DIR/summary.txt"
systemctl status --no-pager quicfuscate.service >"$OUTPUT_DIR/service-status.txt"
journalctl -u quicfuscate.service --no-pager >"$OUTPUT_DIR/service-journal.txt"

systemctl disable --now quicfuscate.service
find /usr/share/quicfuscate -depth -type f -delete
find /usr/share/quicfuscate -depth -type l -delete
find /usr/share/quicfuscate -depth -type d -exec rmdir {} \;
find /etc/quicfuscate -depth -type f -delete
find /etc/quicfuscate -depth -type l -delete
find /etc/quicfuscate -depth -type d -exec rmdir {} \;
find /var/lib/quicfuscate -depth -type f -delete
find /var/lib/quicfuscate -depth -type l -delete
find /var/lib/quicfuscate -depth -type d -exec rmdir {} \;
find /var/log/quicfuscate -depth -type f -delete
find /var/log/quicfuscate -depth -type l -delete
find /var/log/quicfuscate -depth -type d -exec rmdir {} \;
rm -f /usr/local/bin/quicfuscate /etc/systemd/system/quicfuscate.service
userdel quicfuscate
if getent group quicfuscate >/dev/null 2>&1; then
  groupdel quicfuscate
fi
systemctl daemon-reload
systemctl reset-failed quicfuscate.service 2>/dev/null || true

managed_state_is_absent || fail "installer-owned residue remains after teardown"
printf 'teardown_residue=0\n' >>"$OUTPUT_DIR/summary.txt"
echo "PASS: Linux installer lifecycle ($DISTRO_LABEL)"
