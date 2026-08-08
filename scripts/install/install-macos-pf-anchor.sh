#!/usr/bin/env bash
# Description: Install or remove the QuicFuscate-managed macOS PF anchor reference.
set -Eeuo pipefail

readonly ANCHOR_NAME="com.quicfuscate.killswitch"
readonly ANCHOR_LINE="anchor \"${ANCHOR_NAME}\" all"
readonly BEGIN_MARKER="# BEGIN QUICFUSCATE MANAGED PF ANCHOR"
readonly END_MARKER="# END QUICFUSCATE MANAGED PF ANCHOR"
readonly STATE_SCHEMA="1"

ROOT="/"
COMMAND=""
PF_CONF=""
STATE_DIR=""
STATE_FILE=""
BACKUP_FILE=""
LOCK_DIR=""
LOCK_HELD=0

usage() {
  cat <<'EOF'
Usage: install-macos-pf-anchor.sh <install|remove|check> [--root PATH]

Install, remove, or inspect the one QuicFuscate-managed PF anchor reference.

Production mode (the default) is macOS-only and requires root. It edits only
/etc/pf.conf, preserves all unrelated lines, reloads the main ruleset through
pfctl, and never enables or disables pf. The managed reference is:

  anchor "com.quicfuscate.killswitch" all

The optional --root PATH mode is a non-privileged fixture boundary. It maps
PATH/etc/pf.conf and PATH/var/db/quicfuscate/pf and skips pfctl, so packaging
and deterministic tests can exercise the file and ownership transaction.

Commands:
  install   Add the managed anchor reference, or succeed idempotently if owned.
  remove    Remove only the exact managed reference and its ownership record.
  check     Verify the managed reference and ownership record without mutation.

The installer refuses an existing unmanaged exact or wildcard QuicFuscate
anchor, modified markers, symlinks, incomplete state, and concurrent runs.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_absolute_path() {
  local path="$1" label="$2"
  [[ "$path" = /* ]] || die "$label must be an absolute path: $path"
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* ]] || die "$label contains a line break"
}

stat_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

stat_uid() {
  if stat -f '%u' "$1" >/dev/null 2>&1; then
    stat -f '%u' "$1"
  else
    stat -c '%u' "$1"
  fi
}

stat_gid() {
  if stat -f '%g' "$1" >/dev/null 2>&1; then
    stat -f '%g' "$1"
  else
    stat -c '%g' "$1"
  fi
}

ensure_regular_file() {
  local path="$1" label="$2"
  [[ -e "$path" ]] || die "$label is missing: $path"
  [[ ! -L "$path" ]] || die "$label is a symlink; refusing to follow it: $path"
  [[ -f "$path" ]] || die "$label is not a regular file: $path"
}

ensure_private_directory() {
  [[ ! -L "$STATE_DIR" ]] || die "state directory is a symlink: $STATE_DIR"
  if [[ ! -e "$STATE_DIR" ]]; then
    mkdir -p "$STATE_DIR" || die "cannot create state directory: $STATE_DIR"
  fi
  [[ -d "$STATE_DIR" ]] || die "state path is not a directory: $STATE_DIR"
  local expected_uid
  if [[ "$ROOT" == "/" ]]; then
    expected_uid=0
  else
    expected_uid="$(id -u)"
  fi
  [[ "$(stat_uid "$STATE_DIR")" == "$expected_uid" ]] \
    || die "state directory is not owned by uid $expected_uid: $STATE_DIR"
  chmod 700 "$STATE_DIR" || die "cannot secure state directory: $STATE_DIR"
  [[ "$(stat_mode "$STATE_DIR")" == "700" ]] \
    || die "state directory has unsafe mode: $STATE_DIR"
}

validate_existing_state_directory() {
  [[ ! -L "$STATE_DIR" ]] || die "state directory is a symlink: $STATE_DIR"
  [[ ! -e "$STATE_DIR" ]] && return 0
  [[ -d "$STATE_DIR" ]] || die "state path is not a directory: $STATE_DIR"
  local expected_uid
  if [[ "$ROOT" == "/" ]]; then
    expected_uid=0
  else
    expected_uid="$(id -u)"
  fi
  [[ "$(stat_uid "$STATE_DIR")" == "$expected_uid" ]] \
    || die "state directory is not owned by uid $expected_uid: $STATE_DIR"
  [[ "$(stat_mode "$STATE_DIR")" == "700" ]] \
    || die "state directory has unsafe mode: $STATE_DIR"
}

release_lock() {
  if (( LOCK_HELD )); then
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    LOCK_HELD=0
  fi
}

acquire_lock() {
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    die "another PF anchor installer is active or left a lock at $LOCK_DIR"
  fi
  printf '%s\n' "$$" >"$LOCK_DIR/pid" || die "cannot write installer lock: $LOCK_DIR/pid"
  chmod 600 "$LOCK_DIR/pid" || die "cannot secure installer lock: $LOCK_DIR/pid"
  LOCK_HELD=1
  trap release_lock EXIT
}

expected_block() {
  printf '%s\n%s\n%s' "$BEGIN_MARKER" "$ANCHOR_LINE" "$END_MARKER"
}

marker_count() {
  local marker="$1"
  awk -v marker="$marker" '$0 == marker { count += 1 } END { print count + 0 }' "$PF_CONF"
}

managed_block_state() {
  local begin_count end_count actual
  begin_count="$(marker_count "$BEGIN_MARKER")"
  end_count="$(marker_count "$END_MARKER")"
  if [[ "$begin_count" == 0 && "$end_count" == 0 ]]; then
    printf 'NONE\n'
    return 0
  fi
  if [[ "$begin_count" != 1 || "$end_count" != 1 ]]; then
    printf 'MODIFIED\n'
    return 0
  fi
  if ! actual="$(awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" '
    $0 == begin {
      if (inside) { invalid = 1 }
      inside = 1
      block = $0 ORS
      next
    }
    inside {
      block = block $0 ORS
      if ($0 == end) {
        inside = 0
        ended = 1
      }
    }
    END {
      if (inside || !ended || invalid) { exit 1 }
      printf "%s", block
    }
  ' "$PF_CONF")"; then
    printf 'MODIFIED\n'
    return 0
  fi
  if [[ "$actual" == "$(expected_block)" ]]; then
    printf 'OWNED\n'
  else
    printf 'MODIFIED\n'
  fi
}

foreign_anchor_reference_count() {
  awk -v exact="\"$ANCHOR_NAME\"" -v wildcard='"com.quicfuscate/*"' '
    $1 == "anchor" && ($2 == exact || $2 == wildcard) { count += 1 }
    END { print count + 0 }
  ' "$PF_CONF"
}

state_contents() {
  printf 'schema=%s\nanchor=%s\npf_conf=/etc/pf.conf' "$STATE_SCHEMA" "$ANCHOR_NAME"
}

state_is_valid() {
  [[ ! -L "$STATE_FILE" ]] || die "ownership state is a symlink: $STATE_FILE"
  [[ -e "$STATE_FILE" ]] || return 1
  [[ -f "$STATE_FILE" ]] || die "ownership state is not a regular file: $STATE_FILE"
  [[ "$(stat_mode "$STATE_FILE")" == "600" ]] \
    || die "ownership state has unsafe mode $(stat_mode "$STATE_FILE"): $STATE_FILE"
  [[ "$(<"$STATE_FILE")" == "$(state_contents)" ]]
}

write_state() {
  local temporary
  temporary="$(mktemp "$STATE_DIR/.managed-anchor.state.XXXXXX")" \
    || { printf 'error: cannot create temporary ownership state\n' >&2; return 1; }
  if ! printf '%s\n' "$(state_contents)" >"$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot write temporary ownership state\n' >&2
    return 1
  fi
  if ! chmod 600 "$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot secure temporary ownership state\n' >&2
    return 1
  fi
  if ! mv "$temporary" "$STATE_FILE"; then
    rm -f "$temporary"
    printf 'error: cannot publish ownership state: %s\n' "$STATE_FILE" >&2
    return 1
  fi
}

remove_state_and_backup() {
  if [[ -L "$STATE_FILE" || -L "$BACKUP_FILE" ]]; then
    die "ownership residue is a symlink; refusing removal"
  fi
  rm -f "$STATE_FILE" "$BACKUP_FILE"
  [[ ! -e "$STATE_FILE" && ! -e "$BACKUP_FILE" ]] \
    || die "could not remove managed PF ownership residue"
}

preserve_config_metadata() {
  local temporary="$1" mode uid gid
  mode="$(stat_mode "$PF_CONF")"
  uid="$(stat_uid "$PF_CONF")"
  gid="$(stat_gid "$PF_CONF")"
  if ! chmod "$mode" "$temporary"; then
    printf 'error: cannot preserve pf.conf mode\n' >&2
    return 1
  fi
  if [[ "$(stat_uid "$temporary")" != "$uid" || "$(stat_gid "$temporary")" != "$gid" ]]; then
    if ! chown "$uid:$gid" "$temporary" 2>/dev/null; then
      printf 'error: cannot preserve pf.conf owner uid %s/gid %s\n' "$uid" "$gid" >&2
      return 1
    fi
  fi
}

create_backup() {
  [[ ! -e "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] \
    || { printf 'error: orphaned pre-install backup exists: %s\n' "$BACKUP_FILE" >&2; return 1; }
  local temporary
  temporary="$(mktemp "$STATE_DIR/.pf.conf.before.XXXXXX")" \
    || { printf 'error: cannot create pre-install backup\n' >&2; return 1; }
  if ! cp -p "$PF_CONF" "$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot copy pf.conf to the pre-install backup\n' >&2
    return 1
  fi
  if ! chmod 600 "$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot secure the pre-install backup\n' >&2
    return 1
  fi
  if ! mv "$temporary" "$BACKUP_FILE"; then
    rm -f "$temporary"
    printf 'error: cannot publish the pre-install backup\n' >&2
    return 1
  fi
}

restore_from_backup() {
  if [[ ! -e "$BACKUP_FILE" || -L "$BACKUP_FILE" || ! -f "$BACKUP_FILE" ]]; then
    printf 'error: pre-install backup is missing or unsafe: %s\n' "$BACKUP_FILE" >&2
    return 1
  fi
  local temporary
  temporary="$(mktemp "$STATE_DIR/.pf.conf.restore.XXXXXX")" \
    || { printf 'error: cannot create pf.conf restore file\n' >&2; return 1; }
  if ! cp -p "$BACKUP_FILE" "$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot copy the pre-install backup\n' >&2
    return 1
  fi
  if ! preserve_config_metadata "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  if ! mv "$temporary" "$PF_CONF"; then
    rm -f "$temporary"
    printf 'error: cannot restore pf.conf\n' >&2
    return 1
  fi
}

append_managed_block() {
  local temporary
  temporary="$(mktemp "$(dirname "$PF_CONF")/.pf.conf.quicfuscate.XXXXXX")" \
    || { printf 'error: cannot create pf.conf staging file\n' >&2; return 1; }
  if ! cp -p "$PF_CONF" "$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot stage pf.conf\n' >&2
    return 1
  fi
  if [[ -s "$temporary" && -n "$(tail -c 1 "$temporary")" ]]; then
    if ! printf '\n' >>"$temporary"; then
      rm -f "$temporary"
      printf 'error: cannot terminate staged pf.conf with a newline\n' >&2
      return 1
    fi
  fi
  if ! printf '\n%s\n' "$(expected_block)" >>"$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot append the managed PF anchor\n' >&2
    return 1
  fi
  if ! preserve_config_metadata "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  if ! mv "$temporary" "$PF_CONF"; then
    rm -f "$temporary"
    printf 'error: cannot publish managed pf.conf\n' >&2
    return 1
  fi
}

remove_managed_block() {
  local temporary
  temporary="$(mktemp "$(dirname "$PF_CONF")/.pf.conf.quicfuscate.XXXXXX")" \
    || { printf 'error: cannot create pf.conf staging file\n' >&2; return 1; }
  if ! awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" '
    $0 == begin { inside = 1; next }
    inside && $0 == end { inside = 0; next }
    !inside { print }
  ' "$PF_CONF" >"$temporary"; then
    rm -f "$temporary"
    printf 'error: cannot remove the managed PF anchor block\n' >&2
    return 1
  fi
  if ! preserve_config_metadata "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  if ! mv "$temporary" "$PF_CONF"; then
    rm -f "$temporary"
    printf 'error: cannot publish pf.conf without the managed anchor\n' >&2
    return 1
  fi
}

run_pfctl_load() {
  [[ "$ROOT" != "/" ]] && return 0
  local output
  if ! output="$(pfctl -f "$PF_CONF" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  return 0
}

pf_status_line() {
  [[ "$ROOT" != "/" ]] && return 0
  pfctl -s info 2>/dev/null | awk '/^Status:/ { print; exit }'
}

active_anchor_reference_present() {
  [[ "$ROOT" != "/" ]] && return 1
  local rules
  if ! rules="$(pfctl -sr 2>&1)"; then
    printf 'error: cannot inspect the active PF main ruleset with pfctl -sr: %s\n' "$rules" >&2
    return 2
  fi
  awk -v exact="\"$ANCHOR_NAME\"" -v wildcard='"com.quicfuscate/*"' '
    $1 == "anchor" && ($2 == exact || $2 == wildcard) { found = 1 }
    END { exit(found ? 0 : 1) }
  ' <<<"$rules"
}

verify_active_reference() {
  [[ "$ROOT" != "/" ]] && return 0
  if active_anchor_reference_present; then
    return 0
  else
    local result=$?
  fi
  if [[ "$result" == "2" ]]; then
    return 1
  fi
  printf 'error: pfctl loaded pf.conf but the active ruleset does not reference %s\n' "$ANCHOR_NAME" >&2
  return 1
}

rollback_after_reload_failure() {
  local reason="$1"
  if ! restore_from_backup; then
    die "$reason; rollback could not restore pf.conf and managed state must be repaired manually"
  fi
  if ! run_pfctl_load; then
    die "$reason; pf.conf was restored on disk but pfctl could not reload the original ruleset"
  fi
  [[ ! -L "$STATE_FILE" && ! -L "$BACKUP_FILE" ]] \
    || die "$reason; rollback restored pf.conf but ownership residue is a symlink"
  rm -f "$STATE_FILE" "$BACKUP_FILE"
  die "$reason; the original pf.conf was restored and reloaded"
}

install_anchor() {
  ensure_regular_file "$PF_CONF" "pf.conf"
  local block_state
  block_state="$(managed_block_state)"
  case "$block_state" in
    OWNED)
      state_is_valid || die "managed PF anchor exists but ownership state is missing or invalid"
      verify_active_reference
      printf 'PASS: managed PF anchor is already installed (%s)\n' "$ANCHOR_NAME"
      return 0
      ;;
    MODIFIED)
      die "managed PF anchor markers are modified or duplicated; refusing repair"
      ;;
  esac
  state_is_valid && die "ownership state exists without its managed PF anchor block"
  [[ ! -e "$STATE_FILE" && ! -L "$STATE_FILE" ]] \
    || die "invalid or incomplete ownership state exists: $STATE_FILE"
  [[ ! -e "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] \
    || die "orphaned pre-install backup exists: $BACKUP_FILE"
  [[ "$(foreign_anchor_reference_count)" == "0" ]] \
    || die "an unmanaged exact or wildcard QuicFuscate anchor already exists; preserving it"
  if active_anchor_reference_present; then
    die "the active PF ruleset already references an unmanaged QuicFuscate anchor; preserving it"
  else
    local active_status=$?
    [[ "$active_status" == "1" ]] \
      || die "cannot prove that the active PF ruleset has no unmanaged QuicFuscate anchor"
  fi

  create_backup \
    || die "could not create the pre-install backup; pf.conf was left unchanged"
  if ! append_managed_block; then
    rm -f "$BACKUP_FILE"
    die "could not stage the managed PF anchor; pf.conf was left unchanged"
  fi
  if ! run_pfctl_load; then
    rollback_after_reload_failure "pfctl could not load the managed PF anchor reference"
  fi
  if ! verify_active_reference; then
    rollback_after_reload_failure "the managed PF anchor reference was not visible after pfctl reload"
  fi
  if ! write_state; then
    rollback_after_reload_failure "ownership state publication failed"
  fi
  local status="disabled"
  if [[ "$ROOT" == "/" ]]; then
    status="$(pf_status_line || true)"
    [[ -n "$status" ]] || die "pfctl did not report the post-install PF status"
  fi
  printf 'PASS: managed PF anchor installed (%s); %s\n' "$ANCHOR_NAME" "${status:-fixture mode}"
}

remove_anchor() {
  ensure_regular_file "$PF_CONF" "pf.conf"
  local block_state
  block_state="$(managed_block_state)"
  case "$block_state" in
    NONE)
      if [[ -e "$STATE_FILE" || -L "$STATE_FILE" || -e "$BACKUP_FILE" || -L "$BACKUP_FILE" ]]; then
        die "managed PF anchor is absent but ownership residue remains"
      fi
      printf 'PASS: managed PF anchor is already absent (%s)\n' "$ANCHOR_NAME"
      return 0
      ;;
    MODIFIED)
      die "managed PF anchor markers are modified or duplicated; refusing removal"
      ;;
  esac
  state_is_valid || die "managed PF anchor exists without valid ownership state"
  ensure_regular_file "$BACKUP_FILE" "pre-install backup"

  remove_managed_block \
    || die "could not stage the managed PF anchor removal; ownership state was retained"
  if ! run_pfctl_load; then
    rollback_after_reload_failure "pfctl could not load pf.conf without the managed anchor"
  fi
  if [[ "$ROOT" == "/" ]]; then
    if active_anchor_reference_present; then
      rollback_after_reload_failure "the managed anchor remained referenced after removal"
    else
      local active_status=$?
      [[ "$active_status" == "1" ]] \
        || rollback_after_reload_failure "cannot prove that the managed anchor was removed from the active ruleset"
    fi
  fi
  remove_state_and_backup
  printf 'PASS: managed PF anchor removed (%s)\n' "$ANCHOR_NAME"
}

check_anchor() {
  validate_existing_state_directory
  ensure_regular_file "$PF_CONF" "pf.conf"
  local block_state
  block_state="$(managed_block_state)"
  case "$block_state" in
    NONE)
      [[ ! -e "$STATE_FILE" && ! -L "$STATE_FILE" \
        && ! -e "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] \
        || die "managed PF anchor is absent but ownership residue remains"
      printf 'PASS: managed PF anchor is not installed (%s)\n' "$ANCHOR_NAME"
      return 0
      ;;
    MODIFIED)
      die "managed PF anchor markers are modified or duplicated; refusing to claim ownership"
      ;;
  esac
  state_is_valid || die "managed PF anchor exists without valid ownership state"
  ensure_regular_file "$BACKUP_FILE" "pre-install backup"
  verify_active_reference \
    || die "managed PF anchor is not visible in the active PF ruleset"
  if [[ "$ROOT" == "/" ]]; then
    local status
    status="$(pf_status_line || true)"
    [[ "$status" == "Status: Enabled" ]] \
      || die "managed PF anchor is installed but pf is not enabled: ${status:-status unavailable}"
  fi
  printf 'PASS: managed PF anchor is installed and owned (%s)\n' "$ANCHOR_NAME"
}

parse_args() {
  [[ $# -ge 1 ]] || { usage >&2; exit 2; }
  COMMAND="$1"
  shift
  case "$COMMAND" in
    install|remove|check) ;;
    -h|--help|help) usage; exit 0 ;;
    *) die "unknown command: $COMMAND" ;;
  esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --root)
        [[ $# -ge 2 ]] || die "--root requires a path"
        ROOT="$2"
        shift 2
        ;;
      -h|--help|help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
  require_absolute_path "$ROOT" "--root"
  if [[ "$ROOT" != "/" ]]; then
    ROOT="${ROOT%/}"
    [[ -n "$ROOT" ]] || ROOT="/"
  fi
  PF_CONF="$ROOT/etc/pf.conf"
  STATE_DIR="$ROOT/var/db/quicfuscate/pf"
  STATE_FILE="$STATE_DIR/managed-anchor.state"
  BACKUP_FILE="$STATE_DIR/pf.conf.before-quicfuscate"
  LOCK_DIR="$STATE_DIR/.installer.lock"
}

main() {
  parse_args "$@"
  if [[ "$ROOT" == "/" ]]; then
    [[ "$(uname -s)" == "Darwin" ]] || die "production PF anchor installation requires macOS"
    [[ "${EUID:-$(id -u)}" == "0" ]] || die "production PF anchor installation requires root"
    need_command pfctl
  fi
  case "$COMMAND" in
    install)
      ensure_private_directory
      acquire_lock
      install_anchor
      ;;
    remove)
      if [[ -e "$STATE_DIR" || -L "$STATE_DIR" ]]; then
        validate_existing_state_directory
        acquire_lock
      fi
      remove_anchor
      ;;
    check)
      check_anchor
      ;;
  esac
}

main "$@"
