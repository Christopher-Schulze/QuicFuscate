#!/usr/bin/env bash
# Description: Build the Svelte web-admin UI and publish bundle to assets/web-admin.
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  cat <<'EOF'
Usage: build-web-admin.sh

Builds apps/svelte-admin with Bun and copies build/* to assets/web-admin.
By default, existing assets/web-admin content is replaced without archiving.
To archive existing assets first:
  - pass --archive-existing
  - or set QF_ARCHIVE_WEB_ADMIN_ASSETS=1
EOF
  exit 0
fi

ARCHIVE_EXISTING="${QF_ARCHIVE_WEB_ADMIN_ASSETS:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive-existing)
      ARCHIVE_EXISTING=1
      ;;
    --no-archive-existing)
      ARCHIVE_EXISTING=0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Run with --help for usage." >&2
      exit 2
      ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SVELTE_APP_DIR="$PROJECT_ROOT/apps/svelte-admin"

if [ ! -d "$SVELTE_APP_DIR" ] || [ ! -f "$SVELTE_APP_DIR/package.json" ]; then
  echo "Svelte web-admin UI not found at: $SVELTE_APP_DIR" >&2
  exit 1
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "bun not found. Install Bun to build the Svelte web-admin UI." >&2
  exit 1
fi

cd "$SVELTE_APP_DIR"
bun install --frozen-lockfile --no-progress
bun run build
SOURCE="$SVELTE_APP_DIR/build"
DEST="$PROJECT_ROOT/assets/web-admin"

if [ ! -d "$SOURCE" ]; then
  echo "Error: Build output not found at $SOURCE" >&2
  exit 1
fi

if [[ "$ARCHIVE_EXISTING" == "1" ]] && [ -d "$DEST" ] && [ "$(ls -A "$DEST" 2>/dev/null)" ]; then
  ARCHIVE_ROOT="$PROJECT_ROOT/archive"
  TS="$(date +"%Y%m%d_%H%M%S")"
  ARCHIVE_DIR="$ARCHIVE_ROOT/web-admin-assets-$TS"
  mkdir -p "$ARCHIVE_DIR"
  cp -R "$DEST"/. "$ARCHIVE_DIR"/
  printf "archived_from=%s\narchived_at=%s\n" "$DEST" "$TS" > "$ARCHIVE_DIR/metadata.txt"
fi

# Publish through a staging directory and an atomic swap.
#
# The previous sequence removed the destination before a fallible copy, so a disk-full,
# permission, or interrupted copy turned a working admin UI into a missing or partial one with no
# way back. The old tree now survives until a fully copied and verified new tree is ready to
# replace it.

# Required members of a usable bundle. A build that produced a directory but not these is not a
# bundle, and must not replace one that is.
REQUIRED_ASSETS=("index.html")

STAGING=""
PREVIOUS=""
cleanup_publish() {
  local status=$?
  # Remove only directories this script created, never the destination.
  [[ -n "$STAGING" && -d "$STAGING" ]] && rm -rf "$STAGING"
  if [[ $status -ne 0 && -n "$PREVIOUS" && -d "$PREVIOUS" && ! -e "$DEST" ]]; then
    # The swap failed between moving the old tree aside and moving the new one in. Put the old
    # tree back rather than leaving the server with no admin UI at all.
    mv "$PREVIOUS" "$DEST" || echo "error: failed to restore the previous bundle from $PREVIOUS" >&2
    PREVIOUS=""
  fi
  [[ -n "$PREVIOUS" && -d "$PREVIOUS" ]] && rm -rf "$PREVIOUS"
  exit "$status"
}
trap cleanup_publish EXIT

mkdir -p "$(dirname "$DEST")"
STAGING="$(mktemp -d "${DEST}.staging.XXXXXX")"
cp -R "$SOURCE"/. "$STAGING"/

for asset in "${REQUIRED_ASSETS[@]}"; do
  [[ -f "$STAGING/$asset" ]] || {
    echo "error: staged bundle is missing required asset: $asset" >&2
    exit 1
  }
done

staged_files="$(find "$STAGING" -type f | wc -l | tr -d ' ')"
[[ "$staged_files" -gt 0 ]] || { echo "error: staged bundle contains no files" >&2; exit 1; }

# Swap: move the old tree aside, move the new one in, then discard the old one. Both moves are
# renames within the same directory, so neither can leave a half-copied tree at $DEST.
if [[ -d "$DEST" ]]; then
  PREVIOUS="$(mktemp -d "${DEST}.previous.XXXXXX")"
  rmdir "$PREVIOUS"
  mv "$DEST" "$PREVIOUS"
fi
mv "$STAGING" "$DEST"
STAGING=""

echo "Web admin assets published to: $DEST (files=$staged_files)"
