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

rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SOURCE"/. "$DEST"/

echo "Web admin assets copied to: $DEST"
