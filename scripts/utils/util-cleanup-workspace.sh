#!/usr/bin/env bash
# Description: Canonical workspace cleanup utility.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

MODE="safe"
KEEP_RELEASES="5"
CARGO_CLEAN=0
DRY_RUN=0

run_cmd() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

prune_releases() {
  local keep="$1"
  local rel="$ROOT/scripts/out/releases"
  if [[ ! -d "$rel" ]]; then
    echo "[cleanup] scripts/out/releases not found, skipping"
    return 0
  fi
  (
    cd "$rel"
    # `mapfile` is a Bash 4 builtin and macOS ships Bash 3.2 as /bin/bash, where this
    # script failed before doing any work. A read loop is portable to both.
    old=()
    while IFS= read -r entry; do
      [[ -n "$entry" ]] && old+=("$entry")
    done < <(ls -1t 2>/dev/null | tail -n "+$((keep + 1))")
    if [[ "${#old[@]}" -eq 0 ]]; then
      echo "[cleanup] releases already within keep=$keep"
      return 0
    fi
    for e in "${old[@]}"; do
      run_cmd rm -rf -- "$e"
    done
    echo "[cleanup] scripts/out/releases pruned (kept latest ${keep})"
  )
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --safe|--soft) MODE="safe";;
    --full) MODE="full";;
    --mode)
      MODE="${2:-}"
      shift
      ;;
    --keep-releases)
      KEEP_RELEASES="${2:-}"
      [[ "$KEEP_RELEASES" =~ ^[0-9]+$ ]] || { echo "error: --keep-releases expects integer" >&2; exit 2; }
      shift
      ;;
    --cargo-clean) CARGO_CLEAN=1;;
    --dry-run) DRY_RUN=1;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/utils/util-cleanup-workspace.sh [--safe|--full] [--keep-releases N] [--cargo-clean] [--dry-run]

--safe:
  - remove .DS_Store and Thumbs.db
  - clear scripts/out/*
  - prune scripts/out/releases/* (keep newest N; default 5)

--full:
  - safe +
  - remove backup/temp/log files (*~, *.bak, *.swp, *.log)

--cargo-clean:
  - additionally run cargo clean (explicit opt-in)
USAGE
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
  shift
done

if [[ "$MODE" != "safe" && "$MODE" != "full" ]]; then
  echo "error: invalid --mode '$MODE' (expected safe|full)" >&2
  exit 2
fi

echo "[cleanup] mode=$MODE root=$ROOT"
echo "[cleanup] keep_releases=$KEEP_RELEASES cargo_clean=$CARGO_CLEAN dry_run=$DRY_RUN"

echo "[cleanup] removing .DS_Store"
run_cmd find "$ROOT" -name ".DS_Store" -type f -delete 2>/dev/null || true

echo "[cleanup] removing Thumbs.db"
run_cmd find "$ROOT" -name "Thumbs.db" -type f -delete 2>/dev/null || true

echo "[cleanup] pruning releases (before clearing scripts/out)"
prune_releases "$KEEP_RELEASES"

echo "[cleanup] clearing scripts/out contents (preserving releases)"
if [[ -d "$ROOT/scripts/out" ]]; then
  run_cmd find "$ROOT/scripts/out" -mindepth 1 -not -name "releases" -not -path "*/releases/*" -depth -delete
fi

if [[ "$MODE" == "full" ]]; then
  echo "[cleanup] removing temp/backup/log files"
  run_cmd find "$ROOT" -name "*~" -type f -delete 2>/dev/null || true
  run_cmd find "$ROOT" -name "*.bak" -type f -delete 2>/dev/null || true
  run_cmd find "$ROOT" -name "*.swp" -type f -delete 2>/dev/null || true
  run_cmd find "$ROOT" -name "*.log" -type f -delete 2>/dev/null || true
fi

if [[ "$CARGO_CLEAN" == "1" ]]; then
  echo "[cleanup] running cargo clean"
  run_cmd cargo clean
else
  echo "[cleanup] skipping cargo clean (use --cargo-clean to enable)"
fi

echo "[cleanup] disk usage summary"
du -sh "$ROOT" 2>/dev/null || true
du -sh "$ROOT/target" 2>/dev/null || echo "[cleanup] target/ not found"
du -sh "$ROOT/scripts/out/releases" 2>/dev/null || echo "[cleanup] scripts/out/releases not found"

echo "[cleanup] done"
