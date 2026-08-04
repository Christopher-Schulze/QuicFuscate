#!/usr/bin/env bash
# Description: Frontend UI smoke runner [Web Admin + Desktop].
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR]"
      usage_common_flags
      exit 0
      ;;
    *) break;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

JSON="$OUTPUT_DIR/results.json"
json_begin "$JSON" "ui_frontends_smoke"
JSON_FIRST_RUN=1

print_system_banner
info "Running Web Admin UI smoke test"
run bash "$PROJECT_ROOT/scripts/tests/frontend/verify-playwright-browser.sh" apps/svelte-admin
run bash -lc "cd '$PROJECT_ROOT/apps/svelte-admin' && env -u NO_COLOR -u FORCE_COLOR NODE_PATH='./node_modules' bunx playwright test smoke-ui.pw.ts --config=playwright.config.ts --project=chromium --workers=1 --reporter=list"

info "Running Desktop UI smoke test"
run bash "$PROJECT_ROOT/scripts/tests/frontend/verify-playwright-browser.sh" apps/svelte-desktop
run bash -lc "cd '$PROJECT_ROOT/apps/svelte-desktop' && env -u NO_COLOR -u FORCE_COLOR NODE_PATH='./node_modules' bunx playwright test smoke-ui.pw.ts --config=playwright.config.ts --project=chromium --workers=1 --reporter=list"

info "UI smoke tests completed successfully"
info "Artifacts: $OUTPUT_DIR"
json_end "$JSON"
