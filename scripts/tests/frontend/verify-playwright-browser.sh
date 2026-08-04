#!/usr/bin/env bash
# Description: Fail-fast Playwright Chromium prerequisite check for frontend E2E.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VERSIONS_FILE="$PROJECT_ROOT/config/tool-versions.env"

usage() {
  echo "Usage: $(basename "$0") apps/svelte-admin|apps/svelte-desktop" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi

WORKSPACE_PATH="$1"
case "$WORKSPACE_PATH" in
  apps/svelte-admin|apps/svelte-desktop) ;;
  *)
    echo "error: unsupported frontend workspace: $WORKSPACE_PATH" >&2
    usage
    exit 64
    ;;
esac

[[ -f "$VERSIONS_FILE" ]] || {
  echo "error: missing source-owned tool versions: $VERSIONS_FILE" >&2
  exit 1
}

EXPECTED_PLAYWRIGHT_VERSION="$(sed -n 's/^PLAYWRIGHT_VERSION="\([^"]*\)"$/\1/p' "$VERSIONS_FILE")"
if [[ -z "$EXPECTED_PLAYWRIGHT_VERSION" ]]; then
  echo "error: PLAYWRIGHT_VERSION is missing from $VERSIONS_FILE" >&2
  exit 1
fi

WORKSPACE_ROOT="$PROJECT_ROOT/$WORKSPACE_PATH"
cd "$WORKSPACE_ROOT"

if ! command -v bun >/dev/null 2>&1; then
  echo "E2E_BROWSER_STATUS=UNAVAILABLE"
  echo "E2E_BROWSER_REASON=bun is unavailable"
  exit 2
fi

set +e
PLAYWRIGHT_CLI_VERSION="$(bunx playwright --version 2>/dev/null)"
PLAYWRIGHT_CLI_STATUS=$?
set -e
EXPECTED_CLI_VERSION="Version $EXPECTED_PLAYWRIGHT_VERSION"
if [[ "$PLAYWRIGHT_CLI_STATUS" -ne 0 ]]; then
  echo "E2E_BROWSER_STATUS=UNAVAILABLE"
  echo "E2E_BROWSER_REASON=Playwright CLI is unavailable"
  echo "E2E_BROWSER_INSTALL=cd $WORKSPACE_PATH && bun run test:e2e:install"
  exit 2
fi
if [[ "$PLAYWRIGHT_CLI_VERSION" != "$EXPECTED_CLI_VERSION" ]]; then
  echo "E2E_BROWSER_STATUS=FAIL"
  echo "E2E_BROWSER_REASON=Playwright version mismatch: expected $EXPECTED_CLI_VERSION, got $PLAYWRIGHT_CLI_VERSION"
  exit 1
fi

set +e
bun -e 'import { chromium } from "@playwright/test"; const browser = await chromium.launch({ headless: true, channel: "chromium" }); await browser.close()' >/dev/null 2>&1
PLAYWRIGHT_LAUNCH_STATUS=$?
set -e
if [[ "$PLAYWRIGHT_LAUNCH_STATUS" -ne 0 ]]; then
  echo "E2E_BROWSER_STATUS=UNAVAILABLE"
  echo "E2E_BROWSER_VERSION=$EXPECTED_PLAYWRIGHT_VERSION"
  echo "E2E_BROWSER_PROBE=headless-chromium-launch"
  echo "E2E_BROWSER_REASON=Playwright headless Chromium launch failed"
  echo "E2E_BROWSER_INSTALL=cd $WORKSPACE_PATH && bun run test:e2e:install"
  exit 2
fi

echo "E2E_BROWSER_STATUS=PASS"
echo "E2E_BROWSER_VERSION=$EXPECTED_PLAYWRIGHT_VERSION"
echo "E2E_BROWSER_PROBE=headless-chromium-launch"
