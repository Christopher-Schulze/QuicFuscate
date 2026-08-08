#!/usr/bin/env bash
# Description: Shell portability gate for utility and installer scripts.
#
# macOS ships Bash 3.2 as /bin/bash, so `env bash` resolves to it on a host without a
# newer Bash installed. Bash 4 builtins such as `mapfile` abort those scripts before
# they do any work. This gate parses every shipped script with the oldest supported
# interpreter and rejects the builtins that are not available there.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${PROJECT_ROOT}"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR]"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
  shift
done
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/smoke/$(basename "$0" .sh)-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Scripts that are Linux-only by definition may use GNU-only builtins; everything a
# macOS operator can run must not.
LINUX_ONLY_PATTERN='scripts/tests/suites/test-linux-installer(-guest)?\.sh$'

FAILURES=0
CHECKED=0

# Bash 4 builtins with no Bash 3.2 equivalent.
BANNED_BUILTINS='(^|[^[:alnum:]_])(mapfile|readarray)[[:space:]]'

while IFS= read -r script; do
  [[ "$script" =~ $LINUX_ONLY_PATTERN ]] && continue
  CHECKED=$((CHECKED + 1))

  # Strip comments before scanning, so documenting the hazard is not itself a hit.
  if sed 's/#.*$//' "$script" | grep -qE "$BANNED_BUILTINS"; then
    echo "[FAIL] ${script}: uses a Bash 4 builtin unavailable in macOS Bash 3.2" >&2
    FAILURES=$((FAILURES + 1))
  fi
done < <(find scripts -type f -name '*.sh' -not -path '*/out/*' | sort)

echo "scanned ${CHECKED} scripts for Bash 4 builtins"

# The two utilities named by TODO-745 must actually run under the old interpreter,
# not merely parse.
if [[ -x /bin/bash ]]; then
  for utility in \
    "scripts/utils/util-cleanup-workspace.sh --help" \
    "scripts/utils/util-check-quality.sh --help" \
    "scripts/install/setup-netfilter-fastpath.sh --dry-run"
  do
    # shellcheck disable=SC2086
    if ! /bin/bash $utility > "$OUTPUT_DIR/$(basename "${utility%% *}").log" 2>&1; then
      echo "[FAIL] ${utility} failed under /bin/bash $(/bin/bash --version | head -1)" >&2
      FAILURES=$((FAILURES + 1))
    fi
  done
else
  echo "note: /bin/bash is absent; the interpreter run was skipped"
fi

if ((FAILURES)); then
  echo "[FAIL] ${FAILURES} portability violation(s)" >&2
  exit 1
fi
echo "[OK] shell portability holds"
