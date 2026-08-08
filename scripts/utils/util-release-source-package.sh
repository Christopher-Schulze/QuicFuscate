#!/usr/bin/env bash
# Description: Build a clean source-first release archive (v1) without transient artifacts.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
OUT_ROOT="$ROOT/scripts/out/releases/source"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="$OUT_ROOT/quicfuscate-v1-source-${STAMP}.tar.gz"

usage() {
  cat <<USAGE
Usage: util-release-source-package.sh [--output FILE] [--dry-run]

Creates a clean source archive from the local workspace while excluding transient data.

Options:
  --output FILE   Output tar.gz path (default: scripts/out/releases/source/quicfuscate-v1-source-<ts>.tar.gz)
  --dry-run       Print archive command and exit
  -h, --help      Show this help
USAGE
}

DRY_RUN=0
while (($#)); do
  case "$1" in
    --output)
      OUT_FILE="${2:?missing value for --output}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "$OUT_FILE")"

# The archive is built from the filesystem, not from Git, so being gitignored keeps
# nothing out of it. Local credentials live on disk in exactly the paths below.
EXCLUDES=(
  --exclude=".git"
  --exclude="target"
  --exclude="archive"
  --exclude="scripts/out"
  --exclude="**/node_modules"
  --exclude="**/dist"
  --exclude="**/test-results"
  --exclude="**/.DS_Store"
  --exclude="**/*.log"
  --exclude="tmp"
  # Local runtime state: admin auth stores, QKey registries, dev certificates.
  --exclude="config/local"
  --exclude="**/config/local"
  # The internal task registry was deliberately removed from the public tree and is
  # gitignored, but this archive is built from the filesystem, so it would republish it.
  --exclude="docs/todo"
  --exclude="docs/todo.md"
  # Credential and key material by name, wherever it sits.
  --exclude="**/*.key"
  --exclude="**/*.pem"
  --exclude="**/*.p12"
  --exclude="**/*.pfx"
  --exclude="**/*.jks"
  --exclude="**/*.keystore"
  --exclude="**/.env"
  --exclude="**/.env.*"
  --exclude="**/admin-auth.json"
  --exclude="**/qkeys.json"
  --exclude="**/*.qkeys.json"
  --exclude="**/dev-certs"
  --exclude="**/id_rsa"
  --exclude="**/id_ed25519"
)

# Archive members that must never be published, checked after the archive is built.
# The exclusion list above is the intent; this is the proof, because a mistyped or
# newly added exclusion fails silently and a published secret cannot be recalled.
SENSITIVE_MEMBER_PATTERNS=(
  '(^|/)config/local/'
  '\.key$'
  '\.pem$'
  '\.p12$'
  '\.pfx$'
  '\.jks$'
  '\.keystore$'
  '(^|/)\.env($|\.)'
  '(^|/)admin-auth\.json$'
  'qkeys\.json$'
  '(^|/)dev-certs/'
  '(^|/)id_rsa($|\.)'
  '(^|/)id_ed25519($|\.)'
)

# Paths that legitimately match a sensitive pattern. Each entry must be a test fixture
# whose contents are not real credentials.
APPROVED_MEMBER_PATTERNS=(
)

CMD=(tar -czf "$OUT_FILE" "${EXCLUDES[@]}" -C "$(dirname "$ROOT")" "$(basename "$ROOT")")

if [[ "$DRY_RUN" -eq 1 ]]; then
  printf 'dry-run: '
  printf '%q ' "${CMD[@]}"
  echo
  exit 0
fi

"${CMD[@]}"

MANIFEST="${OUT_FILE}.manifest.txt"
tar -tzf "$OUT_FILE" > "$MANIFEST"

VIOLATIONS=()
while IFS= read -r member; do
  for pattern in "${SENSITIVE_MEMBER_PATTERNS[@]}"; do
    if [[ "$member" =~ $pattern ]]; then
      approved=0
      for allow in "${APPROVED_MEMBER_PATTERNS[@]}"; do
        if [[ -n "$allow" && "$member" =~ $allow ]]; then
          approved=1
          break
        fi
      done
      (( approved )) || VIOLATIONS+=("$member")
      break
    fi
  done
done < "$MANIFEST"

# Name-based exclusion cannot see a private key stored under an innocuous name, so the
# contents are checked too.
if tar -xzOf "$OUT_FILE" 2>/dev/null | grep -qE '^-----BEGIN [A-Z ]*PRIVATE KEY-----'; then
  VIOLATIONS+=("<private key material found in archive contents>")
fi

if ((${#VIOLATIONS[@]})); then
  echo "error: refusing to publish an archive containing sensitive material:" >&2
  printf '  %s\n' "${VIOLATIONS[@]}" >&2
  rm -f "$OUT_FILE"
  echo "removed $OUT_FILE; manifest retained at $MANIFEST" >&2
  exit 1
fi

echo "archive gate: $(wc -l < "$MANIFEST" | tr -d ' ') members, no sensitive paths or key material"

SIZE="$(du -h "$OUT_FILE" | awk '{print $1}')"
echo "source package created: $OUT_FILE ($SIZE)"
