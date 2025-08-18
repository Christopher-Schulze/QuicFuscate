#!/usr/bin/env bash
# Description: Diff TLS profiles (env A vs B)

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1

A=${QUICFUSCATE_DIFF_A:-}
B=${QUICFUSCATE_DIFF_B:-}
if [ -z "$B" ]; then echo 'Set QUICFUSCATE_DIFF_B=browser_os (e.g., firefox_linux)'; exit 2; fi
if [ -z "$A" ]; then
  B1=${QUICFUSCATE_BROWSER:-Chrome}
  O1=${QUICFUSCATE_OS:-Windows}
  A=$(echo "$B1" | tr 'A-Z' 'a-z')_$(echo "$O1" | tr 'A-Z' 'a-z')
fi
A_b=${A%%_*}; A_o=${A#*_}
B_b=${B%%_*}; B_o=${B#*_}

if base64 --help 2>&1 | grep -q '\-d'; then DEC='-d'; else DEC='-D'; fi

tmpA=$(mktemp)
tmpB=$(mktemp)
foundA=0; foundB=0
for d in browser_profiles src/browser_profiles; do
  f="$d/${A_b}_${A_o}.chlo"
  if [ -f "$f" ]; then base64 $DEC < "$f" > "$tmpA"; foundA=1; break; fi
done
for d in browser_profiles src/browser_profiles; do
  f="$d/${B_b}_${B_o}.chlo"
  if [ -f "$f" ]; then base64 $DEC < "$f" > "$tmpB"; foundB=1; break; fi
done
if [ "$foundA" = 0 ] || [ "$foundB" = 0 ]; then echo 'Profile(s) not found.'; rm -f "$tmpA" "$tmpB"; exit 3; fi

echo "[A] $A  size=$(wc -c < "$tmpA")"
echo "[B] $B  size=$(wc -c < "$tmpB")"
if cmp -s "$tmpA" "$tmpB"; then
  echo 'Profiles identical.'
else
  echo 'Profiles differ.'
  cmp -l "$tmpA" "$tmpB" | head -n 10 || true
fi
hexdump -C -n 64 "$tmpA" | sed 's/^/[A] /'
hexdump -C -n 64 "$tmpB" | sed 's/^/[B] /'
rm -f "$tmpA" "$tmpB"
