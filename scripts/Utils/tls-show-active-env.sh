#!/usr/bin/env bash
# Description: Show current TLS/Stealth env overrides that map into StealthConfig.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"; cd "$ROOT" || exit 1

B=${QUICFUSCATE_BROWSER:-Chrome}
O=${QUICFUSCATE_OS:-Windows}
F=${QUICFUSCATE_USE_FAKE_TLS:-0}
D=${QUICFUSCATE_DOH:-1}
FP=${QUICFUSCATE_DOH_PROVIDER:-https://cloudflare-dns.com/dns-query}
FR=${QUICFUSCATE_FRONTING:-1}
Q=${QUICFUSCATE_QPACK:-1}
X=${QUICFUSCATE_XOR:-1}

echo 'Active TLS/Stealth configuration (env overrides -> StealthConfig):'
printf ' - Browser: %q\n' "$B"
printf ' - OS: %q\n' "$O"
printf ' - Use FakeTLS: %q\n' "$F"
printf ' - DoH enabled: %q\n' "$D"
printf ' - DoH provider: %q\n' "$FP"
printf ' - Domain fronting: %q\n' "$FR"
printf ' - QPACK headers: %q\n' "$Q"
printf ' - XOR obfuscation: %q\n' "$X"
echo
echo 'Tip: export QUICFUSCATE_BROWSER/QUICFUSCATE_OS to change the uTLS fingerprint.'
