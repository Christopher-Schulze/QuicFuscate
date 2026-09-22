#!/usr/bin/env bash
# Description: Verify that the browser persona catalog stays fresh and internally coherent (TODO-1009).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

exec python3 - "$PROJECT_ROOT" <<'PY'
from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

MAX_AGE_MONTHS = 6

root = Path(sys.argv[1])
profile_src = (root / "crates/qf-stealth/src/fingerprint_profile.rs").read_text()
cover_src = (root / "crates/qf-stealth/src/tls_cover.rs").read_text()

failures: list[str] = []

# 1. Catalog snapshot marker must exist and be no older than MAX_AGE_MONTHS.
marker = re.search(r'PROFILE_CATALOG_SNAPSHOT:\s*&str\s*=\s*"(\d{4})-(\d{2})"', profile_src)
if marker is None:
    failures.append("PROFILE_CATALOG_SNAPSHOT marker missing from fingerprint_profile.rs")
    snapshot_age = None
else:
    year, month = int(marker.group(1)), int(marker.group(2))
    today = date.today()
    snapshot_age = (today.year - year) * 12 + (today.month - month)
    if snapshot_age > MAX_AGE_MONTHS:
        failures.append(
            f"fingerprint catalog snapshot {year}-{month:02d} is {snapshot_age} months old "
            f"(limit {MAX_AGE_MONTHS}); refresh personas against real browser captures"
        )

# 2. UA version coherence: a partial bump is the classic fingerprint-rot failure.
chrome_majors = set(re.findall(r"Chrome/(\d+)\.", profile_src))
edge_majors = set(re.findall(r"Edg/(\d+)\.", profile_src))
firefox_majors = set(re.findall(r"Firefox/(\d+)\.", profile_src))
rv_majors = set(re.findall(r"rv:(\d+)\.", profile_src))
safari_versions = set(re.findall(r"Version/(\d+)\.", profile_src))
ios_versions = set(re.findall(r"iPhone OS (\d+)_", profile_src))

if len(chrome_majors) != 1:
    failures.append(f"inconsistent Chrome major versions in UA catalog: {sorted(chrome_majors)}")
if edge_majors and edge_majors != chrome_majors:
    failures.append(
        f"Edge major {sorted(edge_majors)} diverges from Chrome major {sorted(chrome_majors)}"
    )
if len(firefox_majors) != 1 or rv_majors != firefox_majors:
    failures.append(
        f"inconsistent Firefox majors: Firefox/{sorted(firefox_majors)} vs rv:{sorted(rv_majors)}"
    )
if safari_versions and ios_versions and safari_versions != ios_versions:
    failures.append(
        f"Safari Version/{sorted(safari_versions)} diverges from iOS {sorted(ios_versions)}"
    )

# 3. Synthetic ClientHello entropy guard: the zero hello_random placeholder may
#    only appear inside cfg(test) code. Locate every occurrence and require a
#    preceding `#[cfg(test)]` attribute on the enclosing item, or membership in
#    `mod tests`.
zero_rand_lines = [
    idx for idx, line in enumerate(cover_src.splitlines()) if "[0u8; 32]" in line
]
lines = cover_src.splitlines()
mod_tests_at = next(
    (idx for idx, line in enumerate(lines) if re.search(r"\bmod tests\b", line)),
    len(lines),
)
for idx in zero_rand_lines:
    in_mod_tests = idx > mod_tests_at
    window = "\n".join(lines[max(0, idx - 40) : idx])
    enclosing_fn_test = "#[cfg(test)]" in window
    if not (in_mod_tests or enclosing_fn_test):
        failures.append(
            f"zero hello_random placeholder at tls_cover.rs:{idx + 1} outside cfg(test) code"
        )

# 4. Cover planning still draws per-call entropy, and the synthetic hello builder is gone.
if "rand::rng()" not in cover_src:
    failures.append("plan_tls_cover_record does not draw per-call entropy (rand::rng missing)")
if "key_share_ext" in cover_src or "generate_client_hello" in cover_src or "xorshift" in cover_src:
    failures.append("synthetic ClientHello builder is still present in tls_cover.rs")

if failures:
    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    raise SystemExit(1)

age_note = f", snapshot age {snapshot_age} months" if snapshot_age is not None else ""
print(f"fingerprint freshness contract passed{age_note}")
PY
