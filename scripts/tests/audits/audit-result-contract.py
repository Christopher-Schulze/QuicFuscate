#!/usr/bin/env python3
"""Resolve the comprehensive audit status and blocking exit contract."""

from __future__ import annotations

import argparse
import json
import sys


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def resolve_status(critical: int, failures: int, unavailable: int) -> tuple[str, str]:
    if critical > 0 or failures > 0:
        return "FAIL", "critical findings or failed checks present"
    if unavailable > 0:
        return "UNAVAILABLE", "one or more required checks were unavailable"
    return "PASS", "all required checks completed without failures"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("strict", "advisory"), required=True)
    parser.add_argument("--critical", type=non_negative_int, required=True)
    parser.add_argument("--check-failures", type=non_negative_int, required=True)
    parser.add_argument("--unavailable", type=non_negative_int, required=True)
    parser.add_argument("--warnings", type=non_negative_int, default=0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    status, reason = resolve_status(args.critical, args.check_failures, args.unavailable)
    blocking = args.mode == "strict" and status != "PASS"
    report = {
        "schema": "quicfuscate.audit-result-contract.v1",
        "mode": args.mode,
        "status": status,
        "blocking": blocking,
        "exit_code": 1 if blocking else 0,
        "critical_issues": args.critical,
        "check_failures": args.check_failures,
        "unavailable_checks": args.unavailable,
        "warnings": args.warnings,
        "reason": reason,
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
