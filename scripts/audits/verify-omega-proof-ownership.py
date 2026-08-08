#!/usr/bin/env python3
"""Fail-closed, read-only preflight for an exact Omega proof boundary.

The preflight never resets a checkout, removes a candidate, stops a process, or
writes to the remote host. It makes ambiguous checkout, Git, runtime, and proof
artifact state explicit as ``UNAVAILABLE`` instead of allowing a local caller to
claim an exact remote proof from an unattributable environment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import posixpath
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "quicfuscate.omega-proof-ownership.v1"
DEFAULT_SEARCH_ROOTS = ("/home/ubuntu/SOFTWARE", "/home/ubuntu/CODE")
DEFAULT_PROCESS_PATTERN = r"(?i)(?:^|/)quicfuscate(?:$|[\s/])"
MAX_EVIDENCE_LINES = 32


@dataclass(frozen=True)
class RemoteResult:
    exit_code: int
    stdout: str
    stderr: str


class PreflightError(ValueError):
    """Invalid local preflight input that cannot produce an evidence result."""


class RemoteRunner:
    def __init__(self, host: str, timeout_seconds: float) -> None:
        if not host.strip():
            raise PreflightError("remote host must not be empty")
        if timeout_seconds <= 0:
            raise PreflightError("remote command timeout must be positive")
        self.host = host
        self.timeout_seconds = timeout_seconds

    def run(self, *args: str) -> RemoteResult:
        remote_command = " ".join(shlex.quote(argument) for argument in args)
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            self.host,
            remote_command,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode() if isinstance(error.stdout, bytes) else (error.stdout or "")
            stderr = error.stderr.decode() if isinstance(error.stderr, bytes) else (error.stderr or "")
            return RemoteResult(124, stdout, f"remote command timed out: {stderr}".strip())
        except OSError as error:
            return RemoteResult(127, "", str(error))
        return RemoteResult(result.returncode, result.stdout.strip(), result.stderr.strip())


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def normalize_remote_path(value: str) -> str:
    if not value.startswith("/"):
        raise PreflightError(f"remote path must be absolute: {value!r}")
    normalized = posixpath.normpath(value)
    if ".." in normalized.split("/"):
        raise PreflightError(f"remote path may not contain parent traversal: {value!r}")
    return normalized


def lines(value: str) -> list[str]:
    return [line for line in value.splitlines() if line]


def bounded_lines(value: str) -> list[str]:
    return lines(value)[:MAX_EVIDENCE_LINES]


def result_record(result: RemoteResult) -> dict[str, Any]:
    return {
        "exit_code": result.exit_code,
        "stdout_lines": bounded_lines(result.stdout),
        "stderr_lines": bounded_lines(result.stderr),
    }


def command_ok(result: RemoteResult) -> bool:
    return result.exit_code == 0


def under(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def inspect_checkout(remote: RemoteRunner, path: str) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": path,
        "exists": False,
        "git": {},
        "status": {},
        "diff": {},
        "object_check": {},
    }
    exists = remote.run("test", "-d", path)
    info["exists"] = command_ok(exists)
    info["exists_check"] = result_record(exists)
    if not info["exists"]:
        return info

    git_root = remote.run("git", "-C", path, "rev-parse", "--show-toplevel")
    head = remote.run("git", "-C", path, "rev-parse", "HEAD")
    branch = remote.run("git", "-C", path, "branch", "--show-current")
    info["git"] = {
        "root": git_root.stdout if command_ok(git_root) else None,
        "head": head.stdout if command_ok(head) else None,
        "branch": branch.stdout if command_ok(branch) else None,
        "root_check": result_record(git_root),
        "head_check": result_record(head),
        "branch_check": result_record(branch),
    }
    info["git"]["root_matches_selected"] = command_ok(git_root) and git_root.stdout == path

    status = remote.run(
        "git",
        "-C",
        path,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    tracked_status = remote.run(
        "git",
        "-C",
        path,
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
    )
    status_lines = lines(status.stdout)
    tracked_status_lines = lines(tracked_status.stdout)
    info["status"] = {
        "all_exit_code": status.exit_code,
        "all_count": len(status_lines),
        "all_sample": status_lines[:MAX_EVIDENCE_LINES],
        "tracked_exit_code": tracked_status.exit_code,
        "tracked_count": len(tracked_status_lines),
        "tracked_sample": tracked_status_lines[:MAX_EVIDENCE_LINES],
        "stderr_lines": bounded_lines(status.stderr or tracked_status.stderr),
    }

    diff = remote.run("git", "-C", path, "diff", "--name-only")
    cached_diff = remote.run("git", "-C", path, "diff", "--cached", "--name-only")
    info["diff"] = {
        "working_tree": {
            "exit_code": diff.exit_code,
            "count": len(lines(diff.stdout)),
            "sample": bounded_lines(diff.stdout),
            "stderr_lines": bounded_lines(diff.stderr),
        },
        "index": {
            "exit_code": cached_diff.exit_code,
            "count": len(lines(cached_diff.stdout)),
            "sample": bounded_lines(cached_diff.stdout),
            "stderr_lines": bounded_lines(cached_diff.stderr),
        },
    }

    object_check = remote.run(
        "git",
        "-C",
        path,
        "fsck",
        "--full",
        "--connectivity-only",
        "--no-progress",
    )
    info["object_check"] = result_record(object_check)
    return info


def discover_checkouts(remote: RemoteRunner, roots: Sequence[str]) -> tuple[list[str], list[dict[str, Any]]]:
    candidates: set[str] = set()
    checks: list[dict[str, Any]] = []
    for root in roots:
        result = remote.run("find", root, "-maxdepth", "2", "-type", "d", "-name", "QuicFuscate", "-print")
        found = [normalize_remote_path(item) for item in lines(result.stdout)]
        candidates.update(found)
        checks.append({"root": root, "result": result_record(result), "found": found})
    return sorted(candidates), checks


def inspect_processes(remote: RemoteRunner, process_pattern: str) -> dict[str, Any]:
    result = remote.run("ps", "-eo", "pid=,args=")
    matcher = re.compile(process_pattern)
    matches: list[dict[str, Any]] = []
    for line in lines(result.stdout):
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if match is None or matcher.search(match.group(2)) is None:
            continue
        command = match.group(2)
        first_token = command.split(maxsplit=1)[0]
        matches.append(
            {
                "pid": int(match.group(1)),
                "executable": first_token,
                "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
            }
        )
    return {
        "pattern": process_pattern,
        "check": result_record(result),
        "matches": matches,
    }


def hash_binaries(remote: RemoteRunner, paths: Sequence[str]) -> tuple[list[dict[str, Any]], list[str]]:
    hashes: list[dict[str, Any]] = []
    reasons: list[str] = []
    for path in paths:
        result = remote.run("sha256sum", "--", path)
        record: dict[str, Any] = {"path": path, "check": result_record(result)}
        if command_ok(result) and lines(result.stdout):
            fields = lines(result.stdout)[0].split()
            if len(fields) >= 2:
                record["sha256"] = fields[0]
            else:
                reasons.append(f"binary_hash_unparseable:{path}")
        else:
            reasons.append(f"binary_hash_unavailable:{path}")
        hashes.append(record)
    return hashes, reasons


def write_new(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(payload)
    except FileExistsError as error:
        raise PreflightError(f"refusing to overwrite existing evidence: {path}") from error


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    remote = RemoteRunner(args.host, args.remote_timeout_seconds)
    checkout = normalize_remote_path(args.checkout)
    search_roots = [normalize_remote_path(root) for root in (args.search_root or DEFAULT_SEARCH_ROOTS)]
    binary_paths = [normalize_remote_path(path) for path in args.binary]

    candidates, discovery_checks = discover_checkouts(remote, search_roots)
    checkout_infos = [inspect_checkout(remote, path) for path in candidates]
    selected = next((info for info in checkout_infos if info["path"] == checkout), None)
    processes = inspect_processes(remote, args.process_pattern)

    reasons: list[str] = []
    for check in discovery_checks:
        if check["result"]["exit_code"] != 0:
            reasons.append(f"checkout_discovery_unavailable:{check['root']}")
    if checkout not in candidates:
        reasons.append("selected_checkout_not_discovered")
    if len(candidates) != 1:
        reasons.append(f"ambiguous_checkout_count:{len(candidates)}")
    if selected is None or not selected["exists"]:
        reasons.append("selected_checkout_unavailable")

    for info in checkout_infos:
        path = info["path"]
        status = info.get("status", {})
        if status.get("all_exit_code") != 0:
            reasons.append(f"status_unreadable:{path}")
        elif status.get("all_count", 0):
            reasons.append(f"dirty_checkout:{path}:{status['all_count']}")
        object_check = info.get("object_check", {})
        if object_check.get("exit_code") != 0:
            reasons.append(f"unreadable_object_database:{path}")
        if not info.get("git", {}).get("root_matches_selected", False):
            reasons.append(f"checkout_root_mismatch:{path}")
        diff = info.get("diff", {})
        for scope in ("working_tree", "index"):
            if diff.get(scope, {}).get("exit_code") != 0:
                reasons.append(f"unreadable_{scope}_diff:{path}")

    source_revision = selected.get("git", {}).get("head") if selected else None
    if not args.expected_revision:
        reasons.append("expected_source_revision_not_bound")
    elif source_revision != args.expected_revision:
        reasons.append("source_revision_mismatch")
    if not args.bundle_revision:
        reasons.append("bundle_revision_not_bound")
    if not binary_paths:
        reasons.append("binary_hashes_not_bound")
    if not args.evidence_root:
        reasons.append("evidence_root_not_bound")

    binary_hashes, binary_reasons = hash_binaries(remote, binary_paths)
    reasons.extend(binary_reasons)

    runtime_matches = processes["matches"]
    if processes["check"]["exit_code"] != 0:
        reasons.append("process_inspection_unavailable")
    owned_pid = args.owned_runtime_pid
    if runtime_matches:
        if owned_pid is None:
            reasons.append("unrelated_runtime_processes_present")
        else:
            owned = [item for item in runtime_matches if item["pid"] == owned_pid]
            unexpected = [item for item in runtime_matches if item["pid"] != owned_pid]
            if not owned:
                reasons.append("declared_runtime_pid_not_present")
            if unexpected:
                reasons.append("additional_runtime_processes_present")
            if owned and selected and not under(owned[0]["executable"], checkout):
                reasons.append("runtime_executable_outside_selected_checkout")
    elif owned_pid is not None:
        reasons.append("declared_runtime_pid_not_present")

    evidence_root = args.evidence_root
    report = {
        "schema": SCHEMA,
        "generated_at_utc": utc_now(),
        "status": "PASS" if not reasons else "UNAVAILABLE",
        "remote": {
            "host": args.host,
            "search_roots": search_roots,
            "discovery": discovery_checks,
            "candidate_checkouts": candidates,
            "selected_checkout": checkout,
            "checkouts": checkout_infos,
            "processes": processes,
        },
        "proof_binding": {
            "source_revision": source_revision,
            "bundle_revision": args.bundle_revision,
            "binary_hashes": binary_hashes,
            "runtime_pids": [item["pid"] for item in runtime_matches],
            "owned_runtime_pid": owned_pid,
            "evidence_root": evidence_root,
        },
        "reasons": sorted(set(reasons)),
        "mutation_policy": {
            "remote_writes": False,
            "remote_process_control": False,
            "remote_checkout_cleanup": False,
        },
    }
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="omega", help="SSH host alias")
    parser.add_argument("--remote-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--checkout", required=True, help="selected remote checkout path")
    parser.add_argument("--search-root", action="append", help="remote root to search; repeatable")
    parser.add_argument("--expected-revision", help="required selected HEAD revision")
    parser.add_argument("--bundle-revision", help="release/source bundle revision bound to the proof")
    parser.add_argument("--binary", action="append", default=[], help="remote proof binary to hash; repeatable")
    parser.add_argument("--owned-runtime-pid", type=int, help="runtime PID explicitly owned by this proof")
    parser.add_argument("--evidence-root", help="evidence root bound to the proof")
    parser.add_argument("--process-pattern", default=DEFAULT_PROCESS_PATTERN)
    parser.add_argument("--json-out", type=Path, help="new local JSON report; existing files are never overwritten")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if not math.isfinite(args.remote_timeout_seconds) or args.remote_timeout_seconds <= 0:
        parser.error("--remote-timeout-seconds must be a finite positive number")
    try:
        re.compile(args.process_pattern)
    except re.error as error:
        parser.error(f"invalid --process-pattern: {error}")
    return args


def main() -> int:
    args = parse_args()
    try:
        report = build_report(args)
        payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.json_out:
            output = args.json_out if args.json_out.is_absolute() else args.project_root.resolve() / args.json_out
            write_new(output, payload)
            display = output
            try:
                display = output.relative_to(args.project_root.resolve())
            except ValueError:
                pass
            print(f"OMEGA_PROOF_OWNERSHIP_REPORT={display}")
        else:
            print(payload, end="")
        print(f"OMEGA_PROOF_OWNERSHIP_STATUS={report['status']}")
        if report["reasons"]:
            print("OMEGA_PROOF_OWNERSHIP_REASONS=" + ",".join(report["reasons"]))
        return 0 if report["status"] == "PASS" else 2
    except (PreflightError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
