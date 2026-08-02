#!/usr/bin/env bash
# Description: Shared fail-closed profiling evidence helpers.

profile_now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

profile_shell_command() {
  local command_text=""
  local arg
  for arg in "$@"; do
    command_text+=" $(printf '%q' "$arg")"
  done
  printf '%s' "${command_text# }"
}

profile_command_json() {
  python3 - "$@" <<'PY'
import json
import os
import sys

environment = {
    name: os.environ[name]
    for name in (
        "RUSTFLAGS",
        "RUSTFLAGS_EXTRA",
        "CARGO_FEATURES",
        "CARGO_TARGET_DIR",
        "JOBS",
        "CARGO_BUILD_JOBS",
        "QUICFUSCATE_ARTIFACT_POLICY",
    )
    if name in os.environ
}
print(json.dumps({"argv": sys.argv[1:], "environment": environment}, ensure_ascii=False, separators=(",", ":")))
PY
}

profile_command_bundle_json() {
  python3 - "$@" <<'PY'
import json
import os
import sys

environment = {
    name: os.environ[name]
    for name in (
        "RUSTFLAGS",
        "RUSTFLAGS_EXTRA",
        "CARGO_FEATURES",
        "CARGO_TARGET_DIR",
        "JOBS",
        "CARGO_BUILD_JOBS",
        "QUICFUSCATE_ARTIFACT_POLICY",
    )
    if name in os.environ
}
commands = []
for item in sys.argv[1:]:
    label, raw_command = item.split("=", 1)
    command = json.loads(raw_command)
    if not isinstance(command, dict) or not isinstance(command.get("argv"), list):
        raise SystemExit(f"invalid structured command for {label}")
    commands.append({
        "label": label,
        "argv": command["argv"],
        "environment": environment,
    })
print(json.dumps({"commands": commands}, ensure_ascii=False, separators=(",", ":")))
PY
}

profile_sha256_file() {
  local path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    printf '%s' "unavailable"
  fi
}

profile_git_revision() {
  local root="$1"
  git -C "$root" rev-parse HEAD 2>/dev/null || printf '%s' "unknown"
}

profile_command_path() {
  command -v "$1" 2>/dev/null || true
}

profile_pairs_json() {
  python3 - "$@" <<'PY'
import json
import sys

result = {}
for item in sys.argv[1:]:
    key, value = item.split("=", 1)
    result[key] = value
print(json.dumps(result, sort_keys=True))
PY
}

profile_typed_pairs_json() {
  python3 - "$@" <<'PY'
import json
import sys

result = {}
for item in sys.argv[1:]:
    key, raw_value = item.split("=", 1)
    if raw_value.startswith("bool:"):
        result[key] = raw_value[5:].lower() == "true"
    elif raw_value.startswith("int:"):
        result[key] = int(raw_value[4:])
    elif raw_value == "null":
        result[key] = None
    else:
        result[key] = raw_value
print(json.dumps(result, sort_keys=True))
PY
}

profile_tool_versions_json() {
  python3 - "$@" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

version_args = {
    "curl": ["--version"],
    "iperf3": ["--version"],
    "perf": ["--version"],
    "python3": ["--version"],
    "tc": ["-V"],
}
result = {}
for item in sys.argv[1:]:
    name, path = item.split("=", 1)
    if not path:
        result[name] = "missing"
        continue
    if name in version_args:
        try:
            completed = subprocess.run(
                [path, *version_args[name]],
                check=False,
                capture_output=True,
                text=True,
            )
            output = (completed.stdout or completed.stderr).splitlines()
            result[name] = output[0] if output else f"exit={completed.returncode}"
        except OSError as error:
            result[name] = f"unavailable: {error}"
        continue
    try:
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        result[name] = f"sha256:{digest}"
    except OSError as error:
        result[name] = f"unavailable: {error}"
print(json.dumps(result, sort_keys=True))
PY
}

profile_iperf_metrics_json() {
  local json_file="$1"
  python3 - "$json_file" <<'PY'
import json
import math
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
end = data.get("end") or {}
sum_received = end.get("sum_received") or {}
sum_sent = end.get("sum_sent") or {}
bits_per_second = sum_received.get("bits_per_second") or sum_sent.get("bits_per_second")
seconds = end.get("sum_received", {}).get("seconds") or end.get("sum_sent", {}).get("seconds")
if not isinstance(bits_per_second, (int, float)) or not math.isfinite(bits_per_second) or bits_per_second <= 0:
    raise SystemExit("iperf JSON has no positive received or sent bitrate")
if not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= 0:
    raise SystemExit("iperf JSON has no positive measured duration")
print(json.dumps({
    "throughput_mbps": round(bits_per_second / 1_000_000, 6),
    "duration_sec": round(seconds, 6),
    "source": "iperf3_json",
}))
PY
}

profile_telemetry_zc_json() {
  local server_file="$1"
  local client_file="$2"
  python3 - "$server_file" "$client_file" <<'PY'
import json
import re
import sys
from pathlib import Path

pattern = re.compile(r"^quicfuscate_io_uring_zc_(sends|notifs)_total\s+([0-9]+(?:\.[0-9]+)?)\s*$")
result = {}
for name, raw_path in zip(("server", "client"), sys.argv[1:]):
    path = Path(raw_path)
    values = {"sends": 0.0, "notifs": 0.0}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            match = pattern.match(line)
            if match:
                values[match.group(1)] = float(match.group(2))
    result[name] = values

sends = sum(values["sends"] for values in result.values())
notifs = sum(values["notifs"] for values in result.values())
for name, values in result.items():
    if values["sends"] <= 0 or values["notifs"] <= 0:
        raise SystemExit(f"{name} telemetry has no positive SendMsgZc sends and notifications")
if sends <= 0 or notifs <= 0:
    raise SystemExit("telemetry has no positive SendMsgZc sends and notifications")
print(json.dumps({
    "status": "PASS",
    "complete": True,
    "sends_total": int(sends),
    "notifs_total": int(notifs),
    "endpoints": result,
}, sort_keys=True))
PY
}

profile_write_scenario() {
  local output_file="$1"
  shift
  python3 - "$output_file" "$@" <<'PY'
import json
import os
import sys
from pathlib import Path


def nested(raw: str, name: str):
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise SystemExit(f"invalid {name} JSON: {error}") from error


(
    output_file,
    runner,
    scenario,
    title,
    result,
    reason,
    command,
    source_revision,
    executable_sha256,
    host,
    kernel,
    tool_versions,
    prerequisites,
    readiness,
    process,
    perf,
    flamegraph,
    metrics,
    cleanup,
    started_at,
    finished_at,
) = sys.argv[1:]

if result not in {"PASS", "FAIL", "SKIP", "UNAVAILABLE"}:
    raise SystemExit(f"invalid profiling result: {result}")

readiness_document = nested(readiness, "readiness")
perf_document = nested(perf, "perf")
flamegraph_document = nested(flamegraph, "flamegraph")
metrics_document = nested(metrics, "metrics")
cleanup_document = nested(cleanup, "cleanup")
command_document = nested(command, "command")
if not isinstance(command_document, dict):
    raise SystemExit("command evidence must be a structured object")
if "argv" not in command_document and "commands" not in command_document:
    raise SystemExit("command evidence must contain argv or commands")
if result == "PASS":
    required = {
        "readiness": readiness_document.get("status") == "PASS",
        "perf": perf_document.get("status") == "PASS",
        "flamegraph": flamegraph_document.get("status") == "PASS",
        "metrics": metrics_document.get("complete") is True,
        "cleanup": cleanup_document.get("status") == "PASS",
    }
    missing = [name for name, valid in required.items() if not valid]
    if missing:
        raise SystemExit(f"PASS scenario is incomplete: {', '.join(missing)}")

document = {
    "schema_version": 1,
    "runner": runner,
    "scenario": scenario,
    "title": title,
    "result": result,
    "reason": reason,
    "command": command_document,
    "provenance": {
        "source_revision": source_revision,
        "executable_sha256": executable_sha256,
        "host": host,
        "kernel": kernel,
        "tool_versions": nested(tool_versions, "tool_versions"),
    },
    "prerequisites": nested(prerequisites, "prerequisites"),
    "readiness": readiness_document,
    "process": nested(process, "process"),
    "perf": perf_document,
    "flamegraph": flamegraph_document,
    "metrics": metrics_document,
    "cleanup": cleanup_document,
    "started_at": started_at,
    "finished_at": finished_at,
}

if "N/A" in json.dumps(document, ensure_ascii=False):
    raise SystemExit("profiling evidence cannot contain N/A markers")

payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
try:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output_file, flags, 0o600)
except FileExistsError as error:
    raise SystemExit(f"refusing to overwrite existing profiling artifact: {output_file}") from error
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    handle.write(payload)
PY
}

profile_write_manifest() {
  local output_file="$1"
  shift
  python3 - "$output_file" "$@" <<'PY'
import json
import os
import sys
from collections import Counter
from pathlib import Path


(
    output_file,
    runner,
    output_root,
    source_revision,
    executable_sha256,
    host,
    kernel,
    tool_versions,
    prerequisites,
    generated_at,
    *scenario_files,
) = sys.argv[1:]

scenarios = []
for scenario_file in scenario_files:
    scenarios.append(json.loads(Path(scenario_file).read_text(encoding="utf-8")))

counts = Counter(item["result"] for item in scenarios)
manifest = {
    "schema_version": 1,
    "runner": runner,
    "output_root": output_root,
    "generated_at": generated_at,
    "provenance": {
        "source_revision": source_revision,
        "executable_sha256": executable_sha256,
        "host": host,
        "kernel": kernel,
        "tool_versions": json.loads(tool_versions),
    },
    "prerequisites": json.loads(prerequisites),
    "summary": {
        "scenario_count": len(scenarios),
        "results": dict(sorted(counts.items())),
    },
    "scenarios": scenarios,
}
payload = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
try:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output_file, flags, 0o600)
except FileExistsError as error:
    raise SystemExit(f"refusing to overwrite existing profiling artifact: {output_file}") from error
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    handle.write(payload)
PY
}

profile_pid_alive() {
  kill -0 "$1" 2>/dev/null
}

profile_wait_for_pid_alive() {
  local pid="$1"
  local timeout_secs="$2"
  local deadline=$((SECONDS + timeout_secs))
  while (( SECONDS < deadline )); do
    if profile_pid_alive "$pid"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

profile_wait_for_pid_exit() {
  local pid="$1"
  local timeout_secs="$2"
  local deadline=$((SECONDS + timeout_secs))
  while profile_pid_alive "$pid"; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
  return 0
}

profile_wait_for_log_pattern() {
  local log_file="$1"
  local pattern="$2"
  local timeout_secs="$3"
  local deadline=$((SECONDS + timeout_secs))
  while (( SECONDS < deadline )); do
    if [[ -s "$log_file" ]] && grep -Eq -- "$pattern" "$log_file"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

profile_wait_status() {
  local pid="$1"
  local status=0
  if wait "$pid"; then
    status=0
  else
    status=$?
  fi
  # shellcheck disable=SC2034
  PROFILE_LAST_WAIT_STATUS="$status"
  return 0
}

profile_stop_pid() {
  local pid="$1"
  local cleanup_status=0
  local wait_status=0
  if profile_pid_alive "$pid"; then
    if ! kill -TERM "$pid" 2>/dev/null; then
      cleanup_status=1
    fi
  fi
  if [[ -d "/proc/$pid" || -n "${ZSH_VERSION:-}" || -n "${BASH_VERSION:-}" ]]; then
    profile_wait_status "$pid"
    wait_status="$PROFILE_LAST_WAIT_STATUS"
    if [[ "$wait_status" -ne 0 && "$wait_status" -ne 143 && "$wait_status" -ne 15 ]]; then
      cleanup_status=1
    fi
  fi
  # The caller reads both values in the parent shell after this direct call.
  # shellcheck disable=SC2034
  PROFILE_LAST_WAIT_STATUS="$wait_status"
  # shellcheck disable=SC2034
  PROFILE_LAST_CLEANUP_STATUS="$cleanup_status"
  return "$cleanup_status"
}

profile_generate_flamegraph() {
  local perf_path="$1"
  local stackcollapse_path="$2"
  local flamegraph_path="$3"
  local perf_data="$4"
  local output_svg="$5"
  local title="$6"
  local output_log="$7"
  if "$perf_path" script -i "$perf_data" 2>"$output_log" | \
      "$stackcollapse_path" 2>>"$output_log" | \
      "$flamegraph_path" --title "$title" --width 1200 >>"$output_svg" 2>>"$output_log"; then
    [[ -s "$output_svg" ]]
  else
    return 1
  fi
}

profile_csv_field() {
  local value="$1"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}
