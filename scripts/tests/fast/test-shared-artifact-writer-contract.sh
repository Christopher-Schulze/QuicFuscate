#!/usr/bin/env bash
# Description: Contract test for shared JSON serialization and artifact ownership.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/../lib/lib-common.sh"
# shellcheck disable=SC1091
source "$PROJECT_ROOT/scripts/benchmarks/profiling-common.sh"

TMP_ROOT="$(mktemp -d /tmp/quicfuscate-shared-artifact-contract.XXXXXX)"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

OUTPUT_DIR="$TMP_ROOT/output with spaces Ω"
mkdir -p "$OUTPUT_DIR"
RESULTS_JSON="$OUTPUT_DIR/results.json"
JSON="$RESULTS_JSON"
export RUSTFLAGS='-C target-cpu=native --quoted'
SPECIAL=$'line with "quotes" \\\\ slash\nand Ω'

json_begin "$RESULTS_JSON" 'suite "quoted" Ω'
JSON_FIRST_RUN=1
run printf '%s\n' "$SPECIAL"
qf_json_append_object "$RESULTS_JSON" \
  "detail=$SPECIAL" \
  'nested=json:{"message":"line\\nΩ"}'
json_end "$RESULTS_JSON"

python3 - "$RESULTS_JSON" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["suite"] == 'suite "quoted" Ω', document
assert document["artifact"]["ownership"] == "create-new", document
assert len(document["items"]) == 2, document
assert document["items"][0]["argv"][:2] == ["printf", "%s\\n"], document
assert document["items"][0]["argv"][2].endswith("Ω"), document
assert document["items"][0]["environment"]["RUSTFLAGS"] == "-C target-cpu=native --quoted", document
assert "command" not in document["items"][0], document
assert "quotes" in document["items"][1]["detail"], document
assert document["items"][1]["nested"]["message"] == "line\\nΩ", document
PY

RESULTS_HASH="$(shasum -a 256 "$RESULTS_JSON" | awk '{print $1}')"
if env -u QUICFUSCATE_ARTIFACT_POLICY bash -c \
  'set -Eeuo pipefail; source "$1"; json_begin "$2" rerun; json_end "$2"' \
  _ "$PROJECT_ROOT/scripts/tests/lib/lib-common.sh" "$RESULTS_JSON"; then
  echo "default rerun unexpectedly overwrote an existing artifact" >&2
  exit 1
fi
[[ "$RESULTS_HASH" == "$(shasum -a 256 "$RESULTS_JSON" | awk '{print $1}')" ]] \
  || { echo "default rerun changed the original artifact" >&2; exit 1; }

QUICFUSCATE_ARTIFACT_POLICY=replace-with-backup bash -c \
  'set -Eeuo pipefail; source "$1"; json_begin "$2" replacement; JSON_FIRST_RUN=1; qf_json_append_object "$2" "status=PASS"; json_end "$2"' \
  _ "$PROJECT_ROOT/scripts/tests/lib/lib-common.sh" "$RESULTS_JSON"
BACKUP_FILE="$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name 'results.json.previous-*' -print -quit)"
[[ -n "$BACKUP_FILE" ]] || { echo "replacement did not preserve a backup" >&2; exit 1; }
qf_json_validate_file "$RESULTS_JSON"
qf_json_validate_file "$BACKUP_FILE"

if qf_json_write_raw_file "$TMP_ROOT/invalid.json" '{"broken":'; then
  echo "invalid JSON was accepted by the raw writer" >&2
  exit 1
fi
[[ ! -e "$TMP_ROOT/invalid.json" ]] || { echo "invalid JSON created an artifact" >&2; exit 1; }

META_FILE="$TMP_ROOT/metadata.json"
qf_json_write_object_file "$META_FILE" \
  'label=profile "quoted" Ω' 'count=int:7' \
  'nested=json:{"line":"quoted\\nΩ"}'
python3 - "$META_FILE" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["label"] == 'profile "quoted" Ω', document
assert document["count"] == 7, document
assert document["nested"]["line"] == "quoted\\nΩ", document
assert document["artifact"]["replacement"] == "create-new", document
PY

PROFILE_DIR="$TMP_ROOT/profile"
mkdir -p "$PROFILE_DIR"
SCENARIO_FILE="$PROFILE_DIR/scenario.json"
COMMAND_JSON="$(profile_command_json 'tool with spaces' $'argument\nΩ' 'RUSTFLAGS=-C target-cpu=native')"
profile_write_scenario "$SCENARIO_FILE" \
  runner scenario 'Quoted scenario Ω' SKIP 'contract fixture' "$COMMAND_JSON" \
  revision executable-sha host kernel '{}' '{}' '{"status":"SKIP"}' '{}' \
  '{"status":"SKIP"}' '{"status":"SKIP"}' '{"complete":false}' '{"status":"SKIP"}' \
  2026-08-02T00:00:00Z 2026-08-02T00:00:01Z
python3 - "$SCENARIO_FILE" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["command"]["argv"] == ["tool with spaces", "argument\nΩ", "RUSTFLAGS=-C target-cpu=native"], document
assert document["result"] == "SKIP", document
PY
if profile_write_scenario "$SCENARIO_FILE" runner scenario title SKIP reason "$COMMAND_JSON" \
  revision sha host kernel '{}' '{}' '{"status":"SKIP"}' '{}' '{"status":"SKIP"}' \
  '{"status":"SKIP"}' '{"complete":false}' '{"status":"SKIP"}' started finished; then
  echo "profiling scenario writer unexpectedly overwrote an artifact" >&2
  exit 1
fi

MANIFEST_FILE="$PROFILE_DIR/manifest.json"
profile_write_manifest "$MANIFEST_FILE" runner "$PROFILE_DIR" revision sha host kernel '{}' '{}' \
  2026-08-02T00:00:02Z "$SCENARIO_FILE"
python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["summary"]["scenario_count"] == 1, document
assert document["scenarios"][0]["result"] == "SKIP", document
PY

python3 - "$TMP_ROOT/python" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
specs = [
    ("runtime-performance-sampler.py", "write_json_new", {"quoted": 'line "quotes" \\ slash', "unicode": "Ω"}),
    ("tcp-throughput-probe.py", "write_json_new", {"quoted": 'line "quotes" \\ slash', "unicode": "Ω"}),
    ("udp-throughput-probe.py", "write_json_new", {"quoted": 'line "quotes" \\ slash', "unicode": "Ω"}),
    ("verify-fingerprint-pcap.py", "write_new_json", {"quoted": 'line "quotes" \\ slash', "unicode": "Ω"}),
    (
        "udp-socket-evidence.py",
        "write_new_json",
        {
            "captured_at_unix_ns": 1,
            "local_address_hex": "01000A0A",
            "local_port": 4433,
            "remote_address_hex": "00000000",
            "remote_port": 0,
            "drops": 0,
            "rx_queue_bytes": 0,
            "tx_queue_bytes": 0,
        },
    ),
]
for index, (name, function_name, payload) in enumerate(specs):
    path = Path("scripts/tests/utils") / name
    module_name = f"writer_contract_{index}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    target = root / f"{index}-nested" / "result with spaces Ω.json"
    writer = getattr(module, function_name)
    writer(target, payload)
    json.loads(target.read_text(encoding="utf-8"))
    try:
        writer(target, payload)
    except (FileExistsError, RuntimeError, ValueError):
        continue
    raise AssertionError(f"{name} replaced an existing artifact")
PY

if rg -n '"command=' scripts/benchmarks scripts/tests scripts/utils \
  --glob '*.sh' --glob '*.py' \
  --glob '!scripts/tests/fast/test-shared-artifact-writer-contract.sh'; then
  echo "Bash-escaped command fields remain in JSON writers" >&2
  exit 1
fi

echo "[PASS] shared artifact writer contract: structured JSON, create-new ownership, backup replacement, and profiling evidence"
