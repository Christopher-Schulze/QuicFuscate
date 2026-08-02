#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

exec python3 - "$PROJECT_ROOT" <<'PY'
from __future__ import annotations

import collections
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(sys.argv[1]).resolve()
TRACKER = ROOT / "docs/todo.md"
ARCHIVE_MANIFEST = ROOT / "docs/todo/todo-754-reconciliation-manifest.tsv"
COVERAGE_MANIFEST = ROOT / "docs/todo/todo-754-coverage-manifest.tsv"
ALLOWED_SECTIONS = {"Active", "Queue", "Completed"}
REQUIRED_FIELDS = {"id", "title", "severity", "phase", "priority", "status", "created"}
ALLOWED_STATUSES = {"DONE", "SCRAP", "OPEN", "COMPLETE", "COMPLETED", "ACTIVE", "CLOSED", "QUEUED"}
SCHEMA_EXCEPTION = "missing_depends_on"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_lines(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return [line for line in result.stdout.splitlines() if line]


def parse_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    raw = path.read_text(encoding="utf-8")
    if not raw.startswith("---\n") or "\n---\n" not in raw[4:]:
        fail(f"missing frontmatter delimiters: {path.relative_to(ROOT)}")
    front, body = raw[4:].split("\n---\n", 1)
    fields = dict(re.findall(r"^([a-z_]+):\s*(.*?)\s*$", front, flags=re.MULTILINE))
    return fields, body


def tracked_class(path: str) -> str | None:
    root_file_classes = {
        ".gitattributes": "root-governance-or-manifest",
        ".gitignore": "root-governance-or-manifest",
        "AGENTS.md": "root-governance-or-manifest",
        "Cargo.lock": "root-governance-or-manifest",
        "Cargo.toml": "root-governance-or-manifest",
        "README.md": "root-governance-or-manifest",
        "SECURITY.md": "root-governance-or-manifest",
        "build.rs": "root-governance-or-manifest",
        "bun.lock": "root-governance-or-manifest",
        "deny.toml": "root-governance-or-manifest",
        "package.json": "root-governance-or-manifest",
        "rust-toolchain.toml": "root-governance-or-manifest",
        "rustfmt.toml": "root-governance-or-manifest",
    }
    if "/" not in path:
        return root_file_classes.get(path)
    if path.startswith(".cargo/"):
        return "cargo-configuration"
    if path.startswith("archive/"):
        return "historical-archive"
    prefixes = (
        (".github/", "ci-workflow"),
        ("apps/svelte-admin/", "frontend-admin"),
        ("apps/svelte-desktop/", "frontend-desktop"),
        ("apps/tauri/", "native-tauri"),
        ("assets/", "runtime-assets"),
        ("benches/", "benchmarks"),
        ("config/", "configuration"),
        ("docs/", "documentation"),
        ("examples/", "examples"),
        ("packages/", "frontend-packages"),
        ("scripts/", "tooling-and-tests"),
        ("src/", "rust-production"),
    )
    for prefix, category in prefixes:
        if path.startswith(prefix):
            return category
    return None


def ignored_class(path: str) -> str | None:
    parts = path.split("/")
    base = parts[-1]
    if path == "docs/todo.md" or path.startswith("docs/todo/"):
        return "ignored-governance-todo"
    if path.startswith("target/") or "/target/" in path:
        return "ignored-cargo-build"
    if "node_modules" in parts:
        return "ignored-node-dependencies"
    if "graphify-out" in parts:
        return "ignored-graph-analysis"
    if path.startswith(".opencode/"):
        return "ignored-agent-runtime"
    if path.startswith(".claude/"):
        return "ignored-agent-config"
    if path.startswith("scripts/out/"):
        return "ignored-audit-output"
    if path.startswith("docs/profiling/"):
        return "ignored-profiling-evidence"
    if path.startswith("config/local/") or path == "config/admin-auth.json":
        return "ignored-local-sensitive"
    if path.startswith("apps/tauri/src-tauri/resources/windows/wintun.dll"):
        return "ignored-platform-binary"
    if base in {".DS_Store", ".DS_Storage", "Thumbs.db", "ehthumbs.db", "desktop.ini"}:
        return "ignored-os-metadata"
    if path.endswith((".log", ".orig", ".bak", ".swp")):
        return "ignored-logs-temp"
    if base.startswith(("npm-debug.log", "yarn-debug.log", "yarn-error.log")):
        return "ignored-logs-temp"
    generated_fragments = (
        "/build/",
        "/dist/",
        "/.svelte-kit/",
        "/.vite/",
        "/.output/",
        "/.vercel/",
        "/.netlify/",
        "/.wrangler/",
        "/.playwright/",
        "/playwright-report/",
        "/test-results/",
        "/-snapshots/",
    )
    if path.startswith(("build/", "dist/", ".svelte-kit/", ".vite/")):
        return "ignored-frontend-generated"
    if any(fragment in f"/{path}" for fragment in generated_fragments):
        return "ignored-frontend-generated"
    if path.startswith("assets/web-admin/"):
        return "ignored-frontend-generated"
    if base == "bun.lockb" or base.endswith(".tsbuildinfo"):
        return "ignored-tool-cache"
    if "/.cache/" in f"/{path}" or base in {"lcov.info"}:
        return "ignored-tool-cache"
    if base.endswith((".profraw", ".profdata", ".dSYM")):
        return "ignored-tool-cache"
    if base == ".env" or base.startswith(".env."):
        return "ignored-secret-material"
    if base.endswith((".pem", ".p12", ".pfx", ".key", ".crt")):
        return "ignored-secret-material"
    return None


def validate_tracker() -> tuple[set[str], dict[str, str], collections.Counter[str]]:
    lines = TRACKER.read_text(encoding="utf-8").splitlines()
    section: str | None = None
    entries: list[dict[str, object]] = []
    headings: dict[str, int] = {}
    section_counts: collections.Counter[str] = collections.Counter()
    for line_no, line in enumerate(lines, start=1):
        if line.startswith("## "):
            section = line[3:].strip()
            if section not in ALLOWED_SECTIONS:
                fail(f"unexpected tracker section {section!r} at line {line_no}")
        heading = re.match(r"^### (TODO-\d+)\s+(.+)$", line)
        if heading:
            if section is None:
                fail(f"TODO heading outside a section at line {line_no}")
            ident = heading.group(1)
            if ident in headings:
                fail(f"duplicate tracker ID {ident} at lines {headings[ident]} and {line_no}")
            headings[ident] = line_no
            section_counts[section] += 1
            entries.append({"id": ident, "section": section, "line": line_no, "details": []})
            continue
        if line.startswith("- Detail: "):
            if not entries:
                fail(f"Detail line before first TODO heading at line {line_no}")
            detail = re.match(r"^- Detail:\s+`([^`]+)`\s*$", line)
            if detail is None:
                fail(f"malformed Detail line at line {line_no}: {line}")
            details = entries[-1]["details"]
            assert isinstance(details, list)
            details.append(detail.group(1))
    if not entries:
        fail("tracker contains no TODO headings")
    for entry in entries:
        details = entry["details"]
        assert isinstance(details, list)
        if len(details) != 1:
            fail(f"{entry['id']} has {len(details)} canonical Detail lines")
        detail_path = ROOT / details[0]
        if not detail_path.is_file():
            fail(f"{entry['id']} Detail path does not exist: {details[0]}")
    return set(headings), {item["id"]: item["section"] for item in entries}, section_counts


def validate_todo_corpus(registered: set[str], sections: dict[str, str]) -> tuple[int, int, int]:
    current_files = sorted((ROOT / "docs/todo").glob("todo-*.md"))
    current_ids: set[str] = set()
    statuses: collections.Counter[str] = collections.Counter()
    for path in current_files:
        match = re.fullmatch(r"todo-(\d+)-.+\.md", path.name)
        if match is None:
            fail(f"invalid current TODO filename: {path.relative_to(ROOT)}")
        ident = f"TODO-{match.group(1)}"
        if ident in current_ids:
            fail(f"duplicate current TODO filename ID: {ident}")
        current_ids.add(ident)
        fields, front_body = parse_frontmatter(path)
        missing = REQUIRED_FIELDS - fields.keys()
        if missing:
            fail(f"{ident} missing frontmatter fields: {sorted(missing)}")
        if fields["id"] != ident:
            fail(f"{ident} frontmatter id is {fields['id']!r}")
        status = fields["status"]
        if status not in ALLOWED_STATUSES:
            fail(f"{ident} has unknown status {status!r}")
        statuses[status] += 1
        has_depends = "depends_on" in fields
        exception = fields.get("schema_exception")
        if has_depends and exception is not None:
            fail(f"{ident} has depends_on and schema_exception simultaneously")
        if not has_depends and exception != SCHEMA_EXCEPTION:
            fail(f"{ident} omits depends_on without schema_exception={SCHEMA_EXCEPTION!r}")
        for dependency in set(re.findall(r"\bTODO-\d+\b", front_body)):
            if dependency == ident:
                continue
            if dependency not in registered:
                fail(f"{ident} references unregistered dependency {dependency}")
        section = sections.get(ident)
        if section is None:
            fail(f"current detail is not registered: {ident}")
        if section == "Active" and status != "ACTIVE":
            fail(f"Active tracker entry {ident} has status {status}, expected ACTIVE")
        if section == "Queue" and status not in {"OPEN", "QUEUED"}:
            fail(f"Queue tracker entry {ident} has status {status}")
        if section == "Completed" and status not in {"DONE", "SCRAP", "COMPLETE", "COMPLETED", "CLOSED"}:
            fail(f"Completed tracker entry {ident} has status {status}")
    missing_current = current_ids - registered
    if missing_current:
        fail(f"unregistered current TODO IDs: {', '.join(sorted(missing_current))}")
    return len(current_files), len(current_ids), len(missing_current)


def validate_archive(registered: set[str]) -> tuple[int, int]:
    if not ARCHIVE_MANIFEST.is_file():
        fail(f"missing archive reconciliation manifest: {ARCHIVE_MANIFEST.relative_to(ROOT)}")
    manifest_lines = ARCHIVE_MANIFEST.read_text(encoding="utf-8").splitlines()
    if not manifest_lines or manifest_lines[0] != "path\tclassification\tcanonical_id\tstatus\treason":
        fail("archive reconciliation manifest has an invalid header")
    manifest: dict[str, tuple[str, str, str, str]] = {}
    for line_no, line in enumerate(manifest_lines[1:], start=2):
        fields = line.split("\t")
        if len(fields) != 5 or not all(fields):
            fail(f"malformed archive manifest row at line {line_no}")
        path, classification, canonical_id, status, reason = fields
        if path in manifest:
            fail(f"duplicate archive manifest path: {path}")
        manifest[path] = (classification, canonical_id, status, reason)
        if not (ROOT / path).is_file() or not path.startswith("docs/todo/done/"):
            fail(f"archive manifest path is not an existing done artifact: {path}")
        if classification not in {"legacy_archive_duplicate_id", "legacy_archive_no_id"}:
            fail(f"unknown archive manifest classification {classification!r}")
        if status != "ARCHIVED":
            fail(f"archive manifest status is not ARCHIVED: {path}")
    done_files = sorted((ROOT / "docs/todo/done").glob("*.md"))
    by_id: collections.defaultdict[str, list[str]] = collections.defaultdict(list)
    no_id: set[str] = set()
    for path in done_files:
        relative = str(path.relative_to(ROOT))
        match = re.match(r"^todo-(\d+)-", path.name)
        if match is None:
            no_id.add(relative)
        else:
            by_id[f"TODO-{match.group(1)}"].append(relative)
    expected_exceptions: set[str] = set(no_id)
    for ident, paths in by_id.items():
        if len(paths) > 1:
            expected_exceptions.update(paths)
        elif ident not in registered:
            fail(f"archive ID {ident} is not registered")
    if set(manifest) != expected_exceptions:
        missing = expected_exceptions - set(manifest)
        extra = set(manifest) - expected_exceptions
        fail(f"archive manifest mismatch; missing={sorted(missing)}, extra={sorted(extra)}")
    for path, (classification, canonical_id, _, _) in manifest.items():
        if classification == "legacy_archive_no_id":
            if canonical_id != "-" or path not in no_id:
                fail(f"invalid no-ID archive classification: {path}")
        elif canonical_id not in registered or path not in by_id[canonical_id] or len(by_id[canonical_id]) < 2:
            fail(f"invalid duplicate archive classification: {path}")
    return len(done_files), len(manifest)


def validate_coverage_manifest() -> set[str]:
    if not COVERAGE_MANIFEST.is_file():
        fail(f"missing coverage manifest: {COVERAGE_MANIFEST.relative_to(ROOT)}")
    lines = COVERAGE_MANIFEST.read_text(encoding="utf-8").splitlines()
    header = "scope\tpattern\tcategory\tdisposition\towner"
    if not lines or lines[0] != header:
        fail("coverage manifest has an invalid header")
    categories: set[str] = set()
    seen_rows: set[tuple[str, str, str, str, str]] = set()
    for line_no, line in enumerate(lines[1:], start=2):
        fields = line.split("\t")
        if len(fields) != 5 or not all(fields):
            fail(f"malformed coverage manifest row at line {line_no}")
        row = tuple(fields)
        if row in seen_rows:
            fail(f"duplicate coverage manifest row at line {line_no}")
        seen_rows.add(row)
        scope, _, category, disposition, _ = fields
        if scope not in {"tracked", "ignored", "untracked"}:
            fail(f"invalid coverage manifest scope {scope!r} at line {line_no}")
        if disposition not in {"in_scope", "protected_ui", "generated", "evidence", "sensitive", "agent_state"}:
            fail(f"invalid coverage manifest disposition {disposition!r} at line {line_no}")
        categories.add(category)
    if not categories:
        fail("coverage manifest has no classification rows")
    return categories


def validate_coverage(manifest_categories: set[str]) -> tuple[int, int, int, collections.Counter[str]]:
    tracked = git_lines("ls-files")
    ignored = git_lines("ls-files", "-o", "--ignored", "--exclude-standard")
    untracked = git_lines("ls-files", "-o", "--exclude-standard")
    if len(set(tracked)) != len(tracked) or len(set(ignored)) != len(ignored):
        fail("Git scope enumeration contains duplicate paths")
    untracked_allowed = {"scripts/tests/audits/verify-audit-completeness.sh"}
    unexpected_untracked = set(untracked) - untracked_allowed
    if unexpected_untracked:
        fail(f"unexpected non-ignored untracked paths: {sorted(unexpected_untracked)}")
    tracked_counts: collections.Counter[str] = collections.Counter()
    ignored_counts: collections.Counter[str] = collections.Counter()
    for path in tracked:
        category = tracked_class(path)
        if category is None:
            fail(f"unclassified tracked path: {path}")
        if category not in manifest_categories:
            fail(f"tracked classifier is absent from coverage manifest: {category}")
        tracked_counts[category] += 1
    for path in ignored:
        category = ignored_class(path)
        if category is None:
            fail(f"unclassified ignored path: {path}")
        if category not in manifest_categories:
            fail(f"ignored classifier is absent from coverage manifest: {category}")
        ignored_counts[category] += 1
    for path in untracked:
        if path not in untracked_allowed:
            fail(f"unclassified untracked path: {path}")
        if "untracked-audit-tool" not in manifest_categories:
            fail("allowed untracked audit tool is absent from coverage manifest")
    accounted = len(tracked) + len(ignored) + len(untracked)
    print(f"coverage tracked={len(tracked)} ignored={len(ignored)} untracked={len(untracked)} accounted={accounted}")
    print("tracked classes=" + ",".join(f"{key}:{tracked_counts[key]}" for key in sorted(tracked_counts)))
    print("ignored classes=" + ",".join(f"{key}:{ignored_counts[key]}" for key in sorted(ignored_counts)))
    return len(tracked), len(ignored), len(untracked), ignored_counts


registered, sections, section_counts = validate_tracker()
current_count, current_unique, missing_current = validate_todo_corpus(registered, sections)
done_count, archive_exception_count = validate_archive(registered)
coverage_categories = validate_coverage_manifest()
tracked_count, ignored_count, untracked_count, _ = validate_coverage(coverage_categories)
print(
    "PASS: audit completeness "
    f"tracker={len(registered)} sections={dict(section_counts)} "
    f"current_details={current_count}/{current_unique} missing_current={missing_current} "
    f"done_archive={done_count} explicit_archive_exceptions={archive_exception_count}"
)
PY
