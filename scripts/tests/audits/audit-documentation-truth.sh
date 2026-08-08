#!/usr/bin/env bash
# Description: Validate canonical documentation status, task references, links, and heading ownership.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${QF_AUDIT_PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"

case "${1:-}" in
  "") ;;
  -h|--help|help)
    printf '%s\n' "Usage: $(basename "$0")"
    printf '%s\n' 'Validates canonical documentation status, task references, links, and heading ownership.'
    exit 0
    ;;
  *)
    printf 'Unknown argument: %s\n' "$1" >&2
    exit 2
    ;;
esac

exec python3 - "$PROJECT_ROOT" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(sys.argv[1]).resolve()
TRACKER = ROOT / "docs/todo.md"
CANONICAL_DOCS = (
    ROOT / "docs/DOCUMENTATION.md",
    ROOT / "docs/MAP.md",
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "docs/CONTRIBUTING.md",
)
DONE_STATUSES = {"DONE", "COMPLETE", "COMPLETED", "CLOSED", "AUDIT_COMPLETE", "SCRAP"}
OPEN_STATUSES = {"OPEN", "QUEUED", "IN_PROGRESS", "ACTIVE", "BLOCKED"}
OPENLIKE = re.compile(
    r"\b(?:remains?|remain|still)\s+(?:open|blocked|pending|unclaimed)\b"
    r"|\b(?:proof|acceptance|gate|task|work|implementation)\s+"
    r"(?:remains?|remain|is)\s+(?:open|blocked|pending|unclaimed)\b"
    r"|\b(?:open|pending|unclaimed)\s+under\s+TODO-\d+\b",
    re.IGNORECASE,
)
DONE_LIKE = re.compile(
    r"\bTODO-\d+\s+(?:is|was|are|were)\s+(?:complete|completed|done|closed)\b"
    r"|\bTODO-\d+\s+(?:now\s+)?(?:closed|complete|completed)\b",
    re.IGNORECASE,
)
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
TASK_RE = re.compile(r"\bTODO-\d+\b")


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_frontmatter(path: Path) -> dict[str, str]:
    raw = path.read_text(encoding="utf-8")
    if not raw.startswith("---\n") or "\n---\n" not in raw[4:]:
        fail(f"missing frontmatter delimiters: {path.relative_to(ROOT)}")
    front = raw[4:].split("\n---\n", 1)[0]
    return dict(re.findall(r"^([a-z_]+):\s*(.*?)\s*$", front, flags=re.MULTILINE))


def load_task_registry() -> tuple[dict[str, str], dict[str, Path]]:
    if not TRACKER.is_file():
        fail("missing canonical task tracker: docs/todo.md")
    statuses: dict[str, str] = {}
    detail_paths: dict[str, Path] = {}
    section: str | None = None
    current_id: str | None = None
    entry_sections: dict[str, str] = {}
    for line_no, line in enumerate(TRACKER.read_text(encoding="utf-8").splitlines(), start=1):
        if line.startswith("## "):
            section = line[3:].strip()
        heading = re.match(r"^### (TODO-\d+)\s+", line)
        if heading:
            current_id = heading.group(1)
            if section is None:
                fail(f"TODO heading outside a tracker section at line {line_no}")
            entry_sections[current_id] = section
            continue
        detail = re.match(r"^- Detail:\s+`([^`]+)`\s*$", line)
        if detail:
            if current_id is None:
                fail(f"tracker Detail line has no TODO owner at line {line_no}")
            if current_id in detail_paths:
                fail(f"duplicate tracker Detail path for {current_id}")
            path = ROOT / detail.group(1)
            if not path.is_file():
                fail(f"{current_id} Detail path does not exist: {detail.group(1)}")
            if path.read_text(encoding="utf-8").startswith("---\n"):
                fields = parse_frontmatter(path)
                if fields.get("id") != current_id:
                    fail(f"{current_id} Detail frontmatter id is {fields.get('id')!r}")
                status = fields.get("status")
                if status is None:
                    fail(f"{current_id} Detail has no status")
            elif path.parent.name == "done" and entry_sections[current_id] == "Completed":
                # Older archived details predate frontmatter. Their Completed tracker
                # section is the retained status owner; do not invent a second schema.
                status = "DONE"
            else:
                fail(f"missing frontmatter delimiters: {path.relative_to(ROOT)}")
            statuses[current_id] = status
            detail_paths[current_id] = path
    if section != "Completed":
        fail("tracker does not end in the canonical Completed section")
    if not statuses:
        fail("tracker has no canonical Detail entries")
    return statuses, detail_paths


def github_slug(heading: str) -> str:
    heading = re.sub(r"<[^>]+>", "", heading).strip().lower()
    heading = re.sub(r"[^\w\s-]", "", heading, flags=re.UNICODE)
    return re.sub(r"\s", "-", heading)


def historical_heading(heading: str) -> bool:
    return bool(
        re.search(r"\(20\d\d-\d\d-\d\d", heading)
        or re.search(
            r"\b(?:deep audit|follow-up audit|audit reconciliation|implementation reconciliation|"
            r"live audit|audit register|evidence|session)\b",
            heading,
            flags=re.IGNORECASE,
        )
    )


def check_document(path: Path, statuses: dict[str, str]) -> tuple[int, int]:
    if not path.is_file():
        fail(f"missing canonical document: {path.relative_to(ROOT)}")
    lines = path.read_text(encoding="utf-8").splitlines()
    headings: dict[str, int] = {}
    links = 0
    task_refs = 0
    historical = False
    for line_no, line in enumerate(lines, start=1):
        heading_match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading_match and not line.startswith("```"):
            heading = heading_match.group(1).strip()
            slug = github_slug(heading)
            if slug in headings:
                fail(
                    f"duplicate Markdown anchor #{slug} in {path.relative_to(ROOT)} "
                    f"at lines {headings[slug]} and {line_no}"
                )
            headings[slug] = line_no
            historical = historical_heading(heading)
        ids = sorted(set(TASK_RE.findall(line)))
        task_refs += len(ids)
        if len(ids) == 1 and not historical:
            ident = ids[0]
            status = statuses.get(ident)
            if status is None:
                fail(f"unregistered task reference {ident} at {path.relative_to(ROOT)}:{line_no}")
            if status in DONE_STATUSES and OPENLIKE.search(line):
                fail(
                    f"{ident} is {status} but current documentation marks it open/pending at "
                    f"{path.relative_to(ROOT)}:{line_no}"
                )
            if status in OPEN_STATUSES and DONE_LIKE.search(line):
                fail(
                    f"{ident} is {status} but current documentation marks it complete at "
                    f"{path.relative_to(ROOT)}:{line_no}"
                )
        for raw_target in LINK_RE.findall(line):
            target = raw_target.strip()
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            target = target.split()[0].strip("<>")
            target_path, separator, anchor = target.partition("#")
            destination = (path.parent / unquote(target_path)).resolve() if target_path else path
            if target_path and not destination.is_file():
                fail(f"broken local link {target!r} at {path.relative_to(ROOT)}:{line_no}")
            if separator and anchor and github_slug(anchor) not in headings_for(destination):
                fail(f"broken local anchor {target!r} at {path.relative_to(ROOT)}:{line_no}")
            links += 1
    return task_refs, links


def headings_for(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    slugs: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if match:
            slugs.add(github_slug(match.group(1).strip()))
    return slugs


def check_security_version() -> None:
    cargo = ROOT / "Cargo.toml"
    security = ROOT / "SECURITY.md"
    if not cargo.is_file() or not security.is_file():
        fail("Cargo.toml or SECURITY.md is missing")
    match = re.search(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', cargo.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        fail("root Cargo.toml has no package version")
    expected = f"{match.group(1)}.{match.group(2)}.x"
    pattern = re.compile(rf"^\|\s*{re.escape(expected)}\s*\|\s*Yes\s*\|$", re.MULTILINE)
    if pattern.search(security.read_text(encoding="utf-8")) is None:
        fail(f"SECURITY.md does not mark the current supported line {expected!r} as supported")


statuses, detail_paths = load_task_registry()
for path in CANONICAL_DOCS:
    if path.name in {"DOCUMENTATION.md", "MAP.md"}:
        text = path.read_text(encoding="utf-8")
        if "Current task status and evidence ownership are canonical only in `docs/todo.md`" not in text:
            fail(f"missing current-status owner boundary in {path.relative_to(ROOT)}")
        if "historical snapshots" not in text:
            fail(f"missing historical-snapshot boundary in {path.relative_to(ROOT)}")

task_count = 0
link_count = 0
for path in CANONICAL_DOCS:
    tasks, links = check_document(path, statuses)
    task_count += tasks
    link_count += links
check_security_version()

print(
    "PASS: documentation truth "
    f"tasks={len(statuses)} references={task_count} links={link_count} "
    f"canonical_docs={len(CANONICAL_DOCS)}"
)
PY
