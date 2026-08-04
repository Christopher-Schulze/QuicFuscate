#!/usr/bin/env python3
"""Build and validate a fail-closed Graphify evidence package.

The external Graphify package is used only for deterministic detection and AST
extraction. This wrapper owns the repository evidence contract: relative source
identity, endpoint normalization, scope and content provenance, unsupported
surface accounting, and stale-artifact detection.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "quicfuscate.graphify-evidence.v1"
STATUSES = {"PASS", "BLOCKED", "UNAVAILABLE", "FAIL"}
CONTENT_CATEGORIES = ("document", "paper", "image", "video")
SENSITIVE_CATEGORIES = ("skipped_sensitive",)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run_command(root: Path, *args: str) -> tuple[int, str, str]:
    result = subprocess.run(
        args,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def git_value(root: Path, *args: str) -> str:
    code, stdout, stderr = run_command(root, "git", *args)
    if code != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr or stdout}")
    return stdout


def git_paths(root: Path, *args: str) -> list[str]:
    code, stdout, stderr = run_command(root, "git", *args)
    if code != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr or stdout}")
    return [item for item in stdout.split("\x00") if item]


def relative_path(path: str | Path, root: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        digest = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:16]
        return f"external/{digest}"


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_scope(
    root: Path,
    detection: dict[str, Any],
) -> tuple[str, list[str], dict[str, int]]:
    digest = hashlib.sha256()
    visible_paths: list[str] = []
    extension_counts: collections.Counter[str] = collections.Counter()
    rows: list[tuple[str, str, int, str]] = []
    for category, values in detection.get("files", {}).items():
        if not isinstance(values, list):
            continue
        for value in values:
            path = Path(value)
            if not path.is_file():
                continue
            relative = relative_path(path, root)
            visible_paths.append(relative)
            extension_counts[path.suffix.lower() or "(none)"] += 1
            rows.append((category, relative, path.stat().st_size, digest_file(path)))
    rows.sort()
    for category, relative, size, file_digest in rows:
        digest.update(f"{category}\t{relative}\t{size}\t{file_digest}\n".encode("utf-8"))
    skipped_count = len(detection.get("skipped_sensitive", []))
    digest.update(f"skipped_sensitive\t{skipped_count}\n".encode("utf-8"))
    return digest.hexdigest(), sorted(set(visible_paths)), dict(sorted(extension_counts.items()))


def classify_ignored(path: str) -> str:
    parts = set(Path(path).parts)
    if "node_modules" in parts or "target" in parts:
        return "dependency-or-build"
    if "graphify-out" in parts or path.startswith("scripts/out/"):
        return "audit-evidence"
    if any(part in parts for part in (".claude", ".opencode", ".agents")):
        return "agent-state"
    if path.startswith("config/local/") or Path(path).name.startswith(".env"):
        return "sensitive-local"
    if any(fragment in f"/{path}" for fragment in ("/build/", "/dist/", "/.svelte-kit/", "/test-results/", "/playwright-report/")):
        return "generated"
    return "ignored-other"


def git_scope(root: Path) -> dict[str, Any]:
    tracked = git_paths(root, "ls-files", "-z")
    ignored = git_paths(root, "ls-files", "-o", "--ignored", "--exclude-standard", "-z")
    untracked = git_paths(root, "ls-files", "-o", "--exclude-standard", "-z")
    digest = hashlib.sha256()
    for scope, values in (("tracked", tracked), ("ignored", ignored), ("untracked", untracked)):
        for value in sorted(values):
            digest.update(f"{scope}\t{value}\n".encode("utf-8"))
    ignored_classes = collections.Counter(classify_ignored(value) for value in ignored)
    return {
        "tracked": len(tracked),
        "ignored": len(ignored),
        "untracked": len(untracked),
        "ignored_classes": dict(sorted(ignored_classes.items())),
        "path_sha256": digest.hexdigest(),
    }


def canonical_endpoint(value: Any, root: Path) -> str:
    text = "" if value is None else str(value)
    root_slug = re.sub(r"[^A-Za-z0-9]+", "_", root.as_posix().strip("/")).strip("_").lower()
    lower = text.lower()
    if root_slug and lower.startswith(root_slug + "_"):
        return text[len(root_slug) + 1 :]
    return text


def stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:32]}"


def node_key(node: dict[str, Any], source_file: str) -> dict[str, Any]:
    return {
        "source_file": source_file,
        "label": str(node.get("label", "")),
        "source_location": node.get("source_location"),
        "file_type": str(node.get("file_type", "")),
        "metadata": node.get("metadata") or {},
    }


def normalize_ast(raw: dict[str, Any], root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_nodes = raw.get("nodes") if isinstance(raw.get("nodes"), list) else []
    raw_edges = raw.get("edges") if isinstance(raw.get("edges"), list) else []
    raw_id_counts = collections.Counter(
        str(node.get("id")) for node in raw_nodes if isinstance(node, dict) and node.get("id") is not None
    )
    normalized_nodes: list[dict[str, Any]] = []
    raw_to_stable: dict[str, set[str]] = collections.defaultdict(set)
    stable_to_source: dict[str, str] = {}
    stable_to_label: dict[str, str] = {}
    seen_keys: set[str] = set()
    duplicate_nodes_collapsed = 0

    for raw_node in raw_nodes:
        if not isinstance(raw_node, dict):
            continue
        source_file = relative_path(raw_node.get("source_file", ""), root) if raw_node.get("source_file") else ""
        key = node_key(raw_node, source_file)
        key_json = json.dumps(key, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        stable = stable_id("ast-node", key)
        if key_json in seen_keys:
            duplicate_nodes_collapsed += 1
        else:
            seen_keys.add(key_json)
            node = {
                "id": stable,
                "label": key["label"],
                "file_type": key["file_type"] or ("external" if not source_file else "code"),
                "source_file": source_file,
                "source_location": key["source_location"],
                "metadata": key["metadata"],
                "_origin": "ast-normalized",
            }
            normalized_nodes.append(node)
            stable_to_source[stable] = source_file
            stable_to_label[stable] = key["label"]
        raw_id = raw_node.get("id")
        if raw_id is not None:
            raw_to_stable[str(raw_id)].add(stable)

    placeholders: dict[str, str] = {}
    ambiguous_edges = 0
    unresolved_edges = 0
    resolved_edges = 0
    normalized_edges: list[dict[str, Any]] = []

    def placeholder(kind: str, raw_id: Any, candidates: set[str], source_file: str) -> str:
        token = canonical_endpoint(raw_id, root)
        key = {"kind": kind, "token": token, "source_file": source_file if kind == "ambiguous" else ""}
        key_json = json.dumps(key, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if key_json in placeholders:
            return placeholders[key_json]
        stable = stable_id("ast-endpoint", key)
        label = f"[{kind} endpoint] {token or '(empty)'}"
        normalized_nodes.append(
            {
                "id": stable,
                "label": label,
                "file_type": "external",
                "source_file": "",
                "source_location": None,
                "metadata": {
                    "resolution": kind,
                    "raw_endpoint_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                    "candidate_count": len(candidates),
                },
                "_origin": "ast-normalized-endpoint",
            }
        )
        stable_to_source[stable] = ""
        stable_to_label[stable] = label
        placeholders[key_json] = stable
        return stable

    def resolve(raw_id: Any, source_file: str) -> tuple[str, str]:
        candidates = raw_to_stable.get(str(raw_id), set()) if raw_id is not None else set()
        if len(candidates) == 1:
            return next(iter(candidates)), "resolved"
        if len(candidates) > 1:
            same_file = {candidate for candidate in candidates if stable_to_source.get(candidate) == source_file}
            if len(same_file) == 1:
                return next(iter(same_file)), "resolved"
            return placeholder("ambiguous", raw_id, candidates, source_file), "ambiguous"
        return placeholder("unresolved", raw_id, set(), source_file), "unresolved"

    for raw_edge in raw_edges:
        edge = raw_edge if isinstance(raw_edge, dict) else {}
        source_file = relative_path(edge.get("source_file", ""), root) if edge.get("source_file") else ""
        source, source_status = resolve(edge.get("source"), source_file)
        target, target_status = resolve(edge.get("target"), source_file)
        endpoint_status = "resolved"
        if source_status != "resolved" or target_status != "resolved":
            endpoint_status = "ambiguous" if "ambiguous" in (source_status, target_status) else "unresolved"
        if endpoint_status == "resolved":
            resolved_edges += 1
        elif endpoint_status == "ambiguous":
            ambiguous_edges += 1
        else:
            unresolved_edges += 1
        normalized_edge = dict(edge)
        normalized_edge.update(
            {
                "source": source,
                "target": target,
                "source_file": source_file,
                "endpoint_status": endpoint_status,
            }
        )
        normalized_edges.append(normalized_edge)

    normalized = {
        "schema": "quicfuscate.graphify-ast-normalized.v1",
        "directed": True,
        "nodes": normalized_nodes,
        "edges": normalized_edges,
    }
    normalized_ids = {node["id"] for node in normalized_nodes}
    health = {
        "raw_node_count": len(raw_nodes),
        "raw_edge_count": len(raw_edges),
        "raw_duplicate_node_ids": sum(count - 1 for count in raw_id_counts.values() if count > 1),
        "normalized_node_count": len(normalized_nodes),
        "normalized_edge_count": len(normalized_edges),
        "duplicate_nodes_collapsed": duplicate_nodes_collapsed,
        "resolved_endpoint_edges": resolved_edges,
        "ambiguous_endpoint_edges": ambiguous_edges,
        "unresolved_endpoint_edges": unresolved_edges,
        "dangling_edges": sum(
            1
            for edge in normalized_edges
            if edge.get("source") not in normalized_ids or edge.get("target") not in normalized_ids
        ),
        "stable_node_ids": len({node["id"] for node in normalized_nodes}) == len(normalized_nodes),
        "relative_source_files": all(not str(node.get("source_file", "")).startswith("/") for node in normalized_nodes),
    }
    return normalized, health


def legacy_artifact(root: Path, current_revision: str) -> dict[str, Any]:
    graph_path = root / "graphify-out/graph.json"
    report_path = root / "graphify-out/GRAPH_REPORT.md"
    if not graph_path.exists():
        return {
            "graph_json": {"exists": False},
            "report": {"exists": report_path.exists()},
            "stale": report_path.exists(),
            "reason": "legacy report exists without graph provenance" if report_path.exists() else "no legacy graph artifact",
        }
    try:
        payload = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "graph_json": {"exists": True, "read_error": str(exc)},
            "report": {"exists": report_path.exists()},
            "stale": True,
            "reason": "legacy graph artifact is unreadable",
        }
    required = (
        "built_at_commit",
        "source_scope_sha256",
        "extraction_mode",
        "tool_version",
        "generated_at_utc",
    )
    missing = [key for key in required if key not in payload]
    built_at = payload.get("built_at_commit")
    stale_reasons = []
    if built_at != current_revision:
        stale_reasons.append("built_at_commit does not match current revision")
    if missing:
        stale_reasons.append("missing provenance fields: " + ", ".join(missing))
    graph = payload.get("graph") if isinstance(payload.get("graph"), dict) else {}
    return {
        "graph_json": {
            "exists": True,
            "built_at_commit": built_at,
            "node_count": len(payload.get("nodes", [])) if isinstance(payload.get("nodes"), list) else None,
            "link_count": len(payload.get("links", [])) if isinstance(payload.get("links"), list) else None,
            "graph_type": graph.get("type"),
            "missing_provenance_fields": missing,
        },
        "report": {"exists": report_path.exists()},
        "stale": bool(stale_reasons),
        "reason": "; ".join(stale_reasons) or "legacy graph artifact is current",
    }


def load_graphify() -> tuple[Any, Any, Any, str]:
    graphify = importlib.import_module("graphify")
    detect_module = importlib.import_module("graphify.detect")
    extract_module = importlib.import_module("graphify.extract")
    version = "unknown"
    for distribution in ("graphifyy", "graphify"):
        try:
            version = importlib.metadata.version(distribution)
            break
        except importlib.metadata.PackageNotFoundError:
            continue
    return graphify, detect_module.detect, extract_module, version


def write_new(path: Path, content: str) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to overwrite existing generated artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def create_output_dir(root: Path, requested: str | None) -> Path:
    if requested:
        output = Path(requested)
        if not output.is_absolute():
            output = root / output
        output = output.resolve()
        if output.exists():
            raise RuntimeError(f"refusing to reuse existing output directory: {output}")
        output.mkdir(parents=True)
        return output
    base = root / "scripts/out/audits"
    base.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("graphify-%Y%m%dT%H%M%SZ")
    for suffix in range(100):
        name = stamp if suffix == 0 else f"{stamp}-{suffix}"
        output = base / name
        try:
            output.mkdir()
            return output
        except FileExistsError:
            continue
    raise RuntimeError("could not allocate a unique Graphify evidence directory")


def language_coverage(
    root: Path,
    code_paths: list[Path],
    raw_nodes: list[dict[str, Any]],
    extract_module: Any,
) -> dict[str, Any]:
    dispatch = getattr(extract_module, "_DISPATCH", {})
    supported_suffixes = set(dispatch) if isinstance(dispatch, dict) else set()
    raw_sources = {
        relative_path(node.get("source_file", ""), root)
        for node in raw_nodes
        if isinstance(node, dict) and node.get("source_file")
    }
    rows: dict[str, dict[str, int]] = {}
    unsupported: collections.Counter[str] = collections.Counter()
    missing: list[str] = []
    for path in code_paths:
        suffix = path.suffix.lower() or "(none)"
        row = rows.setdefault(suffix, {"detected_files": 0, "files_with_nodes": 0, "files_without_nodes": 0})
        row["detected_files"] += 1
        relative = relative_path(path, root)
        if relative in raw_sources:
            row["files_with_nodes"] += 1
        else:
            row["files_without_nodes"] += 1
            missing.append(relative)
        if suffix != "(none)" and suffix not in supported_suffixes:
            unsupported[suffix] += 1
    return {
        "by_extension": dict(sorted(rows.items())),
        "unsupported_extensions": dict(sorted(unsupported.items())),
        "files_without_nodes": sorted(missing),
        "rust_files": sum(1 for path in code_paths if path.suffix.lower() == ".rs"),
        "rust_files_with_nodes": sum(1 for path in code_paths if path.suffix.lower() == ".rs" and relative_path(path, root) in raw_sources),
        "script_files": sum(1 for path in code_paths if path.suffix.lower() in {".sh", ".bash", ".ps1", ".psm1"}),
        "script_files_with_nodes": sum(1 for path in code_paths if path.suffix.lower() in {".sh", ".bash", ".ps1", ".psm1"} and relative_path(path, root) in raw_sources),
    }


def render_report(manifest: dict[str, Any]) -> str:
    detection = manifest["detection"]
    extraction = manifest["extraction"]
    health = manifest["health"]
    semantic = manifest["semantic"]
    legacy = manifest["legacy_artifacts"]
    lines = [
        "# Graphify Evidence Report",
        "",
        f"Status: {manifest['status']}",
        f"Generated: {manifest['provenance']['generated_at_utc']}",
        f"Source revision: `{manifest['provenance']['source_revision']}`",
        f"Graphify version: `{manifest['provenance']['graphify_version']}`",
        "",
        "## Detection",
        "",
        f"- Files: {detection['total_files']}; words: {detection['total_words']}",
        f"- Categories: {json.dumps(detection['category_counts'], sort_keys=True)}",
        f"- Sensitive files skipped: {detection['skipped_sensitive_count']}",
        f"- Scope SHA-256: `{manifest['provenance']['source_scope_sha256']}`",
        "",
        "## Deterministic AST",
        "",
        f"- Raw nodes/edges: {extraction['raw_node_count']}/{extraction['raw_edge_count']}",
        f"- Normalized nodes/edges: {extraction['normalized_node_count']}/{extraction['normalized_edge_count']}",
        f"- Rust files with nodes: {extraction['language_coverage']['rust_files_with_nodes']}/{extraction['language_coverage']['rust_files']}",
        f"- Script files with nodes: {extraction['language_coverage']['script_files_with_nodes']}/{extraction['language_coverage']['script_files']}",
        f"- Raw dangling edges: {health['raw']['dangling_edges']}; normalized dangling edges: {health['normalized']['dangling_edges']}",
        f"- Ambiguous/unresolved normalized endpoint edges: {health['normalized']['ambiguous_endpoint_edges']}/{health['normalized']['unresolved_endpoint_edges']}",
        "",
        "## Semantic extraction",
        "",
        f"- Status: {semantic['status']}",
        f"- Content files: {semantic['content_file_count']}; cached: {semantic['cached_file_count']}; uncached: {semantic['uncached_file_count']}",
        f"- Reason: {semantic['reason']}",
        "",
        "## Legacy artifacts",
        "",
        f"- Stale: {legacy['stale']}",
        f"- Reason: {legacy['reason']}",
        "",
        "## Unsupported surfaces",
        "",
    ]
    for name, value in manifest["unsupported_surfaces"].items():
        lines.append(f"- {name}: {json.dumps(value, sort_keys=True)}")
    lines.extend(
        [
            "",
            "This report is evidence, not a green project claim. BLOCKED and UNAVAILABLE states are intentional fail-closed results.",
            "",
        ]
    )
    return "\n".join(lines)


def build_manifest(root: Path, output_dir: Path) -> tuple[dict[str, Any], str]:
    current_revision = git_value(root, "rev-parse", "HEAD")
    scope = git_scope(root)
    generated_at = utc_now()
    base_provenance = {
        "source_revision": current_revision,
        "generated_at_utc": generated_at,
        "scan_root": str(root),
        "python": sys.executable,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "extraction_mode": "deterministic-ast-sequential",
        "ignored_generated_policy": "counted in git scope, excluded by Graphify detection policy",
        "sensitive_policy": "counted but paths and contents are redacted",
    }
    try:
        graphify, detect, extract_module, graphify_version = load_graphify()
    except (ImportError, ModuleNotFoundError, importlib.metadata.PackageNotFoundError) as exc:
        raw_path = output_dir / "raw-ast.json"
        normalized_path = output_dir / "normalized-ast.json"
        report_path = output_dir / "GRAPH_REPORT.md"
        unavailable_reason = f"Graphify package unavailable: {exc}"
        manifest = {
            "schema": SCHEMA,
            "status": "UNAVAILABLE",
            "status_reasons": [unavailable_reason],
            "provenance": {
                **base_provenance,
                "graphify_version": "unavailable",
                "source_scope_sha256": scope["path_sha256"],
                "source_scope_kind": "git-path-scope-only",
            },
            "scope": scope,
            "detection": {
                "status": "UNAVAILABLE",
                "reason": unavailable_reason,
                "total_files": 0,
                "total_words": 0,
                "category_counts": {},
                "extension_counts": {},
                "skipped_sensitive_count": 0,
                "graphifyignore_pattern_count": 0,
                "detected_path_count": 0,
            },
            "extraction": {
                "status": "UNAVAILABLE",
                "reason": "deterministic AST was not executed",
                "raw_node_count": 0,
                "raw_edge_count": 0,
                "normalized_node_count": 0,
                "normalized_edge_count": 0,
                "language_coverage": {
                    "by_extension": {},
                    "unsupported_extensions": {},
                    "files_without_nodes": [],
                    "rust_files": 0,
                    "rust_files_with_nodes": 0,
                    "script_files": 0,
                    "script_files_with_nodes": 0,
                },
            },
            "semantic": {
                "status": "UNAVAILABLE",
                "reason": "Graphify package unavailable",
                "content_file_count": 0,
                "cached_file_count": 0,
                "uncached_file_count": 0,
                "partial_subagent_results": False,
            },
            "health": {
                "raw": {"raw_node_count": 0, "raw_edge_count": 0, "dangling_edges": 0, "duplicate_node_id_count": 0},
                "normalized": {
                    "raw_node_count": 0,
                    "raw_edge_count": 0,
                    "normalized_node_count": 0,
                    "normalized_edge_count": 0,
                    "dangling_edges": 0,
                    "stable_node_ids": True,
                    "relative_source_files": True,
                },
            },
            "unsupported_surfaces": {"graphify_runtime": {"status": "UNAVAILABLE", "reason": str(exc)}},
            "legacy_artifacts": legacy_artifact(root, current_revision),
            "artifacts": {
                "output_dir": relative_path(output_dir, root),
                "raw_ast": relative_path(raw_path, root),
                "normalized_ast": relative_path(normalized_path, root),
                "report": relative_path(report_path, root),
            },
        }
        write_new(raw_path, json.dumps({"schema": "quicfuscate.graphify-ast.v1", "status": "UNAVAILABLE", "nodes": [], "edges": []}, indent=2) + "\n")
        write_new(normalized_path, json.dumps({"schema": "quicfuscate.graphify-ast-normalized.v1", "status": "UNAVAILABLE", "nodes": [], "edges": []}, indent=2) + "\n")
        write_new(report_path, render_report(manifest))
        return manifest, "Graphify package unavailable"

    detection = detect(root)
    source_scope_sha256, detected_paths, extension_counts = digest_scope(root, detection)
    base_provenance["graphify_version"] = graphify_version
    base_provenance["source_scope_sha256"] = source_scope_sha256
    ignore_patterns = detection.get("graphifyignore_patterns", 0)
    ignore_pattern_count = ignore_patterns if isinstance(ignore_patterns, int) else len(ignore_patterns)
    code_paths = [Path(value) for value in detection.get("files", {}).get("code", [])]
    content_paths = [
        value
        for category in CONTENT_CATEGORIES
        for value in detection.get("files", {}).get(category, [])
    ]
    try:
        cache_module = importlib.import_module("graphify.cache")
        cached_nodes, cached_edges, cached_hyperedges, uncached = cache_module.check_semantic_cache(content_paths, root=root)
        semantic_cache = {
            "cached_node_count": len(cached_nodes),
            "cached_edge_count": len(cached_edges),
            "cached_hyperedge_count": len(cached_hyperedges),
            "cached_file_count": len(content_paths) - len(uncached),
            "uncached_file_count": len(uncached),
        }
    except Exception as exc:
        semantic_cache = {"cached_node_count": 0, "cached_edge_count": 0, "cached_hyperedge_count": 0, "cached_file_count": 0, "uncached_file_count": len(content_paths), "cache_error": str(exc)}
    credentials = [name for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY") if os.environ.get(name)]
    if not content_paths or semantic_cache["uncached_file_count"] == 0:
        semantic_status = "PASS"
        semantic_reason = "all semantic input files are covered by cache"
    elif credentials:
        semantic_status = "PARTIAL"
        semantic_reason = "semantic credentials exist but this deterministic evidence gate does not execute LLM extraction"
    else:
        semantic_status = "UNAVAILABLE"
        semantic_reason = "neither GEMINI_API_KEY nor GOOGLE_API_KEY is available"
    semantic = {
        "status": semantic_status,
        "reason": semantic_reason,
        "credential_sources_present": credentials,
        "content_file_count": len(content_paths),
        **semantic_cache,
        "partial_subagent_results": False,
    }

    raw: dict[str, Any]
    raw_path = output_dir / "raw-ast.json"
    normalized_path = output_dir / "normalized-ast.json"
    try:
        raw = extract_module.extract(code_paths, cache_root=output_dir, parallel=False)
        write_new(raw_path, json.dumps(raw, indent=2, ensure_ascii=False) + "\n")
        normalized, normalized_health = normalize_ast(raw, root)
        write_new(normalized_path, json.dumps(normalized, indent=2, ensure_ascii=False) + "\n")
    except Exception as exc:
        extraction_reason = f"deterministic AST extraction failed: {type(exc).__name__}: {exc}"
        legacy = legacy_artifact(root, current_revision)
        manifest = {
            "schema": SCHEMA,
            "status": "FAIL",
            "status_reasons": [extraction_reason],
            "provenance": base_provenance,
            "scope": scope,
            "detection": {
                "status": "PASS",
                "total_files": detection.get("total_files", 0),
                "total_words": detection.get("total_words", 0),
                "category_counts": {key: len(value) for key, value in detection.get("files", {}).items() if isinstance(value, list)},
                "extension_counts": extension_counts,
                "skipped_sensitive_count": len(detection.get("skipped_sensitive", [])),
                "graphifyignore_pattern_count": ignore_pattern_count,
                "detected_path_count": len(detected_paths),
            },
            "extraction": {
                "status": "FAIL",
                "reason": extraction_reason,
                "raw_node_count": 0,
                "raw_edge_count": 0,
                "normalized_node_count": 0,
                "normalized_edge_count": 0,
                "language_coverage": {
                    "by_extension": {},
                    "unsupported_extensions": {},
                    "files_without_nodes": [],
                    "rust_files": 0,
                    "rust_files_with_nodes": 0,
                    "script_files": 0,
                    "script_files_with_nodes": 0,
                },
            },
            "semantic": semantic,
            "health": {
                "raw": {"raw_node_count": 0, "raw_edge_count": 0, "dangling_edges": 0, "duplicate_node_id_count": 0},
                "normalized": {
                    "raw_node_count": 0,
                    "raw_edge_count": 0,
                    "normalized_node_count": 0,
                    "normalized_edge_count": 0,
                    "dangling_edges": 0,
                    "stable_node_ids": True,
                    "relative_source_files": True,
                },
            },
            "unsupported_surfaces": {"ast_runtime": extraction_reason},
            "legacy_artifacts": legacy,
            "artifacts": {
                "output_dir": relative_path(output_dir, root),
                "raw_ast": relative_path(raw_path, root),
                "normalized_ast": relative_path(normalized_path, root),
            },
        }
        write_new(raw_path, json.dumps({"schema": "quicfuscate.graphify-ast.v1", "status": "FAIL", "nodes": [], "edges": []}, indent=2) + "\n")
        write_new(normalized_path, json.dumps({"schema": "quicfuscate.graphify-ast-normalized.v1", "status": "FAIL", "nodes": [], "edges": []}, indent=2) + "\n")
        report_path = output_dir / "GRAPH_REPORT.md"
        manifest["artifacts"]["report"] = relative_path(report_path, root)
        write_new(report_path, render_report(manifest))
        return manifest, extraction_reason

    raw_nodes = raw.get("nodes") if isinstance(raw.get("nodes"), list) else []
    raw_edges = raw.get("edges") if isinstance(raw.get("edges"), list) else []
    raw_node_ids = {
        node.get("id")
        for node in raw_nodes
        if isinstance(node, dict) and node.get("id") is not None
    }
    coverage = language_coverage(root, code_paths, raw_nodes, extract_module)
    raw_health = {
        "raw_node_count": len(raw_nodes),
        "raw_edge_count": len(raw_edges),
        "dangling_edges": sum(
            1
            for edge in raw_edges
            if isinstance(edge, dict)
            and (
                edge.get("source") not in raw_node_ids or edge.get("target") not in raw_node_ids
            )
        ),
        "duplicate_node_id_count": sum(
            count - 1
            for count in collections.Counter(node.get("id") for node in raw_nodes if isinstance(node, dict)).values()
            if count > 1
        ),
        "absolute_source_file_count": sum(
            1 for node in raw_nodes if isinstance(node, dict) and str(node.get("source_file", "")).startswith("/")
        ),
    }
    extraction_status = "PASS"
    if (
        not normalized_health["stable_node_ids"]
        or normalized_health["dangling_edges"] != 0
        or normalized_health["ambiguous_endpoint_edges"]
        or normalized_health["unresolved_endpoint_edges"]
        or raw_health["dangling_edges"]
        or raw_health["duplicate_node_id_count"]
        or coverage["unsupported_extensions"]
        or coverage["files_without_nodes"]
    ):
        extraction_status = "BLOCKED"
    extraction = {
        "status": extraction_status,
        "raw_node_count": len(raw_nodes),
        "raw_edge_count": len(raw_edges),
        "normalized_node_count": normalized_health["normalized_node_count"],
        "normalized_edge_count": normalized_health["normalized_edge_count"],
        "language_coverage": coverage,
        "raw_source_identity": "absolute-or-tool-defined",
        "normalized_source_identity": "relative-path-plus-content-addressed-node-id",
    }
    health = {"raw": raw_health, "normalized": normalized_health}
    unsupported = {
        "semantic": semantic,
        "sensitive_files": {"status": "ACCOUNTED_REDACTED", "count": len(detection.get("skipped_sensitive", []))},
        "unsupported_code_extensions": coverage["unsupported_extensions"],
        "code_files_without_ast_nodes": {"count": len(coverage["files_without_nodes"]), "paths_redacted": False, "paths": coverage["files_without_nodes"][:100]},
        "parallel_spawn_boundary": {"status": "AVOIDED", "reason": "sequential extraction is used to avoid stdin/process-spawn partial-output risk"},
    }
    legacy = legacy_artifact(root, current_revision)
    reasons: list[str] = []
    if semantic_status != "PASS":
        reasons.append(f"semantic extraction status={semantic_status}")
    if raw_health["dangling_edges"] or raw_health["duplicate_node_id_count"]:
        reasons.append("raw AST contains dangling edges or duplicate node IDs")
    if normalized_health["ambiguous_endpoint_edges"] or normalized_health["unresolved_endpoint_edges"]:
        reasons.append("normalized AST contains explicitly unresolved or ambiguous endpoint edges")
    if coverage["unsupported_extensions"] or coverage["files_without_nodes"]:
        reasons.append("language/file coverage is incomplete")
    if legacy["stale"]:
        reasons.append("legacy Graphify artifact is stale or lacks provenance")
    status = "PASS" if not reasons else "BLOCKED"
    manifest = {
        "schema": SCHEMA,
        "status": status,
        "status_reasons": reasons,
        "provenance": base_provenance,
        "scope": scope,
        "detection": {
            "status": "PASS",
            "scan_root": detection.get("scan_root"),
            "total_files": detection.get("total_files", 0),
            "total_words": detection.get("total_words", 0),
            "category_counts": {key: len(value) for key, value in detection.get("files", {}).items() if isinstance(value, list)},
            "extension_counts": extension_counts,
            "skipped_sensitive_count": len(detection.get("skipped_sensitive", [])),
            "graphifyignore_pattern_count": ignore_pattern_count,
            "detected_path_count": len(detected_paths),
        },
        "extraction": extraction,
        "semantic": semantic,
        "health": health,
        "unsupported_surfaces": unsupported,
        "legacy_artifacts": legacy,
        "artifacts": {
            "output_dir": relative_path(output_dir, root),
            "raw_ast": relative_path(raw_path, root),
            "normalized_ast": relative_path(normalized_path, root),
        },
    }
    report_path = output_dir / "GRAPH_REPORT.md"
    manifest["artifacts"]["report"] = relative_path(report_path, root)
    write_new(report_path, render_report(manifest))
    return manifest, "; ".join(reasons) if reasons else "all Graphify evidence contracts pass"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.project_root.resolve()
    if not (root / ".git").exists():
        print(f"error: project root is not a Git worktree: {root}", file=sys.stderr)
        return 1
    try:
        output_dir = create_output_dir(root, str(args.output_dir) if args.output_dir else None)
        manifest, reason = build_manifest(root, output_dir)
        manifest_path = output_dir / "graphify-evidence.json"
        write_new(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        print(f"GRAPHIFY_EVIDENCE_STATUS={manifest['status']}")
        print(f"GRAPHIFY_EVIDENCE_PATH={relative_path(manifest_path, root)}")
        print(f"GRAPHIFY_EVIDENCE_REASON={reason}")
        if manifest["status"] == "PASS":
            return 0
        if manifest["status"] in {"BLOCKED", "UNAVAILABLE"}:
            return 2
        return 1
    except Exception as exc:
        print(f"GRAPHIFY_EVIDENCE_STATUS=FAIL", file=sys.stderr)
        print(f"GRAPHIFY_EVIDENCE_REASON={type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
