#!/usr/bin/env python3
"""Audit the current Rust workspace seam graph without compiling product code."""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "quicfuscate.workspace-seams.v1"
PROTECTED_PREFIXES = (
    "apps/svelte-admin/",
    "apps/svelte-desktop/",
    "apps/tauri/",
    "packages/ui/",
    "packages/theme/",
    "assets/web-admin/",
)
MOD_RE = re.compile(r"^(?:pub\s+)?mod\s+([A-Za-z_]\w*)", re.MULTILINE)
CRATE_REF_RE = re.compile(r"\bcrate::([A-Za-z_]\w*)")
CRATE_BRACED_RE = re.compile(r"\bcrate::\{([^}]*)\}", re.DOTALL)


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def run(root: Path, command: list[str]) -> str:
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        output = (result.stdout + result.stderr).strip()
        fail(f"command failed ({result.returncode}): {' '.join(command)}\n{output}")
    return result.stdout


def relative_owner(path: Path, root: Path, top_modules: set[str]) -> str:
    relative = path.relative_to(root)
    if relative.parts[0] == "crates":
        if len(relative.parts) < 3 or relative.parts[2] != "src":
            fail(f"workspace crate source path is outside its src directory: {path}")
        return relative.parts[1]
    parts = relative.relative_to(Path("src")).parts
    first = parts[0]
    if first == "lib.rs":
        return "__root__"
    if first in top_modules:
        return first.removesuffix(".rs")
    if first == "core_parts":
        return "core"
    if first == "main_parts":
        return "main"
    if first == "bin":
        return "bin"
    return first.removesuffix(".rs")


def source_inventory(root: Path) -> dict[str, Any]:
    lib_path = root / "src/lib.rs"
    top_modules = set(MOD_RE.findall(lib_path.read_text(encoding="utf-8")))
    source_roots = [root / "src"]
    source_roots.extend(
        path / "src"
        for path in sorted((root / "crates").iterdir())
        if path.is_dir() and (path / "src").is_dir()
    )
    files = sorted({path for source_root in source_roots for path in source_root.rglob("*.rs")})
    stats: dict[str, dict[str, int]] = collections.defaultdict(lambda: {"files": 0, "lines": 0})
    edges: dict[tuple[str, str], dict[str, Any]] = {}

    for path in files:
        owner = relative_owner(path, root, top_modules)
        text = path.read_text(encoding="utf-8")
        stats[owner]["files"] += 1
        stats[owner]["lines"] += len(text.splitlines())
        destinations = [match.group(1) for match in CRATE_REF_RE.finditer(text)]
        for match in CRATE_BRACED_RE.finditer(text):
            for item in match.group(1).split(","):
                name = re.match(r"\s*([A-Za-z_]\w*)", item)
                if name:
                    destinations.append(name.group(1))
        for destination in destinations:
            if destination not in top_modules or destination == owner:
                continue
            key = (owner, destination)
            edge = edges.setdefault(key, {"references": 0, "files": set()})
            edge["references"] += 1
            edge["files"].add(path.relative_to(root).as_posix())

    graph: dict[str, set[str]] = collections.defaultdict(set)
    for owner in stats:
        graph[owner]
    for source, destination in edges:
        graph[source].add(destination)
        graph[destination]

    components = strongly_connected_components(graph)
    component_by_node = {node: index for index, component in enumerate(components) for node in component}
    serialized_edges = []
    for (source, destination), edge in sorted(edges.items()):
        serialized_edges.append(
            {
                "source": source,
                "target": destination,
                "references": edge["references"],
                "files": sorted(edge["files"]),
                "cycle": component_by_node[source] == component_by_node[destination]
                and len(components[component_by_node[source]]) > 1,
            }
        )

    return {
        "source_files": len(files),
        "source_lines": sum(item["lines"] for item in stats.values()),
        "top_modules": sorted(top_modules),
        "module_stats": {name: stats[name] for name in sorted(stats)},
        "edges": serialized_edges,
        "strongly_connected_components": [component for component in components if len(component) > 1],
    }


def strongly_connected_components(graph: dict[str, set[str]]) -> list[list[str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(graph[node]):
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] != indices[node]:
            return
        component: list[str] = []
        while True:
            target = stack.pop()
            on_stack.remove(target)
            component.append(target)
            if target == node:
                break
        components.append(sorted(component))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return sorted(components, key=lambda component: (component[0], len(component)))


def cargo_inventory(root: Path) -> dict[str, Any]:
    metadata = json.loads(run(root, ["cargo", "metadata", "--no-deps", "--format-version", "1"]))
    workspace_ids = set(metadata["workspace_members"])
    packages = [package for package in metadata["packages"] if package["id"] in workspace_ids]
    if not packages:
        fail("current workspace has no package metadata")

    def package_inventory(package: dict[str, Any]) -> dict[str, Any]:
        dependency_names = sorted({dependency["name"] for dependency in package["dependencies"]})
        dependencies_by_kind: dict[str, set[str]] = collections.defaultdict(set)
        for dependency in package["dependencies"]:
            dependencies_by_kind[dependency.get("kind") or "normal"].add(dependency["name"])
        targets = [
            {
                "name": target["name"],
                "kind": sorted(target["kind"]),
                "required_features": sorted(target.get("required-features") or []),
            }
            for target in package["targets"]
        ]
        return {
            "name": package["name"],
            "version": package["version"],
            "dependencies": dependency_names,
            "dependencies_by_kind": {
                kind: sorted(names) for kind, names in sorted(dependencies_by_kind.items())
            },
            "features": sorted(package["features"]),
            "targets": sorted(targets, key=lambda target: (target["name"], target["kind"])),
        }

    root_manifest = (root / "Cargo.toml").resolve()
    root_packages = [
        package
        for package in packages
        if Path(package["manifest_path"]).resolve() == root_manifest
    ]
    if len(root_packages) != 1:
        fail(f"expected one root package, found {len(root_packages)}")
    package = root_packages[0]
    workspace_names = {item["name"] for item in packages}
    workspace_dependency_edges = [
        {
            "source": item["name"],
            "target": dependency["name"],
            "kind": dependency.get("kind") or "normal",
        }
        for item in packages
        for dependency in item["dependencies"]
        if dependency["name"] in workspace_names
    ]
    workspace_dependency_edges.sort(key=lambda edge: (edge["source"], edge["target"], edge["kind"]))
    inventories = [package_inventory(item) for item in packages]
    return {
        "workspace_members": sorted(workspace_names),
        "workspace_packages": sorted(inventories, key=lambda item: item["name"]),
        "workspace_dependency_edges": workspace_dependency_edges,
        "package": package["name"],
        "version": package["version"],
        **{
            key: value
            for key, value in package_inventory(package).items()
            if key not in {"name", "version"}
        },
    }


def protected_changes(root: Path) -> list[str]:
    names = set(run(root, ["git", "diff", "--name-only", "HEAD"]).splitlines())
    names.update(run(root, ["git", "ls-files", "--others", "--exclude-standard"]).splitlines())
    return sorted(
        name for name in names if any(name.startswith(prefix) for prefix in PROTECTED_PREFIXES)
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--json-out", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.project_root.resolve()
    if not (root / ".git").exists():
        fail(f"project root is not a Git worktree: {root}")
    report = {
        "schema": SCHEMA,
        "source_revision": run(root, ["git", "rev-parse", "HEAD"]).strip(),
        "cargo": cargo_inventory(root),
        "source": source_inventory(root),
        "protected_changes": protected_changes(root),
    }
    if report["protected_changes"]:
        fail("protected frontend/Tauri paths changed: " + ", ".join(report["protected_changes"]))
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        output = args.json_out if args.json_out.is_absolute() else root / args.json_out
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("x", encoding="utf-8") as handle:
                handle.write(payload)
        except FileExistsError:
            fail(f"refusing to overwrite existing report: {output}")
        try:
            display = output.relative_to(root)
        except ValueError:
            display = output
        print(f"WORKSPACE_SEAMS_REPORT={display}")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
