"""Shared helpers for Role B graph tests (synthetic fixtures, not real scans)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def mod(path: str = ".", lock: str | None = "package-lock.json", mid: str | None = None) -> dict[str, Any]:
    prefix = "" if path == "." else path + "/"
    return {
        "module_id": mid or f"mod:{path}", "relative_path": path, "ecosystem": "npm",
        "manifests": [prefix + "package.json"], "lockfiles": [prefix + lock] if lock else [],
        "ci_files": [], "dockerfiles": [], "coverage": "PARTIAL", "coverage_reason": "pending",
        "scanner_names": [], "file_counts": {}, "scan_stage": {}, "artifact_sbom_status": "NOT_RUN",
    }


def write_project(root: Path, pkg: dict, packages: dict | None, version: int = 3, subdir: str = ".") -> None:
    d = root if subdir == "." else root / subdir
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    if packages is not None:
        (d / "package-lock.json").write_text(json.dumps({
            "name": pkg.get("name", "x"), "version": "1.0.0", "lockfileVersion": version,
            "requires": True, "packages": packages}), encoding="utf-8")


def comp_by_name(graph: dict, name: str, version: str | None = None) -> list[dict]:
    data = graph.model_dump(mode="json") if hasattr(graph, "model_dump") else graph
    return [c for c in data["components"] if c["name"] == name and (version is None or c["resolved_version"] == version)]


def edge_pairs(graph: dict) -> set[tuple[str, str]]:
    data = graph.model_dump(mode="json") if hasattr(graph, "model_dump") else graph
    names = {c["occurrence_id"]: f"{c['name']}@{c['resolved_version']}" for c in data["components"]}
    names.update({m["module_id"]: "<root>" for m in data["modules"]})
    return {(names[e["source_id"]], names[e["target_id"]]) for e in data["edges"] if e["relationship"] == "DEPENDS_ON"}


# Hand-checked fixture: nested duplicate versions, scoped name, dev dep, 3-level chain.
NESTED_PKG = {"name": "app", "version": "1.0.0",
              "dependencies": {"a": "1.0.0", "b": "1.0.0", "@sc/s": "1.0.0"},
              "devDependencies": {"devtool": "1.0.0"}}
NESTED_LOCK = {
    "": {"name": "app", "version": "1.0.0",
         "dependencies": {"a": "1.0.0", "b": "1.0.0", "@sc/s": "1.0.0"},
         "devDependencies": {"devtool": "1.0.0"}},
    "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^1.0.0"}},
    "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "^2.0.0"}},
    "node_modules/b/node_modules/c": {"version": "2.0.0", "dependencies": {"deep": "1.0.0"}},
    "node_modules/c": {"version": "1.0.0"},
    "node_modules/deep": {"version": "1.0.0"},
    "node_modules/@sc/s": {"version": "1.0.0", "hasInstallScript": True},
    "node_modules/devtool": {"version": "1.0.0", "dev": True},
}
