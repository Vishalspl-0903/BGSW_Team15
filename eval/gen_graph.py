"""Deterministic synthetic GraphBundle generator + baseline traversal benchmark (Role E, PROJECT.md 7.6, 15.E1).

Produces GraphBundle-shaped JSON (PROJECT.md 9.2) for stress sizes such as 100 / 1,000 /
10,000 occurrences.  The same parameters and seed always give byte-identical output.  These
are stress inputs, not claims about supported repository sizes.

Usage
    python -m eval.gen_graph --nodes 10000 --seed 7 --cycles 5 --out runs/bench/graph-10000.json
    python -m eval.gen_graph --nodes 10000 --seed 7 --measure
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import tracemalloc
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

GENERATOR_VERSION = "1.0.0"


def generate(nodes: int, *, seed: int = 7, max_parents: int = 3, direct: int | None = None,
             cycles: int = 0, modules: int = 1) -> dict[str, Any]:
    """Synthetic graph: a DAG from each module root plus ``cycles`` back edges."""
    if nodes < 1 or modules < 1:
        raise ValueError("nodes and modules must be >= 1")
    rng = random.Random(seed)
    direct = direct if direct is not None else max(1, min(25, nodes // 40))
    module_list = [{
        "module_id": f"mod:syn-{m}", "relative_path": "." if m == 0 else f"packages/m{m}", "ecosystem": "npm",
        "manifests": [], "lockfiles": [], "ci_files": [], "dockerfiles": [], "coverage": "RESOLVED",
        "coverage_reason": "", "scanner_names": ["e-synthetic-generator"], "file_counts": {}, "scan_stage": {},
        "artifact_sbom_status": "NOT_RUN",
    } for m in range(modules)]
    components, edges = [], []
    per_module = [list(range(m, nodes, modules)) for m in range(modules)]
    for i in range(nodes):
        m = i % modules
        name, version = f"syn-pkg-{i // 3}", f"1.{i % 3}.0"
        components.append({
            "package_key": f"npm:{name}@{version}", "ecosystem": "npm", "name": name, "resolved_version": version,
            "declared_constraint": f"^{version}", "purl": f"pkg:npm/{name}@{version}", "occurrence_id": f"occ:syn-{i}",
            "module_id": f"mod:syn-{m}", "source_refs": [f"package-lock.json#/packages/node_modules~1{name}"],
            "resolution": "RESOLVED", "evidence_ids": ["ev:syn-lockfile"], "install_stage_indicator": None,
            "dependency_scopes": ["production"], "directness": "TRANSITIVE", "license": None, "artifact_hashes": [],
            "package_source_type": "REGISTRY", "resolved_source_url": None, "registry_host": None,
            "source_scope": "SOURCE", "image_presence": "NOT_CHECKED", "manifest_refs": [],
        })
    for m, members in enumerate(per_module):
        parents: dict[int, list[int]] = {}
        for pos, i in enumerate(members):
            if pos < direct:
                components[i]["directness"] = "DIRECT"
                edges.append((f"mod:syn-{m}", f"occ:syn-{i}"))
                continue
            chosen = sorted(rng.sample(range(pos), min(pos, rng.randint(1, max_parents))))
            parents[pos] = chosen
            for parent_pos in chosen:
                edges.append((f"occ:syn-{members[parent_pos]}", f"occ:syn-{i}"))
        candidates = sorted(parents)
        for _ in range(cycles if candidates else 0):
            # back edge from a node to one of its real ancestors -> guaranteed cycle
            child = rng.choice(candidates)
            ancestor = child
            for _step in range(rng.randint(1, 3)):
                if ancestor not in parents:
                    break
                ancestor = rng.choice(parents[ancestor])
            if ancestor != child:
                edges.append((f"occ:syn-{members[child]}", f"occ:syn-{members[ancestor]}"))
    edge_list = [{
        "edge_id": f"edge:syn-{k}", "source_id": s, "target_id": t, "relationship": "DEPENDS_ON",
        "evidence_ids": ["ev:syn-lockfile"], "module_id": None, "resolution": "OBSERVED",
        "dependency_scope": "production", "declared_constraint": None, "source_scope": "SOURCE",
    } for k, (s, t) in enumerate(dict.fromkeys(edges))]
    summary = {"total_modules": modules, "resolved_modules": modules, "partial_modules": 0,
               "declared_only_modules": 0, "unsupported_modules": 0, "failed_modules": 0}
    return {"schema_version": "1.0", "scan_id": f"synthetic-{nodes}-{seed}", "modules": module_list,
            "components": components, "edges": edge_list, "coverage_summary": summary,
            "warnings": [f"SYNTHETIC graph from eval.gen_graph {GENERATOR_VERSION}; not a scan of any repository"]}


def measure(graph: dict[str, Any]) -> dict[str, Any]:
    """Baseline cost of indexing adjacency and one full BFS per module (reference numbers for B)."""
    tracemalloc.start()
    t0 = time.perf_counter()
    out_adj: dict[str, list[str]] = defaultdict(list)
    for e in graph["edges"]:
        out_adj[e["source_id"]].append(e["target_id"])
    t1 = time.perf_counter()
    reached = 0
    for module in graph["modules"]:
        seen = {module["module_id"]}
        queue = deque([module["module_id"]])
        while queue:
            for nxt in out_adj[queue.popleft()]:
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        reached += len(seen) - 1
    t2 = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"nodes": len(graph["components"]), "edges": len(graph["edges"]), "modules": len(graph["modules"]),
            "index_ms": round((t1 - t0) * 1000, 2), "bfs_all_modules_ms": round((t2 - t1) * 1000, 2),
            "reached_occurrences": reached, "peak_traced_mib": round(peak / 2**20, 2),
            "note": "Python tracemalloc peak during indexing+BFS only; not process RSS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=int, required=True)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-parents", type=int, default=3)
    parser.add_argument("--cycles", type=int, default=0)
    parser.add_argument("--modules", type=int, default=1)
    parser.add_argument("--out")
    parser.add_argument("--measure", action="store_true")
    args = parser.parse_args(argv)
    params = {"nodes": args.nodes, "seed": args.seed, "max_parents": args.max_parents,
              "cycles": args.cycles, "modules": args.modules}
    graph = generate(args.nodes, seed=args.seed, max_parents=args.max_parents, cycles=args.cycles, modules=args.modules)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(graph, separators=(",", ":")), encoding="utf-8")
        meta = {"generator": "eval.gen_graph", "generator_version": GENERATOR_VERSION, "parameters": params,
                "nodes": len(graph["components"]), "edges": len(graph["edges"])}
        out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    if args.measure:
        print(json.dumps({"parameters": params, **measure(graph)}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
