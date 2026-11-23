"""Bounded graph queries over graph.sqlite (Role B; project.md §6.5, §7.7, §9.4).

All traversals use a visited set and hard caps; they never enumerate all simple
paths. Only resolved ``DEPENDS_ON`` edges count toward a path; UNRESOLVED
``DECLARES`` edges are ignored so unknown parents are never papered over.
``NO_KNOWN_PATH`` never means proved unreachable.

Return shapes (exact key sets):
  get_dependency_path -> PATH_KEYS, ``status`` in PATH_STATUSES
  get_neighbors       -> NEIGHBOR_KEYS
  get_reverse_impact  -> IMPACT_KEYS
"""

from __future__ import annotations

import json
import sqlite3
from collections import deque
from typing import Any

MAX_VISITED = 200_000
_RESOLVED = "relationship='DEPENDS_ON' AND resolution IN ('OBSERVED','INFERRED')"

PATH_STATUSES = ("FOUND", "NO_KNOWN_PATH", "UNRESOLVED", "TRUNCATED", "NOT_FOUND")
PATH_KEYS = ("scan_id", "module_id", "target_occurrence_id", "status", "node_ids", "edge_ids",
             "edge_evidence_ids", "truncated")
NEIGHBOR_KEYS = ("scan_id", "selected_occurrence_id", "direction", "status", "nodes", "edges",
                 "truncated", "coverage_notice")
IMPACT_KEYS = ("scan_id", "selected_occurrence_id", "package_key", "status", "modules",
               "representative_paths", "affected_occurrence_ids", "truncated", "coverage_notice")
COVERAGE_NOTICE = "Graph includes only supported resolved relationships"

_DIRECTIONS = {"in": "dependents", "dependents": "dependents",
               "out": "dependencies", "dependencies": "dependencies", "both": "both"}


def _connect(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _node_info(con: sqlite3.Connection, scan_id: str, node_id: str) -> dict[str, Any] | None:
    r = con.execute("SELECT node_id,module_id,package_key,name,version,directness FROM node "
                    "WHERE scan_id=? AND node_id=?", (scan_id, node_id)).fetchone()
    if r:
        label = f"{r['name']}@{r['version']}" if r["version"] else str(r["name"])
        return {"id": r["node_id"], "type": "occurrence", "label": label, "module_id": r["module_id"],
                "package_key": r["package_key"], "directness": r["directness"]}
    m = con.execute("SELECT module_id,relative_path,coverage FROM module WHERE scan_id=? AND module_id=?",
                    (scan_id, node_id)).fetchone()
    if m:
        return {"id": m["module_id"], "type": "module", "label": m["relative_path"],
                "module_id": m["module_id"], "coverage": m["coverage"]}
    return None


def _path_result(scan_id: str, module_id: str, occ: str, status: str, nodes=(), edges=(), ev=(),
                 truncated: bool = False) -> dict[str, Any]:
    return {"scan_id": scan_id, "module_id": module_id, "target_occurrence_id": occ, "status": status,
            "node_ids": list(nodes), "edge_ids": list(edges), "edge_evidence_ids": list(ev),
            "truncated": truncated}


def _load_incoming(con: sqlite3.Connection, scan_id: str) -> dict[str, list[tuple[str, str]]]:
    """target -> [(source, edge_id)] for resolved edges; one query per call."""
    inc: dict[str, list[tuple[str, str]]] = {}
    for eid, src, tgt in con.execute(
            f"SELECT edge_id,source,target FROM edge WHERE scan_id=? AND {_RESOLVED} ORDER BY edge_id",
            (scan_id,)):
        inc.setdefault(tgt, []).append((src, eid))
    return inc


def _edge_evidence(con: sqlite3.Connection, scan_id: str, edge_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    ev: list[str] = []
    by_id: dict[str, list[str]] = {}
    for i in range(0, len(edge_ids), 500):
        chunk = edge_ids[i:i + 500]
        q = ",".join("?" * len(chunk))
        for row in con.execute(f"SELECT edge_id,data FROM edge WHERE scan_id=? AND edge_id IN ({q})",
                               (scan_id, *chunk)):
            by_id[row["edge_id"]] = json.loads(row["data"])["evidence_ids"]
    for eid in edge_ids:                       # path order, de-duplicated
        for x in by_id.get(eid, []):
            if x not in seen:
                seen.add(x)
                ev.append(x)
    return ev


def get_dependency_path(db_path: str, scan_id: str, module_id: str, occurrence_id: str) -> dict[str, Any]:
    """Shortest known module-root -> occurrence path (backward BFS, bounded, §7.7).

    ``status``: FOUND | NO_KNOWN_PATH | UNRESOLVED (a package on the search
    frontier has no known declaring parent) | TRUNCATED (visit bound hit) |
    NOT_FOUND (unknown module or occurrence).
    """
    con = _connect(db_path)
    try:
        if _node_info(con, scan_id, occurrence_id) is None or _node_info(con, scan_id, module_id) is None:
            return _path_result(scan_id, module_id, occurrence_id, "NOT_FOUND")
        incoming = _load_incoming(con, scan_id)
        modules = {r[0] for r in con.execute("SELECT module_id FROM module WHERE scan_id=?", (scan_id,))}
        prev: dict[str, tuple[str, str]] = {}      # node -> (child toward target, edge_id)
        seen = {occurrence_id}
        queue: deque[str] = deque([occurrence_id])
        parentless = truncated = False
        found = occurrence_id == module_id
        while queue and not found:
            cur = queue.popleft()
            rows = incoming.get(cur, [])
            if not rows and cur != module_id and cur not in modules:
                parentless = True
            for s, eid in rows:
                if s in seen:
                    continue
                seen.add(s)
                prev[s] = (cur, eid)
                if s == module_id:
                    found = True
                    break
                queue.append(s)
            if len(seen) > MAX_VISITED:
                truncated = True
                break
        if not found:
            status = "TRUNCATED" if truncated else "UNRESOLVED" if parentless else "NO_KNOWN_PATH"
            return _path_result(scan_id, module_id, occurrence_id, status, truncated=truncated)
        nodes, edge_ids, cur = [module_id], [], module_id
        while cur != occurrence_id:
            cur, eid = prev[cur]
            nodes.append(cur)
            edge_ids.append(eid)
        return _path_result(scan_id, module_id, occurrence_id, "FOUND", nodes, edge_ids,
                            _edge_evidence(con, scan_id, edge_ids))
    finally:
        con.close()


def _edge_view(r: sqlite3.Row) -> dict[str, Any]:
    stored = json.loads(r["data"])
    return {"edge_id": r["edge_id"], "source_id": r["source"], "target_id": r["target"],
            "relationship": r["relationship"], "resolution": r["resolution"],
            "dependency_scope": r["scope"],
            "evidence_ids": list(stored.get("evidence_ids", []))}


def get_neighbors(db_path: str, scan_id: str, node_id: str, direction: str = "both",
                  depth: int = 1, max_nodes: int = 150) -> dict[str, Any]:
    """Bounded neighborhood (§7.7). ``direction``: dependents|in, dependencies|out, both.

    ``status`` is FOUND, TRUNCATED (a bound cut the result) or NOT_FOUND.
    """
    if direction not in _DIRECTIONS:
        raise ValueError("direction must be one of: dependents/in, dependencies/out, both")
    norm = _DIRECTIONS[direction]
    depth = max(0, min(int(depth), 10))
    max_nodes = max(1, min(int(max_nodes), 1000))
    con = _connect(db_path)
    try:
        def result(status, nodes=(), edges=(), truncated=False, notice=COVERAGE_NOTICE):
            return {"scan_id": scan_id, "selected_occurrence_id": node_id, "direction": norm,
                    "status": status, "nodes": list(nodes), "edges": list(edges),
                    "truncated": truncated, "coverage_notice": notice}

        if _node_info(con, scan_id, node_id) is None:
            return result("NOT_FOUND", notice="Selected node is not in the graph")
        nodes = {node_id}
        edges: dict[str, dict[str, Any]] = {}
        frontier = [node_id]
        truncated = False
        for _ in range(depth):
            nxt: list[str] = []
            for cur in frontier:
                sides = []
                if norm in ("dependencies", "both"):
                    sides.append(("source", "target"))
                if norm in ("dependents", "both"):
                    sides.append(("target", "source"))
                for near, far in sides:
                    rows = con.execute(
                        f"SELECT edge_id,source,target,relationship,resolution,scope,data FROM edge "
                        f"WHERE scan_id=? AND {near}=? ORDER BY edge_id LIMIT ?",
                        (scan_id, cur, max_nodes + 1)).fetchall()
                    if len(rows) > max_nodes:
                        truncated = True
                    for r in rows[:max_nodes]:
                        other = r[far]
                        if other not in nodes:
                            if len(nodes) >= max_nodes:
                                truncated = True
                                continue
                            nodes.add(other)
                            nxt.append(other)
                        edges[r["edge_id"]] = _edge_view(r)
            frontier = nxt
            if not frontier:
                break
        keep = [v for v in edges.values() if v["source_id"] in nodes and v["target_id"] in nodes]
        infos = [i for i in (_node_info(con, scan_id, n) for n in sorted(nodes)) if i]
        return result("TRUNCATED" if truncated else "FOUND", infos, keep, truncated)
    finally:
        con.close()


def get_reverse_impact(db_path: str, scan_id: str, occurrence_id: str, max_modules: int = 100) -> dict[str, Any]:
    """Module roots that (transitively) depend on this occurrence's package identity.

    Identity-level: every occurrence sharing ``package_key`` is a start point; an
    occurrence without a package_key is queried by itself. ``representative_paths``
    maps each module root to one shortest root-to-start path (node IDs).
    ``status``: FOUND | NO_KNOWN_PATH | TRUNCATED | NOT_FOUND.
    """
    con = _connect(db_path)
    try:
        def result(status, key=None, modules=(), paths=None, starts=(), truncated=False, notice=COVERAGE_NOTICE):
            return {"scan_id": scan_id, "selected_occurrence_id": occurrence_id, "package_key": key,
                    "status": status, "modules": list(modules), "representative_paths": paths or {},
                    "affected_occurrence_ids": list(starts), "truncated": truncated,
                    "coverage_notice": notice}

        r = con.execute("SELECT package_key FROM node WHERE scan_id=? AND node_id=?",
                        (scan_id, occurrence_id)).fetchone()
        if r is None:
            return result("NOT_FOUND", notice="Selected occurrence is not in the graph")
        starts = [occurrence_id]
        if r["package_key"]:
            starts = sorted(x["node_id"] for x in con.execute(
                "SELECT node_id FROM node WHERE scan_id=? AND package_key=?", (scan_id, r["package_key"])))
        incoming = _load_incoming(con, scan_id)
        module_ids = {m[0] for m in con.execute("SELECT module_id FROM module WHERE scan_id=?", (scan_id,))}
        prev: dict[str, str] = {}                 # node -> next node toward a start occurrence
        seen = set(starts)
        queue = deque(starts)
        modules: list[str] = []
        truncated = False
        while queue:
            cur = queue.popleft()
            for s, _eid in incoming.get(cur, []):
                if s in seen:
                    continue
                seen.add(s)
                prev[s] = cur
                if s in module_ids:
                    if len(modules) >= max_modules:
                        truncated = True
                        continue
                    modules.append(s)
                else:
                    queue.append(s)
            if len(seen) > MAX_VISITED:
                truncated = True
                break
        paths: dict[str, list[str]] = {}
        for m in modules:
            chain, cur = [m], m
            while cur in prev:
                cur = prev[cur]
                chain.append(cur)
            paths[m] = chain
        status = "TRUNCATED" if truncated else "FOUND" if modules else "NO_KNOWN_PATH"
        return result(status, r["package_key"], sorted(modules), paths, starts, truncated)
    finally:
        con.close()
