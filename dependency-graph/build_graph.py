#!/usr/bin/env python3
"""Guardian Scout - dependency graph builder for npm projects.

Reads package.json + package-lock.json (lockfile v2/v3) WITHOUT installing anything,
builds the dependency graph (direct vs transitive, runtime vs dev), looks up known
vulnerabilities in OSV.dev, and writes:

  graph.json            nodes, edges, dependency paths, flags
  sbom.cdx.json         CycloneDX 1.5 SBOM generated from the lockfile
  vulnerabilities.json  vulnerable packages with advisories, severity, fixed versions, paths
  graph.html            interactive, self-contained graph (open in any browser, works offline)
  graph-direct.png      root + direct dependencies, coloured by the worst issue below them
  graph-vulnerable-paths.png   runtime paths from the app to every vulnerable package
  summary.md            numbers + top risks (pasted into the README)
  raw/                  raw OSV responses + hashes (evidence)

Usage:
  python -I build_graph.py --repo ../sandbox/sample-app --out .
  python -I build_graph.py --repo ../sandbox/sample-app --out . --no-osv     # offline
"""
import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import urllib.request
import uuid
from collections import defaultdict, deque

SCRIPT_VERSION = "0.1.0"
ROOT = "__root__"
OFFICIAL_REGISTRY = "https://registry.npmjs.org/"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
UA = {"User-Agent": "guardian-depgraph/0.1", "Content-Type": "application/json"}
SEV_RANK = {"MALICIOUS": 5, "CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "UNKNOWN": 0.5}


# ----------------------------------------------------------------------------- helpers
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo, *args):
    try:
        return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def name_from_path(path):
    return path.rsplit("node_modules/", 1)[-1]


def parent_path(path):
    idx = path.rfind("/node_modules/")
    return "" if idx == -1 else path[:idx]


def resolve(pkgs, from_path, dep):
    """Node.js module resolution over lockfile install paths."""
    p = from_path
    while True:
        cand = f"{p}/node_modules/{dep}" if p else f"node_modules/{dep}"
        if cand in pkgs:
            entry = pkgs[cand]
            if entry.get("link") and entry.get("resolved") in pkgs:
                return entry["resolved"]
            return cand
        if p == "":
            return None
        p = parent_path(p)


def semver_key(v):
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?", str(v))
    if not m:
        return (0, 0, 0, 0, ())
    pre = m.group(4)
    pre_key = tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre.split(".")) if pre else ()
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), 0 if pre else 1, pre_key)


def cvss3_score(vector):
    """CVSS v3.x base score from a vector string (returns None if not parseable)."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
             "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0}}
        changed = parts["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[parts["PR"]]
        iss = 1 - (1 - W["CIA"][parts["C"]]) * (1 - W["CIA"][parts["I"]]) * (1 - W["CIA"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * W["AV"][parts["AV"]] * W["AC"][parts["AC"]] * pr * W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if changed else min(impact + expl, 10)
        i = round(raw * 100000)
        return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0
    except Exception:
        return None


def sev_from_score(s):
    if s is None:
        return "UNKNOWN"
    if s >= 9:
        return "CRITICAL"
    if s >= 7:
        return "HIGH"
    if s >= 4:
        return "MODERATE"
    if s > 0:
        return "LOW"
    return "UNKNOWN"


def http_json(url, body=None, timeout=60, attempts=4):
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, data=data, headers=UA, method="POST" if body is not None else "GET")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # network hiccup: back off and retry
            last = e
            import time
            time.sleep(1.5 * (i + 1))
    raise last


# ----------------------------------------------------------------------------- graph
def build_graph(repo):
    with open(os.path.join(repo, "package.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    lock_path = os.path.join(repo, "package-lock.json")
    with open(lock_path, encoding="utf-8") as f:
        lock = json.load(f)
    if "packages" not in lock:
        sys.exit("package-lock.json has no 'packages' map (lockfile v1). Run: "
                 "npm install --package-lock-only --ignore-scripts   (npm 7+) and retry.")
    pkgs = lock["packages"]
    root_entry = pkgs.get("", {})

    nodes = {}          # key name@version -> node dict
    path_to_key = {}
    for path, e in pkgs.items():
        if path == "" or e.get("link") or "version" not in e:
            continue
        name = e.get("name") or name_from_path(path)
        key = f"{name}@{e['version']}"
        path_to_key[path] = key
        n = nodes.setdefault(key, {
            "id": key, "name": name, "version": e["version"], "install_paths": [], "resolved": set(),
            "integrity": e.get("integrity"), "license": e.get("license"), "install_script": False,
            "runtime": False, "optional": True, "direct": None, "spec": None, "deprecated": e.get("deprecated"),
        })
        n["install_paths"].append(path)
        if e.get("resolved"):
            n["resolved"].add(e["resolved"])
        if e.get("hasInstallScript"):
            n["install_script"] = True
        if not (e.get("dev") or e.get("devOptional")):
            n["runtime"] = True
        if not e.get("optional"):  # optional only if EVERY installed copy is optional
            n["optional"] = False

    edges = set()
    unresolved = []

    def add_deps(from_path, from_key, entry, fields):
        for field in fields:
            for dep in (entry.get(field) or {}):
                tp = resolve(pkgs, from_path, dep)
                if tp is None or tp not in path_to_key:
                    if field not in ("optionalDependencies", "peerDependencies"):
                        meta = entry.get("peerDependenciesMeta", {})
                        if not meta.get(dep, {}).get("optional"):
                            unresolved.append(f"{from_key} -> {dep}")
                    continue
                edges.add((from_key, path_to_key[tp]))

    # root edges + direct flags
    root_fields = {"dependencies": "runtime", "optionalDependencies": "runtime", "devDependencies": "dev"}
    for field, kind in root_fields.items():
        for dep, spec in (root_entry.get(field) or manifest.get(field) or {}).items():
            tp = resolve(pkgs, "", dep)
            if tp is None or tp not in path_to_key:
                unresolved.append(f"root -> {dep}")
                continue
            key = path_to_key[tp]
            edges.add((ROOT, key))
            if nodes[key]["direct"] != "runtime":
                nodes[key]["direct"] = kind
            nodes[key]["spec"] = (manifest.get(field) or {}).get(dep, spec)
    for path, key in path_to_key.items():
        add_deps(path, key, pkgs[path], ("dependencies", "optionalDependencies", "peerDependencies"))

    adj = defaultdict(set)
    for a, b in edges:
        adj[a].add(b)

    # BFS over the full graph and over the runtime-only graph
    def bfs(runtime_only):
        depth, preds = {ROOT: 0}, defaultdict(list)
        q = deque([ROOT])
        while q:
            u = q.popleft()
            for v in sorted(adj[u]):
                if runtime_only and not nodes[v]["runtime"]:
                    continue
                if v not in depth:
                    depth[v] = depth[u] + 1
                    preds[v].append(u)
                    q.append(v)
                elif depth[v] == depth[u] + 1:
                    preds[v].append(u)
        return depth, preds

    depth_all, preds_all = bfs(False)
    depth_rt, preds_rt = bfs(True)

    def paths_to(target, preds, cap=5):
        out = []

        def walk(node, acc):
            if len(out) >= cap:
                return
            if node == ROOT:
                out.append(list(reversed(acc)))
                return
            for p in preds.get(node, []):
                walk(p, acc + [p])
        walk(target, [target])
        return out

    for key, n in nodes.items():
        use_rt = n["runtime"] and key in depth_rt
        n["depth"] = (depth_rt if use_rt else depth_all).get(key)
        n["paths"] = paths_to(key, preds_rt if use_rt else preds_all)
        n["resolved"] = sorted(n["resolved"])
        n["non_registry"] = any(not r.startswith(OFFICIAL_REGISTRY) for r in n["resolved"]) if n["resolved"] else False
        n["dependents"] = 0
    for a, b in edges:
        if b in nodes:
            nodes[b]["dependents"] += 1

    unpinned = []
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        for dep, spec in (manifest.get(field) or {}).items():
            s = str(spec)
            if s in ("latest", "*", "") or re.match(r"^(https?:|git(\+|:)|github:|file:)", s) or "/" in s and not s.startswith("@"):
                unpinned.append({"package": dep, "spec": s, "field": field})

    meta = {
        "project": manifest.get("name", "project"), "project_version": manifest.get("version"),
        "lockfile_version": lock.get("lockfileVersion"), "lockfile_sha256": sha256_file(lock_path),
        "repo_url": git(repo, "remote", "get-url", "origin"), "commit": git(repo, "rev-parse", "HEAD"),
        "commit_date": git(repo, "log", "-1", "--format=%cI"),
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "generator": f"guardian build_graph.py {SCRIPT_VERSION} (python {sys.version.split()[0]})",
        "unresolved_edges": unresolved[:50], "unresolved_count": len(unresolved), "unpinned_specs": unpinned,
    }
    return nodes, edges, meta


# ----------------------------------------------------------------------------- OSV
def osv_lookup(nodes, raw_dir):
    os.makedirs(os.path.join(raw_dir, "osv-vulns"), exist_ok=True)
    keys = sorted(nodes)
    ids_by_key = {}
    batches = []
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        body = {"queries": [{"package": {"name": nodes[k]["name"], "ecosystem": "npm"},
                             "version": nodes[k]["version"]} for k in chunk]}
        resp = http_json(OSV_BATCH, body)
        batches.append(resp)
        for k, r in zip(chunk, resp.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            token = r.get("next_page_token")
            while token:  # rare: very many advisories for one package
                more = http_json(OSV_BATCH, {"queries": [{"package": {"name": nodes[k]["name"], "ecosystem": "npm"},
                                                          "version": nodes[k]["version"], "page_token": token}]})
                rr = more["results"][0]
                ids += [v["id"] for v in rr.get("vulns", [])]
                token = rr.get("next_page_token")
            if ids:
                ids_by_key[k] = ids
    with open(os.path.join(raw_dir, "osv-querybatch.json"), "w", encoding="utf-8") as f:
        json.dump({"queried_at": dt.datetime.now(dt.timezone.utc).isoformat(), "responses": batches}, f)

    unique = sorted({i for ids in ids_by_key.values() for i in ids})
    details = {}

    def fetch(vid):
        cache = os.path.join(raw_dir, "osv-vulns", f"{vid}.json")
        if os.path.exists(cache):  # reuse advisories fetched by an earlier run
            with open(cache, encoding="utf-8") as f:
                return vid, json.load(f)
        d = http_json(OSV_VULN + vid)
        with open(cache, "w", encoding="utf-8") as f:
            json.dump(d, f)
        return vid, d
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for vid, d in ex.map(fetch, unique):
            details[vid] = d
    return ids_by_key, details


def summarize_vuln(vid, d, name, version):
    aliases = sorted(a for a in d.get("aliases", []) if a.startswith("CVE-"))
    score, vector = None, None
    for s in d.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS_V3"):
            vector = s.get("score")
            score = cvss3_score(vector)
    sev = (d.get("database_specific") or {}).get("severity")
    sev = {"MEDIUM": "MODERATE"}.get(str(sev).upper(), str(sev).upper()) if sev else sev_from_score(score)
    if vid.startswith("MAL-"):
        sev = "MALICIOUS"
    fixed = set()
    for aff in d.get("affected", []) or []:
        pk = aff.get("package", {})
        if pk.get("ecosystem") != "npm" or pk.get("name") != name:
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed.add(ev["fixed"])
    later = sorted((f for f in fixed if semver_key(f) > semver_key(version)), key=semver_key)
    return {"id": vid, "cves": aliases, "severity": sev if sev in SEV_RANK else "UNKNOWN", "cvss": score,
            "vector": vector, "summary": (d.get("summary") or d.get("details", "")[:160]).strip(),
            "fixed_in": later[0] if later else None, "published": d.get("published")}


# ----------------------------------------------------------------------------- outputs
def purl(name, version):
    if name.startswith("@"):
        scope, pkg = name[1:].split("/", 1)
        return f"pkg:npm/%40{scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def write_sbom(nodes, edges, meta, path):
    comps = []
    for k in sorted(nodes):
        n = nodes[k]
        c = {"type": "library", "bom-ref": purl(n["name"], n["version"]), "name": n["name"].split("/")[-1],
             "version": n["version"], "purl": purl(n["name"], n["version"]),
             "scope": "required" if n["runtime"] else "optional"}
        if n["name"].startswith("@"):
            c["group"] = n["name"].split("/")[0]
        if n.get("integrity"):
            alg, _, b64 = n["integrity"].split(" ")[0].partition("-")
            try:
                c["hashes"] = [{"alg": {"sha512": "SHA-512", "sha1": "SHA-1", "sha256": "SHA-256"}.get(alg, alg.upper()),
                                "content": base64.b64decode(b64).hex()}]
            except Exception:
                pass
        if n.get("license"):
            c["licenses"] = [{"license": {"name": str(n["license"])}}]
        if n["resolved"]:
            c["externalReferences"] = [{"type": "distribution", "url": u} for u in n["resolved"]]
        if not n["runtime"]:
            c["properties"] = [{"name": "cdx:npm:package:development", "value": "true"}]
        comps.append(c)
    deps = defaultdict(list)
    for a, b in edges:
        deps["root" if a == ROOT else purl(nodes[a]["name"], nodes[a]["version"])].append(
            purl(nodes[b]["name"], nodes[b]["version"]))
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": meta["generated_at"],
                     "tools": {"components": [{"type": "application", "name": "guardian-build-graph",
                                               "version": SCRIPT_VERSION}]},
                     "component": {"type": "application", "bom-ref": "root", "name": meta["project"],
                                   "version": meta.get("project_version") or "0"}},
        "components": comps,
        "dependencies": [{"ref": "root", "dependsOn": sorted(deps.get("root", []))}] +
                        [{"ref": c["bom-ref"], "dependsOn": sorted(deps.get(c["bom-ref"], []))} for c in comps],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=1)


def worst(vulns):
    return max((v["severity"] for v in vulns), key=lambda s: SEV_RANK.get(s, 0)) if vulns else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-osv", action="store_true")
    ap.add_argument("--vis", default=None, help="path to vis-network standalone UMD js (default: vendor/)")
    args = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.abspath(args.out)
    raw = os.path.join(out, "raw")
    os.makedirs(raw, exist_ok=True)

    nodes, edges, meta = build_graph(args.repo)
    print(f"packages: {len(nodes)}  edges: {len(edges)}  unresolved: {meta['unresolved_count']}")

    if not args.no_osv:
        ids_by_key, details = osv_lookup(nodes, raw)
        meta["osv_queried_at"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        for k, n in nodes.items():
            vs = [summarize_vuln(i, details[i], n["name"], n["version"]) for i in ids_by_key.get(k, []) if i in details]
            vs.sort(key=lambda v: (-SEV_RANK.get(v["severity"], 0), -(v["cvss"] or 0)))
            n["vulns"] = vs
            n["risk"] = worst(vs)
    else:
        meta["osv_queried_at"] = None
        for n in nodes.values():
            n["vulns"], n["risk"] = [], None

    # worst issue anywhere below each node (for the direct-dependency view)
    adj = defaultdict(set)
    for a, b in edges:
        adj[a].add(b)

    def below(start):
        seen, stack = set(), [start]
        while stack:
            u = stack.pop()
            for v in adj[u]:
                if v not in seen:
                    seen.add(v)
                    stack.append(v)
        return seen
    for k, n in nodes.items():
        if n["direct"]:
            sub = below(k) | {k}
            vul = [x for x in sub if nodes[x]["risk"]]
            n["subtree_size"] = len(sub) - 1
            n["subtree_vulnerable"] = len(vul)
            n["subtree_worst"] = worst([{"severity": nodes[x]["risk"]} for x in vul]) if vul else None

    # ---- stats
    vul_nodes = [n for n in nodes.values() if n["risk"]]
    sev_counts = defaultdict(int)
    for n in vul_nodes:
        sev_counts[n["risk"]] += 1
    stats = {
        "packages": len(nodes), "edges": len(edges),
        "runtime_packages": sum(1 for n in nodes.values() if n["runtime"]),
        "dev_packages": sum(1 for n in nodes.values() if not n["runtime"]),
        "direct_runtime": sum(1 for n in nodes.values() if n["direct"] == "runtime"),
        "direct_dev": sum(1 for n in nodes.values() if n["direct"] == "dev"),
        "transitive": sum(1 for n in nodes.values() if not n["direct"]),
        "max_depth": max((n["depth"] or 0) for n in nodes.values()),
        "duplicate_versions": sum(1 for name in {n["name"] for n in nodes.values()}
                                  if sum(1 for m in nodes.values() if m["name"] == name) > 1),
        "install_scripts": sum(1 for n in nodes.values() if n["install_script"]),
        "non_registry": sum(1 for n in nodes.values() if n["non_registry"]),
        "vulnerable_packages": len(vul_nodes),
        "vulnerable_runtime": sum(1 for n in vul_nodes if n["runtime"]),
        "advisories": len({v["id"] for n in vul_nodes for v in n["vulns"]}),
        "by_severity": dict(sev_counts),
    }
    meta["stats"] = stats

    # ---- graph.json
    node_list = []
    for k in sorted(nodes, key=lambda x: (nodes[x]["depth"] if nodes[x]["depth"] is not None else 99, x)):
        n = nodes[k]
        node_list.append({kk: n[kk] for kk in (
            "id", "name", "version", "direct", "spec", "runtime", "optional", "depth", "dependents", "license",
            "resolved", "integrity", "install_script", "non_registry", "deprecated", "install_paths", "paths",
            "vulns", "risk") if kk in n} | ({"subtree_size": n["subtree_size"], "subtree_vulnerable": n["subtree_vulnerable"],
                                            "subtree_worst": n["subtree_worst"]} if n["direct"] else {}))
    graph = {"meta": meta, "root": {"id": ROOT, "name": meta["project"], "version": meta.get("project_version")},
             "nodes": node_list, "edges": [{"from": a, "to": b} for a, b in sorted(edges)]}
    with open(os.path.join(out, "graph.json"), "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=1)

    with open(os.path.join(out, "vulnerabilities.json"), "w", encoding="utf-8") as f:
        json.dump(sorted(({"package": n["id"], "runtime": n["runtime"], "direct": n["direct"], "risk": n["risk"],
                           "paths": n["paths"], "advisories": n["vulns"]} for n in vul_nodes),
                         key=lambda x: (-SEV_RANK.get(x["risk"], 0), not x["runtime"], x["package"])), f, indent=1)

    write_sbom(nodes, edges, meta, os.path.join(out, "sbom.cdx.json"))

    # ---- evidence hashes
    ev = {}
    for fn in ("graph.json", "vulnerabilities.json", "sbom.cdx.json", "raw/osv-querybatch.json"):
        p = os.path.join(out, fn)
        if os.path.exists(p):
            ev[fn] = sha256_file(p)
    ev["input:package-lock.json"] = meta["lockfile_sha256"]
    with open(os.path.join(raw, "evidence-hashes.json"), "w", encoding="utf-8") as f:
        json.dump(ev, f, indent=1)

    # ---- renderers (python -I drops the script folder from sys.path, so add it explicitly)
    sys.path.insert(0, here)
    import render_graph
    vis = args.vis or os.path.join(here, "vendor", "vis-network-9.1.9.min.js")
    render_graph.render_html(graph, os.path.join(here, "graph_template.html"), vis, os.path.join(out, "graph.html"))
    render_graph.render_pngs(graph, out)
    summary_md = render_graph.write_summary(graph, os.path.join(out, "summary.md"))
    render_graph.write_readme(graph, summary_md, os.path.join(out, "README.md"))
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
