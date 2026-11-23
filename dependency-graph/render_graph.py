"""Renderers for build_graph.py: interactive HTML, two PNGs and a Markdown summary."""
import json
import re
from collections import defaultdict

ROOT = "__root__"
SEV_RANK = {"MALICIOUS": 5, "CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "UNKNOWN": 0.5}
SEV_COLOR = {"MALICIOUS": "#3B0A45", "CRITICAL": "#8E1B1B", "HIGH": "#D64545", "MODERATE": "#E8912D",
             "LOW": "#E9C46A", "UNKNOWN": "#B9A27A"}
NAVY, BLUE, PURPLE, GREY, GREY_DEV = "#17324D", "#2F6FB3", "#7B5EA7", "#9AA7B4", "#CFC6DD"


def _semver_key(v):
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v))
    return tuple(int(x or 0) for x in m.groups()) if m else (0, 0, 0)


def _label(graph, nid):
    return graph["root"]["name"] if nid == ROOT else nid


def _adv_ids(n):
    """CVE id where there is one, else the advisory id; duplicates removed, order kept."""
    seen, out = set(), []
    for v in n["vulns"]:
        i = v["cves"][0] if v["cves"] else v["id"]
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


# ----------------------------------------------------------------------------- HTML
def render_html(graph, template_path, vis_path, out_path):
    with open(template_path, encoding="utf-8") as f:
        tpl = f.read()
    with open(vis_path, encoding="utf-8") as f:
        vis = f.read().replace("</script", "<\\/script")
    data = json.dumps(graph, separators=(",", ":")).replace("</", "<\\/")
    title = f"{graph['root']['name']} dependency graph"
    html = (tpl.replace("__TITLE__", title)
               .replace("/*__VIS__*/", vis)
               .replace("/*__DATA__*/null", data))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


# ----------------------------------------------------------------------------- PNGs
def render_pngs(graph, out_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    nodes = {n["id"]: n for n in graph["nodes"]}
    plt.rcParams["font.family"] = ["Segoe UI", "DejaVu Sans", "Arial", "sans-serif"]

    def legend_handles(extra=()):
        h = [Line2D([0], [0], marker="o", color="w", markerfacecolor=NAVY, markersize=10, label="application")]
        h += list(extra)
        for s in ("MALICIOUS", "CRITICAL", "HIGH", "MODERATE", "LOW"):
            h.append(Line2D([0], [0], marker="o", color="w", markerfacecolor=SEV_COLOR[s], markersize=10,
                            label="malicious-package advisory" if s == "MALICIOUS" else f"{s.lower()} (worst known advisory)"))
        return h

    # ---- 1. direct dependencies
    direct_rt = sorted([n for n in graph["nodes"] if n.get("direct") == "runtime"], key=lambda n: n["name"])
    direct_dev = sorted([n for n in graph["nodes"] if n.get("direct") == "dev"], key=lambda n: n["name"])
    rows = len(direct_rt) + len(direct_dev) + 2
    fig_h = max(7, rows * 0.34 + 1.6)
    fig, ax = plt.subplots(figsize=(13, fig_h), dpi=150)
    ax.set_xlim(-0.2, 3.6)
    ax.set_ylim(-rows - 0.5, 2.9)
    ax.axis("off")
    y_root = -(rows - 1) / 2.0
    ax.scatter([0], [y_root], s=900, c=NAVY, zorder=3)
    ax.text(0, y_root - 0.75, graph["root"]["name"], ha="center", va="top", fontsize=10, weight="bold", color=NAVY)
    y = 0
    for group, items, edge_col in (("Runtime dependencies", direct_rt, BLUE), ("Dev dependencies", direct_dev, PURPLE)):
        ax.text(0.95, y + 0.55, f"{group} ({len(items)})", fontsize=10, weight="bold", color=edge_col)
        for n in items:
            ax.plot([0, 1], [y_root, y], color=edge_col, alpha=0.35, lw=0.9, zorder=1)
            face = SEV_COLOR.get(n.get("risk"), "#FFFFFF")
            ring = SEV_COLOR.get(n.get("subtree_worst"), GREY)
            ax.scatter([1], [y], s=170, c=face, edgecolors=ring, linewidths=2.6, zorder=3)
            txt = f"{n['name']}@{n['version']}"
            if n.get("spec") and n["spec"] != n["version"]:
                spec = str(n["spec"])
                spec = spec if len(spec) <= 24 else spec[:22] + "…"
                txt += f"   (wants {spec})"
            ax.text(1.08, y, txt, va="center", fontsize=8.6, color="#1D2733")
            sub = f"{n.get('subtree_size', 0)} below · {n.get('subtree_vulnerable', 0)} vulnerable"
            flags = []
            if n.get("non_registry"):
                flags.append("NOT FROM REGISTRY")
            if str(n.get("spec")) in ("latest", "*"):
                flags.append("UNPINNED")
            if n.get("install_script"):
                flags.append("install script")
            if flags:
                sub += "  ·  " + ", ".join(flags)
            ax.text(2.45, y, sub, va="center", fontsize=8, color="#5B6B7B")
            y -= 1
        y -= 1
    st = graph["meta"]["stats"]
    ax.text(-0.15, 2.35, f"{graph['root']['name']} — direct dependencies", fontsize=14, weight="bold", color=NAVY)
    ax.text(-0.15, 1.75, f"{st['packages']} packages in total ({st['direct_runtime']} direct runtime, "
                         f"{st['direct_dev']} direct dev, {st['transitive']} transitive) · "
                         f"{st['vulnerable_packages']} with known advisories (OSV, {graph['meta'].get('osv_queried_at') or 'not queried'})."
                         f"  Fill = the package itself, ring = worst issue anywhere below it.",
            fontsize=8.4, color="#5B6B7B")
    ax.legend(handles=legend_handles([Line2D([0], [0], marker="o", color="w", markerfacecolor="#FFFFFF",
                                             markeredgecolor=GREY, markeredgewidth=2, markersize=10,
                                             label="no known advisory")]),
              loc="lower left", fontsize=8, frameon=False, bbox_to_anchor=(0.0, 0.0))
    fig.savefig(f"{out_dir}/graph-direct.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)

    # ---- 2. runtime paths to vulnerable packages
    targets = [n for n in graph["nodes"] if n.get("risk") and n["runtime"]]
    keep, path_edges = {ROOT}, set()
    for n in targets:
        for p in n["paths"][:2]:
            keep.update(p)
            path_edges.update(zip(p, p[1:]))
    depth = {ROOT: 0}
    for nid in keep:
        if nid != ROOT:
            depth[nid] = nodes[nid]["depth"] or 1
    layers = defaultdict(list)
    for nid, d in depth.items():
        layers[d].append(nid)
    preds = defaultdict(list)
    for a, b in path_edges:
        preds[b].append(a)
    order = {ROOT: 0}
    for d in sorted(layers):
        if d == 0:
            continue
        layers[d].sort(key=lambda x: (sum(order.get(p, 0) for p in preds[x]) / max(1, len(preds[x])), x))
        for i, nid in enumerate(layers[d]):
            order[nid] = i
    max_n = max(len(v) for v in layers.values())
    n_layers = max(layers) + 1
    fig, ax = plt.subplots(figsize=(max(12, 3.0 * n_layers), max(6, max_n * 0.56 + 1.8)), dpi=150)
    ax.axis("off")
    pos = {}
    for d, ids in layers.items():
        offset = (max_n - len(ids)) / 2.0
        for i, nid in enumerate(ids):
            pos[nid] = (d * 3.0, -(offset + i))
    for a, b in path_edges:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        ax.annotate("", xy=(x2 - 0.12, y2), xytext=(x1 + 0.12, y1),
                    arrowprops=dict(arrowstyle="-|>", color="#9AA7B4", lw=0.8, shrinkA=0, shrinkB=0), zorder=1)
    for nid, (x, yy) in pos.items():
        if nid == ROOT:
            ax.scatter([x], [yy], s=500, c=NAVY, zorder=3)
            ax.text(x, yy - 0.45, graph["root"]["name"], ha="center", va="top", fontsize=8.5, weight="bold", color=NAVY)
            continue
        n = nodes[nid]
        face = SEV_COLOR.get(n.get("risk"), BLUE if n.get("direct") else "#E6EBF0")
        edge = BLUE if n.get("direct") else ("#5B6B7B" if not n.get("risk") else face)
        ax.scatter([x], [yy], s=150 if n.get("risk") else 80, c=face, edgecolors=edge, linewidths=1.6, zorder=3)
        label = nid
        if n.get("risk"):
            ids = _adv_ids(n)
            label += f"  [{len(ids)} adv.{', optional' if n.get('optional') else ''}]"
        ax.text(x + 0.16, yy + 0.16, label, fontsize=6.8, color="#1D2733", va="bottom",
                weight="bold" if n.get("direct") else "normal")
    ax.set_xlim(-0.6, (n_layers - 1) * 3.0 + 3.2)
    ax.set_ylim(-max_n - 0.2, 2.2)
    ax.text(-0.5, 1.7, f"Runtime paths from {graph['root']['name']} to its {len(targets)} vulnerable runtime packages",
            fontsize=13, weight="bold", color=NAVY)
    ax.text(-0.5, 1.1, "Columns = dependency depth (1 = direct). Up to 2 shortest paths per vulnerable package. "
                       "Bold = direct dependency (blue ring). Advisory data: OSV.dev, "
                       f"{graph['meta'].get('osv_queried_at') or 'not queried'}.", fontsize=8.2, color="#5B6B7B")
    ax.legend(handles=legend_handles([Line2D([0], [0], marker="o", color="w", markerfacecolor="#E6EBF0",
                                             markeredgecolor="#5B6B7B", markersize=9, label="on the path, no advisory")]),
              loc="lower right", fontsize=7.5, frameon=False)
    fig.savefig(f"{out_dir}/graph-vulnerable-paths.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ----------------------------------------------------------------------------- summary
def write_summary(graph, out_path):
    m, st = graph["meta"], graph["meta"]["stats"]
    nodes = graph["nodes"]
    L = []
    L.append(f"| Metric | Value |\n|---|---|")
    rows = [
        ("Packages (unique name@version)", st["packages"]),
        ("Dependency edges", st["edges"]),
        ("Direct runtime / direct dev", f"{st['direct_runtime']} / {st['direct_dev']}"),
        ("Transitive", st["transitive"]),
        ("Runtime packages / dev-only packages", f"{st['runtime_packages']} / {st['dev_packages']}"),
        ("Deepest dependency chain", st["max_depth"]),
        ("Packages present in more than one version", st["duplicate_versions"]),
        ("Packages with install scripts", st["install_scripts"]),
        ("Packages not resolved from registry.npmjs.org", st["non_registry"]),
        ("Packages with known advisories (all / runtime)", f"{st['vulnerable_packages']} / {st['vulnerable_runtime']}"),
        ("Distinct advisories", st["advisories"]),
        ("Vulnerable packages by worst severity",
         ", ".join(f"{k.lower()} {v}" for k, v in sorted(st["by_severity"].items(), key=lambda kv: -SEV_RANK.get(kv[0], 0)))
         or "none"),
    ]
    L += [f"| {a} | {b} |" for a, b in rows]
    L.append("")
    vul = sorted([n for n in nodes if n.get("risk")],
                 key=lambda n: (not n["runtime"], -SEV_RANK.get(n["risk"], 0), -len(n["vulns"]), n["id"]))
    L.append("### Top vulnerable packages (runtime first)\n")
    L.append("| Package | Scope | Worst | Advisories | Fixed in | Dependency path |\n|---|---|---|---|---|---|")
    for n in vul[:20]:
        ids = _adv_ids(n)
        fixes = [v["fixed_in"] for v in n["vulns"]]
        fix = (max(fixes, key=_semver_key) if all(fixes) else
               (f"{max([f for f in fixes if f], key=_semver_key)} (some unfixed)" if any(fixes) else "no fix listed"))
        path = " → ".join(_label(graph, x) for x in n["paths"][0]) if n["paths"] else "-"
        scope = ("direct " if n.get("direct") else "") + ("runtime" if n["runtime"] else "dev") + \
                (" (optional)" if n.get("optional") else "")
        L.append(f"| `{n['id']}` | {scope} | {n['risk'].lower()} | {len(ids)}: {', '.join(ids[:3])}"
                 f"{' ...' if len(ids) > 3 else ''} | {fix} | {path} |")
    L.append("")
    odd = [n for n in nodes if n.get("non_registry")]
    if odd or m["unpinned_specs"]:
        L.append("### Supply-chain observations (non-CVE)\n")
        for n in odd:
            L.append(f"- `{n['id']}` is not resolved from the npm registry: {', '.join(n['resolved'])}")
        for u in m["unpinned_specs"]:
            L.append(f"- `{u['package']}` is declared as `{u['spec']}` in `{u['field']}` (not pinned to a version range)")
        L.append("")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return "\n".join(L)


def write_readme(graph, summary_md, out_path):
    m = graph["meta"]
    commit = (m.get("commit") or "")[:12]
    text = f"""# Dependency graph: {graph['root']['name']} {graph['root'].get('version') or ''}

- **Application:** {m.get('repo_url') or 'n/a'} @ `{commit}` (commit date {(m.get('commit_date') or '')[:10]})
- **Input:** `package.json` + `package-lock.json` (lockfile v{m.get('lockfile_version')}, sha256 `{m['lockfile_sha256'][:16]}...`)
- **Generated:** {m['generated_at']} by {m['generator']}
- **Advisory data:** OSV.dev, queried {m.get('osv_queried_at') or 'not queried'}

Nothing was installed and no package scripts were run: the graph is built only from the lockfile.
Each node is one `name@version`; edges follow Node.js module resolution over the lockfile's install paths
({m['stats']['edges']} edges, {m['unresolved_count']} unresolved).

## Files

| File | What it is |
|---|---|
| `graph.html` | **Interactive graph** (open in any browser, works offline). Toggle dev dependencies, show only paths to vulnerable packages, search, click a package to see its advisories and how it reaches the app. |
| `graph-direct.png` | The application and its {m['stats']['direct_runtime'] + m['stats']['direct_dev']} direct dependencies. Fill = the package itself, ring = worst advisory anywhere below it. |
| `graph-vulnerable-paths.png` | Runtime paths from the application to every vulnerable runtime package, by depth. |
| `graph.json` | Machine-readable graph: nodes (version, direct/transitive, runtime/dev, depth, source URL, integrity, licence, install-script flag, advisories, paths) and edges. |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM generated from the lockfile, including the dependency relationships. |
| `vulnerabilities.json` | Every vulnerable package with its advisories (id, CVE, severity, CVSS, fixed version) and dependency paths. |
| `raw/` | Evidence: raw OSV responses and sha256 hashes of every output and of the input lockfile. |

## Summary

{summary_md}

## How to read it

- **Direct** = declared in `package.json`. **Transitive** = pulled in by another package. **Runtime** = shipped with the app; **dev-only** = only used for building and testing.
- **Optional** packages (e.g. `fsevents`) are only installed on platforms that support them (macOS for `fsevents`).
- Severity is the worst known advisory for that exact version. It does not yet say whether the vulnerable code is reachable; that is the next step (risk prioritisation).

## Regenerate

```
python -I build_graph.py --repo ../sandbox/sample-app --out output
python -I build_graph.py --repo ../sandbox/sample-app --out output --no-osv   # offline, graph only
```
Requires Python 3.10+ and `matplotlib` (for the PNGs). `vendor/vis-network-9.1.9.min.js` is inlined into `graph.html`, so the page needs no internet.
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
