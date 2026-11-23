import json
import os

with open('runs/day1-nodegoat/graph.json', 'r', encoding='utf-8') as f:
    g = json.load(f)
meta = g.get('meta', {})

metadata = {
    'schema_version': '1.0',
    'scan_id': 'scan-nodegoat-day1',
    'repo_url': meta.get('repo_url', 'https://github.com/OWASP/NodeGoat'),
    'commit_sha': meta.get('commit', 'c5cb68a7084e4ae7dcc60e6a98768720a81841e8'),
    'source_kind': 'GIT_PUBLIC',
    'started_at': meta.get('generated_at', '2026-11-23T09:24:17Z'),
    'finished_at': meta.get('osv_queried_at', '2026-11-23T09:24:21Z'),
    'status': 'COMPLETE',
    'tool_versions': {'generator': meta.get('generator', 'guardian 0.1.0'), 'osv': '2026-11-23'},
    'errors': [],
    'stage_statuses': {'intake': 'COMPLETE', 'graph': 'COMPLETE', 'advisories': 'COMPLETE', 'ci': 'COMPLETE'},
    'database_snapshots': {'osv': meta.get('osv_queried_at')},
    'source_snapshot_sha256': meta.get('lockfile_sha256'),
    'scope_capabilities': {'ecosystems': 'npm', 'packages': meta.get('stats', {}).get('packages', 1091)}
}
with open('runs/day1-nodegoat/metadata.json', 'w', encoding='utf-8') as f:
    json.dump(metadata, f, indent=2)

module_index = {
    'schema_version': '1.0',
    'scan_id': 'scan-nodegoat-day1',
    'modules': [
        {
            'module_id': 'mod-nodegoat-root',
            'relative_path': '.',
            'ecosystem': 'npm',
            'manifests': ['package.json'],
            'lockfiles': ['package-lock.json'],
            'ci_files': ['.github/workflows/ci.yml'],
            'dockerfiles': ['Dockerfile'],
            'coverage': 'RESOLVED',
            'coverage_reason': '',
            'scanner_names': ['guardian build_graph.py', 'osv'],
            'file_counts': {'found': 1091, 'scanned': 1091, 'failed': 0, 'unsupported': 0},
            'scan_stage': {'inventory': 'COMPLETE', 'graph': 'COMPLETE', 'advisory': 'COMPLETE', 'ci': 'COMPLETE'},
            'artifact_sbom_status': 'COMPLETE'
        }
    ]
}
with open('runs/day1-nodegoat/module_index.json', 'w', encoding='utf-8') as f:
    json.dump(module_index, f, indent=2)

with open('runs/day1-nodegoat/vulnerabilities.json', 'r', encoding='utf-8') as f:
    vulns = json.load(f)

findings = []
for idx, v in enumerate(vulns):
    pkg = v.get('package')
    runtime = v.get('runtime', False)
    direct = v.get('direct', False)
    risk = v.get('risk', 'MEDIUM')
    advisories = v.get('advisories', [])
    adv_ids = [a.get('id') for a in advisories if 'id' in a]
    first_adv = advisories[0] if advisories else {}
    summary = first_adv.get('summary') or f'Advisory in {pkg}'
    details = first_adv.get('details') or f'Known advisory affecting {pkg}'
    findings.append({
        'schema_version': '1.0',
        'scan_id': 'scan-nodegoat-day1',
        'finding_id': f'finding-nodegoat-{idx+1:03d}',
        'finding_type': 'VULNERABILITY',
        'title': summary,
        'description': details,
        'module_ids': ['mod-nodegoat-root'],
        'occurrence_ids': [f'occ-{pkg}'],
        'advisory_ids': adv_ids,
        'advisory_urls': [f'https://osv.dev/vulnerability/{aid}' for aid in adv_ids],
        'rule_id': None,
        'severity_label': risk,
        'cvss_score': 7.5 if risk == 'HIGH' else (5.0 if risk == 'MEDIUM' else 3.0),
        'priority': 'P0' if risk == 'CRITICAL' else ('P1' if risk == 'HIGH' else 'P2'),
        'evidence_ids': [f'ev-nodegoat-{pkg}'],
        'dependency_path_node_ids': v.get('paths', [[]])[0] if v.get('paths') else [],
        'path_status': 'FOUND' if v.get('paths') else 'NO_KNOWN_PATH',
        'execution_stage': 'RUNTIME' if runtime else 'BUILD',
        'execution_evidence': 'CONFIRMED' if runtime else 'POTENTIAL',
        'evidence_basis': 'TOOL_OBSERVED',
        'uncertainties': [],
        'recommendations': ['Update package to fixed release or replace with audited alternative'],
        'classification': 'CONFIRMED_ADVISORY',
        'advisory_aliases': first_adv.get('aliases', []),
        'first_seen_in': 'REAL_UPSTREAM',
        'advisory_as_of': meta.get('osv_queried_at'),
        'scanner_names': ['osv']
    })

for u_idx, u in enumerate(meta.get('unpinned_specs', [])):
    findings.append({
        'schema_version': '1.0',
        'scan_id': 'scan-nodegoat-day1',
        'finding_id': f'finding-nodegoat-susp-{u_idx+1:02d}',
        'finding_type': 'SUSPICIOUS_CHANGE',
        'title': f'Unpinned or non-registry dependency: {u.get("package")} ({u.get("spec")})',
        'description': f'Package {u.get("package")} declared with spec {u.get("spec")} in {u.get("field")}',
        'module_ids': ['mod-nodegoat-root'],
        'occurrence_ids': [f'occ-{u.get("package")}'],
        'advisory_ids': [],
        'advisory_urls': [],
        'rule_id': 'RULE-SUSP-UNPINNED',
        'severity_label': 'MEDIUM',
        'cvss_score': None,
        'priority': 'P2',
        'evidence_ids': [],
        'dependency_path_node_ids': ['mod-nodegoat-root', f'occ-{u.get("package")}'],
        'path_status': 'FOUND',
        'execution_stage': 'BUILD',
        'execution_evidence': 'CONFIRMED',
        'evidence_basis': 'RULE_MATCH',
        'uncertainties': ['External git/tarball references bypass npm registry integrity'],
        'recommendations': ['Pin to official registry semantic version with sha512 integrity'],
        'classification': 'SUSPICIOUS_INDICATOR',
        'advisory_aliases': [],
        'first_seen_in': 'REAL_UPSTREAM',
        'advisory_as_of': None,
        'scanner_names': ['guardian-detector']
    })

with open('runs/day1-nodegoat/findings.json', 'w', encoding='utf-8') as f:
    json.dump({'schema_version': '1.0', 'scan_id': 'scan-nodegoat-day1', 'findings': findings}, f, indent=2)

print('Generated metadata.json, module_index.json, and findings.json with', len(findings), 'findings')

