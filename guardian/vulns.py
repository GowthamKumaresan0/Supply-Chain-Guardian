"""[3] Vulnerability agent: correlate every name@version with OSV.dev
(GitHub Advisory DB, NVD aliases, OpenSSF malicious-packages feed)."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests
from cvss import CVSS3, CVSS4

from .discover import Inventory
from .graph import DepGraph
from .models import Evidence, Finding

OSV = "https://api.osv.dev/v1"


def _cvss_score(vuln: dict) -> float | None:
    best = None
    for s in vuln.get("severity", []) or []:
        try:
            if s.get("type") == "CVSS_V3":
                sc = float(CVSS3(s["score"]).base_score)
            elif s.get("type") == "CVSS_V4":
                sc = float(CVSS4(s["score"]).base_score)
            else:
                continue
            best = sc if best is None else max(best, sc)
        except Exception:
            continue
    return best


def _severity(vuln: dict, score: float | None) -> str:
    if vuln["id"].startswith("MAL-"):
        return "CRITICAL"
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
        return {"MODERATE": "MEDIUM"}.get(ds.upper(), ds.upper())
    if score is None:
        return "MEDIUM"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def _fixed_version(vuln: dict, name: str) -> str:
    fixes = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != "npm" or pkg.get("name") != name:
            continue
        for r in aff.get("ranges", []) or []:
            fixes += [e["fixed"] for e in r.get("events", []) if "fixed" in e]
    return ", ".join(dict.fromkeys(fixes))


_MAL_PHRASES = ("malicious code", "malicious package", "embedded malware", "contains malware",
                "malicious version", "compromised")


def _is_malicious(vuln: dict) -> bool:
    if vuln["id"].startswith("MAL-"):
        return True
    text = (vuln.get("summary", "") or "").lower().strip()
    # advisories ABOUT malware start with the phrase; "...crafted malicious code" input bugs do not
    return text.startswith(("malicious", "embedded malware", "compromised")) or "malicious package" in text


class OSVClient:
    def __init__(self, cache_dir: Path):
        self.cache = cache_dir / "osv"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.s = requests.Session()

    def query_batch(self, pkgs: list[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
        out: dict[tuple[str, str], list[str]] = {}
        for i in range(0, len(pkgs), 500):
            chunk = pkgs[i:i + 500]
            body = {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v}
                                for n, v in chunk]}
            r = self.s.post(f"{OSV}/querybatch", json=body, timeout=60)
            r.raise_for_status()
            for (n, v), res in zip(chunk, r.json().get("results", [])):
                ids = [x["id"] for x in res.get("vulns", []) or []]
                if ids:
                    out[(n, v)] = ids
        return out

    def get(self, vid: str) -> dict:
        p = self.cache / f"{vid}.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        r = self.s.get(f"{OSV}/vulns/{vid}", timeout=30)
        r.raise_for_status()
        p.write_text(r.text, encoding="utf-8")
        return r.json()


def scan_vulnerabilities(inv: Inventory, graph: DepGraph, cache_dir: Path) -> tuple[list[Finding], dict]:
    client = OSVClient(cache_dir)
    pkgs = sorted({(c.name, c.version) for c in inv.components.values()
                   if c.version and not c.version.startswith(("http", "git"))})
    hits = client.query_batch(pkgs)
    all_ids = sorted({i for ids in hits.values() for i in ids})
    with ThreadPoolExecutor(max_workers=16) as ex:
        details = dict(zip(all_ids, ex.map(client.get, all_ids)))

    # every lockfile location where name@version is installed
    locations: dict[tuple[str, str], list[str]] = {}
    for k, c in inv.components.items():
        locations.setdefault((c.name, c.version), []).append(k)

    findings: list[Finding] = []
    for (name, version), ids in hits.items():
        keys = locations[(name, version)]
        comps = [inv.components[k] for k in keys]
        runtime = any(not c.dev for c in comps)
        direct = any(c.direct for c in comps)
        paths: list[list[str]] = []
        for k in keys:
            for p in graph.paths(k, limit=2):
                if p not in paths:
                    paths.append(p)
        for vid in ids:
            v = details[vid]
            score = _cvss_score(v)
            sev = _severity(v, score)
            malicious = _is_malicious(v)
            aliases = [a for a in v.get("aliases", []) if a.startswith(("CVE-", "GHSA-"))]
            fixed = _fixed_version(v, name)
            findings.append(Finding(
                id=f"VULN-{name}@{version}-{vid}",
                category="malicious-package" if malicious else "vulnerability",
                title=v.get("summary") or vid,
                severity="CRITICAL" if malicious else sev,
                component=f"{name}@{version}",
                purl=comps[0].purl,
                scope="runtime" if runtime else "dev",
                location="package-lock.json",
                dependency_paths=paths[:4],
                vuln_ids=[vid] + [a for a in aliases if a != vid],
                cvss=score,
                fixed_version=fixed,
                references=[r["url"] for r in (v.get("references") or [])[:3]],
                evidence=[Evidence(
                    source="OSV.dev",
                    detail=f"{name}@{version} is listed as affected by {vid}"
                           + (f" ({', '.join(aliases)})" if aliases else "")
                           + f"; severity {sev}" + (f", CVSS {score}" if score else "")
                           + (f"; fixed in {fixed}" if fixed else "; no fixed version published"),
                    data={"osv_id": vid, "modified": v.get("modified"), "installed_at": keys,
                          "direct": direct, "introduced_by": graph.direct_introducers(keys[0])},
                )],
            ))
    stats = {"packages_queried": len(pkgs), "vulnerable_packages": len(hits),
             "advisories": len(all_ids)}
    return findings, stats
