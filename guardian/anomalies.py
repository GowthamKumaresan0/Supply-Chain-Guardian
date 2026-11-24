"""[4] Suspicious-change agent: supply-chain anomalies that are NOT CVEs.

Static checks on the current tree + a diff against a trusted baseline."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from rapidfuzz.distance import DamerauLevenshtein

from .discover import Inventory
from .graph import DepGraph
from .models import Evidence, Finding

POPULAR = [
    ln.strip() for ln in (Path(__file__).parent / "data" / "popular_npm.txt").read_text().splitlines()
    if ln.strip() and not ln.startswith("#")
]
POPULAR_SET = set(POPULAR)
OFFICIAL_REGISTRY = "registry.npmjs.org"
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
DANGEROUS_CMD = re.compile(r"(curl|wget|Invoke-WebRequest|iwr)\b.*\|\s*(sh|bash|node)|child_process|"
                           r"\beval\b|base64\s+-d|https?://\d{1,3}(\.\d{1,3}){3}", re.I)


def _norm(n: str) -> str:
    return re.sub(r"[-_.]", "", n.lower()).removesuffix("js")


def typosquat_target(name: str) -> str | None:
    if name in POPULAR_SET or name.startswith("@") or len(name) < 4:
        return None
    for pop in POPULAR:
        if len(pop) < 4:
            continue
        if _norm(name) == _norm(pop) and name != pop:
            return pop  # separator / "js" suffix trick: body_parser, expressjs
        if DamerauLevenshtein.distance(name, pop) == 1 and len(name) >= 5:
            return pop
    return None


_DL_CACHE: dict[str, int | None] = {}
POPULARITY_THRESHOLD = 50_000  # weekly downloads; above this a look-alike is almost certainly legitimate


def weekly_downloads(name: str) -> int | None:
    """Public npm download counts API (read-only, no auth). None if unknown/offline."""
    if name in _DL_CACHE:
        return _DL_CACHE[name]
    val = None
    try:
        import requests
        r = requests.get(f"https://api.npmjs.org/downloads/point/last-week/{name}", timeout=10)
        if r.status_code == 200:
            val = int(r.json().get("downloads", 0))
        elif r.status_code == 404:
            val = 0
    except Exception:
        val = None
    _DL_CACHE[name] = val
    return val


def _host(url: str) -> str:
    return urlparse(url).netloc if url.startswith("http") else url.split(":", 1)[0]


def static_checks(inv: Inventory, graph: DepGraph) -> list[Finding]:
    out: list[Finding] = []
    seen_typo: set[str] = set()

    for key, c in inv.components.items():
        paths = graph.paths(key, limit=2)
        # --- typosquatting
        target = typosquat_target(c.name)
        if target and c.label not in seen_typo:
            seen_typo.add(c.label)
            dl, dl_target = weekly_downloads(c.name), weekly_downloads(target)
            if dl is not None and dl >= POPULARITY_THRESHOLD:
                continue  # widely used in its own right (e.g. safer-buffer) -> legitimate look-alike
            ev = [Evidence("typosquat-rule",
                           f"Edit distance between '{c.name}' and top package '{target}' is "
                           f"{DamerauLevenshtein.distance(c.name, target)}; '{c.name}' is not in "
                           f"the popular-package reference list",
                           {"lookalike_of": target, "direct": c.direct})]
            if dl is not None:
                ev.append(Evidence("npm downloads API",
                                   f"'{c.name}': {dl:,} downloads last week vs '{target}': "
                                   f"{(dl_target or 0):,}",
                                   {"downloads": dl, "target_downloads": dl_target}))
            out.append(Finding(
                id=f"TYPO-{c.label}", category="suspicious-change",
                title=f"Possible typosquat: '{c.name}' imitates popular package '{target}'",
                severity="HIGH" if c.direct or dl is not None else "MEDIUM",
                component=c.label, purl=c.purl, scope=c.scope,
                location="package-lock.json", dependency_paths=paths, evidence=ev,
            ))
        # --- non-registry source (git / tarball / http / custom mirror)
        if c.resolved:
            host = _host(c.resolved)
            if host != OFFICIAL_REGISTRY:
                insecure = c.resolved.startswith("http://")
                out.append(Finding(
                    id=f"SRC-{c.label}", category="suspicious-change",
                    title=f"{c.name} is fetched from a non-registry source ({host})",
                    severity="HIGH" if insecure else "MEDIUM",
                    component=c.label, purl=c.purl, scope=c.scope, location="package-lock.json",
                    dependency_paths=paths,
                    evidence=[Evidence("lockfile-rule LF001",
                                       f"resolved = {c.resolved} (expected https://{OFFICIAL_REGISTRY}). "
                                       "Content is not covered by the npm registry's immutability guarantees.",
                                       {"resolved": c.resolved, "integrity": c.integrity})],
                ))
        if not c.integrity and c.resolved:
            out.append(Finding(
                id=f"INT-{c.label}", category="suspicious-change",
                title=f"{c.name} has no integrity hash in the lockfile",
                severity="MEDIUM", component=c.label, purl=c.purl, scope=c.scope,
                location="package-lock.json", dependency_paths=paths,
                evidence=[Evidence("lockfile-rule LF002", "Missing 'integrity' field; tampering cannot be detected")],
            ))
        # --- install scripts (code that runs at `npm install` time)
        if c.has_install_script:
            out.append(Finding(
                id=f"INSTALL-{c.label}", category="suspicious-change",
                title=f"{c.name} runs an install-time script",
                severity="MEDIUM" if c.dev else "HIGH",
                component=c.label, purl=c.purl, scope=c.scope, location="package-lock.json",
                dependency_paths=paths,
                evidence=[Evidence("lockfile-rule LF003",
                                   "hasInstallScript=true: package executes code during `npm install` "
                                   "(on developer machines, CI runners and the Docker build)")],
            ))

    # --- weak (sha1) integrity, aggregated to avoid noise
    sha1 = [c.label for c in inv.components.values() if c.integrity.startswith("sha1-")]
    if sha1:
        out.append(Finding(
            id="LOCK-SHA1", category="manifest-hygiene",
            title="Lockfile entries use weak SHA-1 integrity hashes",
            severity="LOW", component="package-lock.json", scope="build", location="package-lock.json",
            evidence=[Evidence("lockfile-rule LF004",
                               f"{len(sha1)} entries use sha1-; SHA-1 is collision-prone. Regenerate the "
                               "lockfile with a modern npm to get sha512",
                               {"count": len(sha1), "examples": sha1[:8]})],
        ))

    # --- manifest: floating versions + dangerous lifecycle scripts
    m = inv.manifest
    for sect in ("dependencies", "devDependencies"):
        for name, spec in (m.get(sect) or {}).items():
            if spec in ("latest", "*", "") or spec.startswith(("http", "git")):
                out.append(Finding(
                    id=f"SPEC-{name}", category="manifest-hygiene",
                    title=f"{name} is declared with an unpinned/remote version spec '{spec}'",
                    severity="MEDIUM", component=name, scope="dev" if sect == "devDependencies" else "runtime",
                    location="package.json",
                    evidence=[Evidence("manifest-rule PJ001",
                                       f'"{name}": "{spec}" in {sect} - every fresh install may pull different code',
                                       {"section": sect, "spec": spec})],
                ))
    for sname, cmd in (m.get("scripts") or {}).items():
        if sname in LIFECYCLE:
            danger = bool(DANGEROUS_CMD.search(cmd))
            out.append(Finding(
                id=f"SCRIPT-{sname}", category="suspicious-change",
                title=f"package.json '{sname}' lifecycle script" + (" downloads/executes remote code" if danger else ""),
                severity="CRITICAL" if danger else "MEDIUM",
                component=f"{inv.app_name}@{inv.app_version}", scope="build", location="package.json",
                evidence=[Evidence("manifest-rule PJ002", f'"{sname}": {cmd}',
                                   {"script": sname, "command": cmd, "matches_dangerous_pattern": danger})],
            ))
    return out


def _hashes(integrity: str) -> dict[str, str]:
    """'sha512-AAA sha1-BBB' -> {'sha512': 'AAA', 'sha1': 'BBB'}."""
    out = {}
    for tok in (integrity or "").split():
        alg, sep, val = tok.partition("-")
        if sep:
            out[alg.lower()] = val
    return out


def integrity_conflict(old: str, new: str) -> bool:
    """True only when both lockfiles record a hash with the SAME algorithm and the values differ.

    A sha1 hash replaced by a sha512 hash (lockfile regenerated by a newer npm) is not comparable, so it is not
    evidence of tampering."""
    a, b = _hashes(old), _hashes(new)
    return any(a[k] != b[k] for k in set(a) & set(b))


def diff_against_baseline(base: Inventory, cur: Inventory, graph: DepGraph) -> tuple[list[Finding], dict]:
    """Compare two lockfiles position-by-position (lockfile path is the identity)."""
    b, c = base.components, cur.components
    added = sorted(set(c) - set(b))
    removed = sorted(set(b) - set(c))
    findings: list[Finding] = []
    changes = {"added": [], "removed": [], "version_changed": [], "integrity_changed": [],
               "source_changed": [], "scripts_changed": []}

    for k in added:
        comp = c[k]
        changes["added"].append(comp.label)
        findings.append(Finding(
            id=f"DIFF-ADD-{comp.label}", category="suspicious-change", changed=True,
            title=f"New {'direct' if comp.direct else 'transitive'} dependency appeared: {comp.label}",
            severity="HIGH" if not comp.direct else "MEDIUM",
            component=comp.label, purl=comp.purl, scope=comp.scope, location="package-lock.json",
            dependency_paths=graph.paths(k, limit=2),
            evidence=[Evidence("lockfile-diff",
                               f"{comp.label} is present at '{k}' in the current lockfile but not in the baseline"
                               + ("" if comp.direct else "; package.json did not change for it, so it was "
                                  "injected into the tree of an existing dependency"),
                               {"lock_path": k, "resolved": comp.resolved})],
        ))
    for k in removed:
        changes["removed"].append(b[k].label)

    for k in sorted(set(b) & set(c)):
        o, n = b[k], c[k]
        if o.version != n.version:
            changes["version_changed"].append(f"{o.label} -> {n.version}")
            findings.append(Finding(
                id=f"DIFF-VER-{n.label}", category="suspicious-change", changed=True,
                title=f"{n.name} version changed {o.version} -> {n.version}",
                severity="LOW", component=n.label, purl=n.purl, scope=n.scope,
                location="package-lock.json", dependency_paths=graph.paths(k, limit=2),
                evidence=[Evidence("lockfile-diff", f"{k}: {o.version} -> {n.version}")],
            ))
        elif integrity_conflict(o.integrity, n.integrity):
            changes["integrity_changed"].append(n.label)
            findings.append(Finding(
                id=f"DIFF-INT-{n.label}", category="suspicious-change", changed=True,
                title=f"{n.label}: integrity hash changed but version did not",
                severity="CRITICAL", component=n.label, purl=n.purl, scope=n.scope,
                location="package-lock.json", dependency_paths=graph.paths(k, limit=2),
                evidence=[Evidence("lockfile-diff",
                                   "Same version, different content hash: the published tarball for an "
                                   "immutable npm version cannot legitimately change",
                                   {"baseline_integrity": o.integrity, "current_integrity": n.integrity,
                                    "baseline_resolved": o.resolved, "current_resolved": n.resolved})],
            ))
        if o.resolved != n.resolved and _host(o.resolved) != _host(n.resolved):
            changes["source_changed"].append(f"{n.label}: {_host(o.resolved)} -> {_host(n.resolved)}")
        if o.has_install_script != n.has_install_script:
            changes["scripts_changed"].append(n.label)

    bs, cs = base.manifest.get("scripts", {}), cur.manifest.get("scripts", {})
    for s in sorted(set(bs) | set(cs)):
        if bs.get(s) != cs.get(s):
            changes["scripts_changed"].append(f"package.json script '{s}'")
    for f in findings:
        pass
    # mark static findings later via `changed` keys
    return findings, changes
