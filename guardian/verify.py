"""Verify approved fixes: build, test and re-scan the fixed code, compared with the original.

Runs after a person has approved fixes. Every step works on a SANDBOX copy; the repository is never changed.

  prepare   apply the approved fixes to a fresh sandbox (remediation.apply_fixes)
  lockfile  `npm ls --package-lock-only` before vs after: no new missing / invalid packages (reads files only)
  docker    Docker engine available; pick the app's own Node image (from its Dockerfile, else engines, else node:20)
  install   in a container: `npm ci --ignore-scripts` (network only for downloads, lifecycle scripts never run)
  runtime   in a container with --network none: load every production dependency in the app's Node version
  tests     in a container with --network none: the project's `npm test`
  usage     for MAJOR upgrades: files and lines that use the package (what a human should re-test)
  rescan    the full agent pipeline on the fixed code, with the original code as the baseline
  verdict   verified | partly fixed | new risk | build failed

Steps install / runtime / tests run on BOTH the original and the fixed code, so a failure only counts against
the fixes when it did not already happen before them.

Container hardening: --cap-drop ALL, no-new-privileges, CPU / memory / process limits, read-only image layers,
files passed in through a Docker volume (no host folder is mounted), and --network none whenever project code runs.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

STEPS = [
    ("prepare", "Apply approved fixes in a sandbox"),
    ("lockfile", "Check the dependency tree"),
    ("docker", "Start an isolated Docker environment"),
    ("install", "Clean install (no install scripts)"),
    ("runtime", "Load every production dependency"),
    ("tests", "Run the project's tests"),
    ("usage", "Find code that uses upgraded packages"),
    ("rescan", "Re-scan the fixed code"),
    ("verdict", "Verdict"),
]
HARDEN = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "3g",
          "--pids-limit", "1024", "-e", "HOME=/tmp", "-e", "npm_config_cache=/tmp/.npm", "-e", "CI=true",
          "-e", "npm_config_update_notifier=false"]
Runner = Callable[..., subprocess.CompletedProcess]


def _run(cmd: list[str], timeout: int = 600, input: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, timeout=timeout, input=input)


def _txt(p: subprocess.CompletedProcess) -> str:
    out = (p.stdout or b"") + b"\n" + (p.stderr or b"")
    return out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)


def _tail(text: str, n: int = 25) -> str:
    return "\n".join([l for l in text.strip().splitlines() if l.strip()][-n:])


# ------------------------------------------------------------------------------ host-side checks

def lockfile_problems(app: Path, run: Runner = _run) -> list[str]:
    """`npm ls` on the lockfile only (no install, nothing executed): missing / invalid / extraneous packages.

    Absolute paths are made relative to the project (`node_modules/cypress/node_modules/tmp`), so the original and
    the fixed lockfile can be compared line by line."""
    npm = shutil.which("npm")
    if not npm or not (app / "package-lock.json").exists():
        return []
    p = run([npm, "ls", "--all", "--json", "--package-lock-only", "--prefix", str(app)], timeout=300)
    try:
        data = json.loads((p.stdout or b"{}").decode("utf-8", "replace") if isinstance(p.stdout, bytes) else p.stdout or "{}")
    except ValueError:
        return []
    root = str(app.resolve())
    probs = [re.sub(r"\s+", " ", x).replace(root + "/", "").replace(str(app) + "/", "") for x in data.get("problems", []) or []]
    return sorted(set(probs))


_PROB = re.compile(r"^(\w+): (@?[^@\s]+)@(\S+)(?: (\S+))?")


def explain_problems(problems: list[str], approved: list[dict], lock: dict | None = None) -> list[dict]:
    """Turn npm ls lines into plain statements, linked to the approved fix they concern.

    `lock` (the fixed lockfile's "packages") lets us name the parent that no longer accepts a package, and the fix
    that upgraded that parent."""
    fx = {(f["package"], f["from_version"]): f for f in approved}
    to = {(f["package"], f["to_version"]): f for f in approved}
    pk = lock or {}

    def parent_of(path: str, name: str):
        """The installed package whose dependency range this copy fails."""
        base = path.rsplit("/node_modules/", 1)[0] if "/node_modules/" in path else ""
        for k, v in pk.items():
            rng = (v.get("dependencies") or {}).get(name) or (v.get("optionalDependencies") or {}).get(name)
            if rng and (k == base or (k.startswith(base + "/node_modules/") if base else k.count("node_modules/") == 1)):
                return k, v, rng
        return None
    out = []
    for p in problems:
        m = _PROB.match(p)
        if not m:
            out.append({"raw": p, "kind": "other", "text": p})
            continue
        kind, name, ver, path = m.groups()
        where = " › ".join(x for x in (path or "").split("node_modules/") if x).replace("/", "") or name
        f = fx.get((name, ver))
        if kind == "invalid" and f:
            out.append({"raw": p, "kind": "override-not-applied", "fix": f["id"], "where": where,
                        "text": f"{where} is still {ver}; the approved override to {f['to_version']} was not applied here"})
        elif kind == "invalid" and to.get((name, ver)):
            g = to[(name, ver)]
            out.append({"raw": p, "kind": "outside-range", "fix": g["id"], "where": where,
                        "text": f"{where} {ver} is outside the version range its parent asks for (forced by {g['id']})"})
        elif kind == "invalid" and (par := parent_of(path or "", name)):
            k, v, rng = par
            pname = k.rsplit("node_modules/", 1)[-1]
            g = to.get((pname, v.get("version")))
            pwhere = " › ".join(x for x in k.split("node_modules/") if x).replace("/", "")
            text = (f"{pwhere} {v.get('version')} needs {name} {rng}, but {ver} is installed"
                    + (f" (the parent was upgraded by {g['id']})" if g else ""))
            out.append({"raw": p, "kind": "dependency-mismatch", "fix": g["id"] if g else None, "where": where, "text": text})
        else:
            out.append({"raw": p, "kind": kind, "where": where, "text": f"{where}: {kind} ({name}@{ver})"})
    return out


def pick_node_image(app: Path) -> str:
    """The app's own Node runtime: first `FROM node:*` in its Dockerfile, else engines.node, else node:20-alpine."""
    df = app / "Dockerfile"
    if df.exists():
        for line in df.read_text(errors="replace").splitlines():
            m = re.match(r"\s*FROM\s+(?:--\S+\s+)*((?:docker\.io/)?(?:library/)?node(?::[\w.-]+)?)", line, re.I)
            if m:
                img = m.group(1)
                return img if ":" in img else img + ":latest"
    try:
        eng = (json.loads((app / "package.json").read_text()).get("engines") or {}).get("node", "")
        m = re.search(r"(\d{2})", eng)
        if m:
            return f"node:{m.group(1)}-alpine"
    except (ValueError, OSError):
        pass
    return "node:20-alpine"


_REQ = re.compile(r"""(?:require\(\s*|import\s+(?:[\w*{}\s,]+\s+from\s+)?|import\(\s*)['"]([^'"./][^'"]*)['"]""")


def usages(app: Path, packages: list[str], limit: int = 20) -> dict[str, list[str]]:
    """file:line places that import each package (skips node_modules, tests and build output)."""
    found: dict[str, list[str]] = {p: [] for p in packages}
    if not packages:
        return found
    skip = {"node_modules", ".git", "dist", "build", "coverage"}
    for f in sorted(app.rglob("*")):
        if f.suffix not in (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx") or any(s in f.parts for s in skip):
            continue
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for m in _REQ.finditer(line):
                spec = m.group(1)
                name = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
                if name in found and len(found[name]) < limit:
                    found[name].append(f"{f.relative_to(app).as_posix()}:{i}")
    return found


# ------------------------------------------------------------------------------ docker

class Docker:
    """Thin wrapper so the steps stay readable and tests can fake the engine."""

    def __init__(self, run: Runner = _run):
        self.run = run
        self.exe = shutil.which("docker")

    def available(self) -> tuple[bool, str]:
        if not self.exe:
            return False, "Docker is not installed (install Colima or Docker Desktop, then start the engine)"
        p = self.run([self.exe, "info", "--format", "{{.ServerVersion}}"], timeout=30)
        if p.returncode != 0:
            return False, "Docker is installed but the engine is not running (run `colima start`)"
        return True, _txt(p).strip().splitlines()[0]

    def pull(self, image: str) -> subprocess.CompletedProcess:
        return self.run([self.exe, "pull", "-q", image], timeout=900)

    def volume_from(self, folder: Path) -> str:
        """Copy a folder into a fresh named volume (no host folder is mounted into project containers)."""
        vol = f"guardian-verify-{uuid.uuid4().hex[:10]}"
        self.run([self.exe, "volume", "create", vol], timeout=60)
        tar = subprocess.run(["tar", "-C", str(folder), "--exclude", "node_modules", "--exclude", ".git", "-cf", "-", "."],
                             capture_output=True, timeout=300).stdout
        p = self.run([self.exe, "run", "--rm", "-i", "--network", "none", "-v", f"{vol}:/app", "alpine:3.20",
                      "sh", "-c", "tar -C /app -xf - && chown -R 1000:1000 /app"], timeout=300, input=tar)
        if p.returncode != 0:
            raise RuntimeError("could not copy the project into the Docker volume: " + _tail(_txt(p), 3))
        return vol

    def node(self, vol: str, image: str, script: str, network: bool, timeout: int) -> subprocess.CompletedProcess:
        cmd = [self.exe, "run", "--rm", "-u", "1000:1000", "-v", f"{vol}:/app", "-w", "/app", *HARDEN,
               "--network", "bridge" if network else "none", image, "sh", "-c", script]
        try:
            return self.run(cmd, timeout=timeout)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, 124, b"", f"timed out after {timeout}s".encode())

    def remove(self, vol: str) -> None:
        self.run([self.exe, "volume", "rm", "-f", vol], timeout=60)


INSTALL = ("npm ci --ignore-scripts --no-audit --no-fund --fetch-timeout=30000 --fetch-retries=1 --loglevel=error "
           "|| (echo '--- npm ci failed, trying npm install ---' && npm install --ignore-scripts --no-audit --no-fund "
           "--fetch-timeout=30000 --fetch-retries=1 --loglevel=error)")
# loads every production dependency, prints one JSON line
RUNTIME = r"""node -e '
const pj = require("./package.json"); const out = {node: process.version, ok: [], failed: []};
for (const d of Object.keys(pj.dependencies || {})) {
  try { require(d); out.ok.push(d); }
  catch (e) { const m = String(e && e.message || e).split("\n")[0];
    if (e && e.code === "ERR_REQUIRE_ESM") out.ok.push(d); else out.failed.push({name: d, error: m.slice(0, 200)}); }
}
console.log("GUARDIAN_RUNTIME " + JSON.stringify(out));'"""


def _npm_failures(log: str) -> list[str]:
    """`name@version` (or source URL) that npm could not fetch, from its error output."""
    names = set()
    for m in re.finditer(r"'(@?[\w.-]+(?:/[\w.-]+)?@[\w.+-]+)' is not in (?:the npm|this) registry", log):
        names.add(m.group(1))
    for m in re.finditer(r"GET https?://[^\s]+?/(@?[\w.-]+(?:%2[fF][\w.-]+)?)/-/[\w.-]+?-(\d[\w.+-]*?)\.tgz", log):
        names.add(f"{m.group(1).replace('%2f', '/').replace('%2F', '/')}@{m.group(2)}")
    for m in re.finditer(r"404 Not Found - GET https?://[^\s]+?/(@?[\w.-]+(?:%2[fF][\w.-]+)?)(?:\s|$)", log):
        name = m.group(1).replace("%2f", "/").replace("%2F", "/")
        if name.endswith(".tgz"):  # tarball URLs are handled above, as name@version
            continue
        if not any(n.rsplit("@", 1)[0] == name for n in names):
            names.add(name)
    for m in re.finditer(r"No matching version found for (@?[\w./-]+@[^\s.]+)", log):
        names.add(m.group(1))
    for m in re.finditer(r"Integrity check failed for \"?(@?[\w./-]+)", log):
        names.add(m.group(1))
    for m in re.finditer(r"https?://(?:\d{1,3}(?:\.\d{1,3}){3}|[\w.-]*\.example)[^\s'\"]*", log):
        url = m.group(0)
        t = re.search(r"/(@?[\w.-]+)/-/[\w.-]+?-(\d[\w.+-]*?)\.tgz", url)
        names.add(f"{t.group(1)}@{t.group(2)}" if t else url[:80])
    return sorted(names)


def flagged_blockers(unfetchable: list[str], report: dict) -> tuple[set[str], set[str]]:
    """Split install blockers that Guardian already flagged into (remove, reset_source).

    remove:       typosquats / malware that npm cannot fetch at all -> drop them from the copy
    reset_source: real packages whose download source was tampered with -> fetch them from the registry"""
    remove, reset = set(), set()
    for b in blocked_by_findings(unfetchable, report):
        name = b["package"].rsplit("@", 1)[0] if "@" in b["package"][1:] else b["package"]
        fs = [f for f in report.get("findings", []) if f.get("component", "").rsplit("@", 1)[0] == name]
        if any(f["category"] == "malicious-package" or f["id"].startswith("TYPO-") for f in fs):
            remove.add(name)            # attacker package: must not be installed at all
        elif any(f["id"].startswith(("SRC-", "DIFF-INT-")) for f in fs):
            reset.add(name)             # real package, tampered download: use the official registry
        else:
            remove.add(name)
    return remove, reset


def clean_copy(src: Path, dst: Path, remove: set[str], reset: set[str]) -> Path:
    """Copy the app without the flagged packages (`remove`) and with tampered sources reset to the registry."""
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", ".git"))
    pj_p, lock_p = dst / "package.json", dst / "package-lock.json"
    pj = json.loads(pj_p.read_text(encoding="utf-8"))
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for n in remove:
            (pj.get(sec) or {}).pop(n, None)
    pj_p.write_text(json.dumps(pj, indent=2) + "\n", encoding="utf-8")
    if lock_p.exists():
        lock = json.loads(lock_p.read_text(encoding="utf-8"))
        pk = lock.get("packages") or {}
        for k in list(pk):
            name = k.rsplit("node_modules/", 1)[-1] if k else ""
            if name in remove:
                for c in [c for c in pk if c == k or c.startswith(k + "/node_modules/")]:
                    pk.pop(c, None)
            elif name in reset and k in pk:
                pk[k].pop("resolved", None)
                pk[k].pop("integrity", None)
        for v in pk.values():
            for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for n in remove:
                    (v.get(sec) or {}).pop(n, None)
        for n in remove:  # lockfile v1 section
            (lock.get("dependencies") or {}).pop(n, None)
        lock_p.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    return dst


def blocked_by_findings(unfetchable: list[str], report: dict) -> list[dict]:
    """Match packages npm could not fetch with suspicious / malicious findings from the original scan."""
    out, seen = [], set()
    for u in unfetchable:
        name = u.rsplit("@", 1)[0] if "@" in u[1:] else u
        for f in report.get("findings", []):
            comp = f.get("component", "")
            if f.get("category") in ("suspicious-change", "malicious-package") and comp.rsplit("@", 1)[0] == name and name not in seen:
                seen.add(name)
                out.append({"package": u, "finding": f["id"], "title": f["title"][:90]})
    return out


def remaining_locations(lock: dict, name: str, version: str) -> list[dict]:
    """Where a version is still installed in the fixed lockfile, and whether it ships inside another package."""
    out = []
    for k, v in sorted(lock.items()):
        if k.endswith(f"node_modules/{name}") and v.get("version") == version:
            parts = [x.strip("/") for x in k.split("node_modules/") if x.strip("/")]
            out.append({"where": " › ".join(parts), "bundled": bool(v.get("inBundle")),
                        "bundled_by": parts[0] if v.get("inBundle") and len(parts) > 1 else None})
    return out


def run_in_docker(dk: Docker, app: Path, image: str, label: str, emit, has_tests: bool) -> dict:
    """install -> runtime -> tests for one copy of the app. Returns per-step results."""
    res: dict = {"label": label}
    vol = dk.volume_from(app)
    try:
        t = time.time()
        p = dk.node(vol, image, INSTALL, network=True, timeout=1200)
        log = _txt(p)
        res["install"] = {"ok": p.returncode == 0, "seconds": round(time.time() - t, 1), "log": _tail(log, 30),
                          "unfetchable": _npm_failures(log) if p.returncode else []}
        emit("install", "running", f"{label}: install {'succeeded' if p.returncode == 0 else 'failed'}")
        if p.returncode != 0:
            res["runtime"] = {"skipped": True, "reason": "install failed"}
            res["tests"] = {"skipped": True, "reason": "install failed"}
            return res
        t = time.time()
        p = dk.node(vol, image, RUNTIME, network=False, timeout=300)
        m = re.search(r"GUARDIAN_RUNTIME (\{.*\})", _txt(p))
        rt = json.loads(m.group(1)) if m else {"ok": [], "failed": [{"name": "(runner)", "error": _tail(_txt(p), 3)}]}
        res["runtime"] = {**rt, "seconds": round(time.time() - t, 1)}
        emit("runtime", "running", f"{label}: {len(rt.get('ok', []))} dependencies load, {len(rt.get('failed', []))} fail")
        if not has_tests:
            res["tests"] = {"skipped": True, "reason": "package.json has no test script"}
            return res
        t = time.time()
        p = dk.node(vol, image, "npm test --silent 2>&1", network=False, timeout=900)
        log = _txt(p)
        res["tests"] = {"ok": p.returncode == 0, "exit_code": p.returncode, "seconds": round(time.time() - t, 1),
                        "log": _tail(log, 40), "timed_out": p.returncode == 124}
        emit("tests", "running", f"{label}: tests {'passed' if p.returncode == 0 else 'failed (exit ' + str(p.returncode) + ')'}")
        return res
    finally:
        dk.remove(vol)


# ------------------------------------------------------------------------------ orchestration

def _sig(f: dict) -> tuple:
    return (f["category"], f["component"], (f.get("vuln_ids") or [f["title"]])[0])


def compare(before: dict, after: dict, approved: list[dict]) -> dict:
    """Before/after risk, approved-fix confirmation and regressions introduced by the fixes."""
    lv = lambda r: {k: r["checkpoint"]["what_looks_risky"]["by_risk_level"].get(k, 0) for k in ("Critical", "High", "Medium", "Low", "Info")}
    b_sigs = {_sig(f) for f in before["findings"]}
    # change-detection findings (DIFF-*) that only exist after the fixes describe the fixes themselves
    # (versions changed, packages added / removed): expected, so not counted as new risk
    expected = [f for f in after["findings"] if f["id"].startswith("DIFF-") and _sig(f) not in b_sigs]
    exp_ids = {f["id"] for f in expected}
    after = {**after, "findings": [f for f in after["findings"] if f["id"] not in exp_ids]}
    after_levels = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Info")}
    for f in after["findings"]:
        after_levels[f["risk_level"]] = after_levels.get(f["risk_level"], 0) + 1
    a_sigs = {_sig(f) for f in after["findings"]}
    vuln_cats = ("vulnerability", "malicious-package")
    resolved = [f for f in before["findings"] if f["category"] in vuln_cats and _sig(f) not in a_sigs]
    introduced = [f for f in after["findings"] if f["category"] in vuln_cats and _sig(f) not in b_sigs]
    after_by_comp: dict[str, set[str]] = {}
    for f in after["findings"]:
        if f["category"] in vuln_cats:
            after_by_comp.setdefault(f["component"], set()).update(f.get("vuln_ids") or [])
    def copies(r, name, ver):
        return sum(1 for c in r.get("inventory", []) if c.get("name") == name and c.get("version") == ver)
    fixes = []
    for fx in approved:
        left = sorted(set(fx["advisories"]) & after_by_comp.get(f"{fx['package']}@{fx['from_version']}", set()))
        c_before, c_after = copies(before, fx["package"], fx["from_version"]), copies(after, fx["package"], fx["from_version"])
        new_comp = f"{fx['package']}@{fx['to_version']}"
        new_issues = sorted({(f.get("vuln_ids") or [""])[0] for f in introduced if f["component"] == new_comp})
        fixes.append({"id": fx["id"], "package": fx["package"], "from_version": fx["from_version"], "to_version": fx["to_version"],
                      "bump": fx["bump"], "fixed": len(fx["advisories"]) - len(left), "of": len(fx["advisories"]),
                      "left": left, "new_issues_in_new_version": new_issues,
                      "copies_before": c_before, "copies_left": c_after, "bundled_in": fx.get("bundled_in", []),
                      "status": "fixed" if not left else
                                ("partly fixed" if len(left) < len(fx["advisories"]) or (c_before and c_after < c_before)
                                 else "not fixed")})
    via_label = {f"{fx['package']}@{fx['to_version']}": fx["id"] for fx in approved}

    def culprits(f):
        """Approved fixes on the dependency path that brought this new issue in."""
        hits = []
        for path in f.get("dependency_paths") or []:
            for label in path[1:]:
                if label in via_label and via_label[label] not in hits:
                    hits.append(via_label[label])
        if f["component"] in via_label and via_label[f["component"]] not in hits:
            hits.insert(0, via_label[f["component"]])
        return hits
    pick = lambda fs: [{"id": f["id"], "component": f["component"], "title": f["title"], "risk_level": f["risk_level"],
                        "risk_score": f["risk_score"], "vuln_ids": (f.get("vuln_ids") or [])[:3], "via": culprits(f)}
                       for f in sorted(fs, key=lambda f: -f["risk_score"])[:60]]
    blame: dict[str, int] = {}
    for f in introduced:
        for c in culprits(f):
            blame[c] = blame.get(c, 0) + 1
    exp_kinds: dict[str, int] = {}
    for f in expected:
        k = {"VER": "versions changed", "ADD": "packages added", "REM": "packages removed", "INT": "content hashes changed",
             "SRC": "download sources changed"}.get(f["id"].split("-")[1] if f["id"].count("-") else "", "other changes")
        exp_kinds[k] = exp_kinds.get(k, 0) + 1
    return {"levels_before": lv(before), "levels_after": after_levels,
            "expected_changes": len(expected), "expected_change_kinds": exp_kinds,
            "findings_before": len(before["findings"]), "findings_after": len(after["findings"]),
            "vulnerable_packages_before": before["vulnerability_scan"].get("vulnerable_packages"),
            "vulnerable_packages_after": after["vulnerability_scan"].get("vulnerable_packages"),
            "resolved_count": len(resolved), "introduced_count": len(introduced),
            "resolved": pick(resolved), "introduced": pick(introduced), "fixes": fixes,
            "introduced_by_fix": dict(sorted(blame.items(), key=lambda kv: -kv[1])),
            "dependency_changes": dependency_changes(before, after)}


def dependency_changes(before: dict, after: dict) -> dict:
    """What the approved fixes changed in the installed tree (expected, informational)."""
    def versions(r):
        out: dict[str, set[str]] = {}
        for c in r.get("inventory", []):
            out.setdefault(c["name"], set()).add(c["version"])
        return out
    b, a = versions(before), versions(after)
    upgraded = sorted(n for n in set(a) & set(b) if a[n] != b[n])
    added, removed = sorted(set(a) - set(b)), sorted(set(b) - set(a))
    return {"upgraded": len(upgraded), "added": len(added), "removed": len(removed),
            "upgraded_examples": [f"{n} {', '.join(sorted(b[n]))} → {', '.join(sorted(a[n]))}" for n in upgraded[:8]],
            "added_examples": [f"{n}@{', '.join(sorted(a[n]))}" for n in added[:8]],
            "removed_examples": removed[:8]}


def verdict(steps: dict, cmp: dict | None) -> dict:
    def state(k):
        return (steps.get(k) or {}).get("status")
    failed = [k for k in ("lockfile", "install", "runtime", "tests") if state(k) == "fail"]
    serious_new = [f for f in (cmp or {}).get("introduced", []) if f["risk_level"] in ("Critical", "High")]
    fixes = (cmp or {}).get("fixes", [])
    all_fixed = bool(fixes) and all(f["status"] == "fixed" for f in fixes)
    if "install" in failed:
        v, head = "build-failed", "The fixed code does not build"
    elif failed:
        v, head = "regression", "The fixes broke something that worked before"
    elif serious_new:
        culprits = sorted({c for f in serious_new for c in f.get("via", [])})
        v = "new-risk"
        head = (f"Fixes applied, but {len(serious_new)} new high-risk issue(s) came in with the upgrades"
                + (f": reject {', '.join(culprits[:3])}{'…' if len(culprits) > 3 else ''} and verify again" if culprits else ""))
    elif all_fixed:
        v, head = "verified", "All approved fixes are verified"
    else:
        v, head = "partial", "Some approved fixes are only partly effective"
    pre = [k for k in ("install", "runtime", "tests") if (steps.get(k) or {}).get("pre_existing")]
    note = (f"Already failing before the fixes (not caused by them): {', '.join(pre)}." if pre else "")
    return {"verdict": v, "headline": head, "note": note,
            "fixed": sum(f["status"] == "fixed" for f in fixes), "total": len(fixes)}


_NO_TESTS = re.compile(r"No files to check|\b0 passing\b|no test specified|No tests? found|Ran 0 tests|0 tests?,? 0 (?:assertions|passed)", re.I)


def ran_no_tests(log: str) -> bool:
    """The test command exited 0 but executed no tests (e.g. mocha 'No files to check', '0 passing')."""
    return bool(_NO_TESTS.search(log or "")) and not re.search(r"\b[1-9]\d* passing\b|\b[1-9]\d* tests? passed", log or "", re.I)


def _compare_step(name: str, before: dict | None, after: dict) -> dict:
    """pass / fail / warn for install, runtime or tests, judged against the original code."""
    a = after.get(name) or {}
    b = (before or {}).get(name) or {}
    if a.get("skipped"):
        return {"status": "skip", "detail": a.get("reason", ""), "after": a, "before": b}
    if name == "runtime":
        a_fail = {x["name"] for x in a.get("failed", [])}
        b_fail = {x["name"] for x in b.get("failed", [])} if b and not b.get("skipped") else set()
        new = sorted(a_fail - b_fail)
        ok = not new
        detail = (f"{len(a.get('ok', []))} of {len(a.get('ok', [])) + len(a_fail)} production dependencies load in Node {a.get('node', '?')}"
                  + (f"; newly failing: {', '.join(new)}" if new else "")
                  + (f"; already failing before: {', '.join(sorted(a_fail & b_fail))}" if a_fail & b_fail else ""))
        return {"status": "pass" if ok and not a_fail else ("warn" if ok else "fail"), "detail": detail,
                "pre_existing": bool(a_fail & b_fail), "after": a, "before": b}
    ok_after = a.get("ok", False)
    ok_before = b.get("ok") if b and not b.get("skipped") else None
    if ok_after and name == "tests" and ran_no_tests(a.get("log", "")):
        return {"status": "pass", "after": a, "before": b, "no_tests": True,
                "detail": "no unit tests in the project; the test command finished without errors"}
    if ok_after:
        return {"status": "pass", "detail": f"succeeded in {a.get('seconds', '?')}s", "after": a, "before": b}
    if ok_before is False:  # failed before the fixes too: not caused by them
        why = ""
        if name == "install" and a.get("unfetchable"):
            why = " Unfetchable: " + ", ".join(a["unfetchable"][:6])
        return {"status": "warn", "pre_existing": True, "after": a, "before": b,
                "detail": f"fails with and without the fixes, so the fixes did not cause it.{why}"}
    why = (" Unfetchable: " + ", ".join(a.get("unfetchable", [])[:6])) if a.get("unfetchable") else ""
    return {"status": "fail", "after": a, "before": b,
            "detail": ("failed" + (f" (exit {a.get('exit_code')})" if "exit_code" in a else "") + why
                       + (" but passed on the original code" if ok_before else ""))}


def run_verification(target: Path, out: Path, plan: dict, decisions: dict, *, apply_fixes, rescan_full, emit,
                     compare_original: bool = True, docker: Docker | None = None, run: Runner = _run) -> dict:
    """Full verification. `apply_fixes(target,out,plan,decisions)` and `rescan_full(sandbox, baseline)->report` are injected."""
    steps: dict = {}
    started = time.time()

    def step(k, status, detail="", **extra):
        steps[k] = {"status": status, "detail": detail, **extra}
        emit(k, "error" if status == "fail" else "done", f"{dict(STEPS)[k]}: {detail}" if detail else dict(STEPS)[k],
             {"result": status})

    approved = [f for f in plan.get("fixes", []) if decisions.get(f["id"], {}).get("decision") == "approved"]
    emit("prepare", "running", f"Applying {len(approved)} approved fix(es) to a fresh sandbox copy")
    if not approved:
        step("prepare", "fail", "No fixes are approved yet. Approve fixes in the Fixes tab first.")
        return _finish(out, steps, None, started, plan_ok=False)
    applied = apply_fixes(target, out, plan, decisions)
    if not applied.get("ok"):
        step("prepare", "fail", applied.get("error", "could not apply the fixes"))
        return _finish(out, steps, None, started, plan_ok=False)
    sandbox = Path(applied["sandbox"])
    step("prepare", "pass", f"{len(approved)} fix(es) written to package.json; lockfile regenerated without scripts",
         lockfile_command=applied.get("lockfile_command"))

    emit("lockfile", "running", "Comparing the dependency tree of the original and the fixed lockfile")
    b_probs, a_probs = lockfile_problems(target, run), lockfile_problems(sandbox, run)
    try:
        fixed_lock = json.loads((sandbox / "package-lock.json").read_text(encoding="utf-8")).get("packages") or {}
    except (OSError, ValueError):
        fixed_lock = {}
    new_probs = explain_problems(sorted(set(a_probs) - set(b_probs)), approved, fixed_lock)
    expected = [p for p in new_probs if p["kind"] in ("override-not-applied", "outside-range")]
    broken = [p for p in new_probs if p not in expected]
    if broken:
        status, detail = "fail", f"{len(broken)} new problem(s) in the dependency tree: " + "; ".join(p["text"] for p in broken[:4])
    elif expected:
        status = "warn"
        detail = (f"{len(expected)} place(s) where an approved fix did not fully take effect: "
                  + "; ".join(p["text"] for p in expected[:3]) + ("…" if len(expected) > 3 else ""))
    elif a_probs:
        status, detail = "warn", f"no new problems ({len(a_probs)} already present in the original)"
    else:
        status, detail = "pass", "consistent: no missing, invalid or extraneous packages"
    if status == "pass" and applied.get("reresolve_rounds"):
        detail += f" (after re-resolving {applied['pruned_lock_entries']} stale lockfile entries)"
    step("lockfile", status, detail, new_problems=new_probs, existing_problems=len(b_probs),
         pruned=applied.get("pruned_lock_entries", 0))

    try:
        before_report = json.loads((out / "guardian_report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        before_report = {"findings": []}
    dk = docker or Docker(run)
    emit("docker", "running", "Checking the Docker engine and pulling the app's Node image")
    ok, info = dk.available()
    image = pick_node_image(target)
    if ok:
        pulled = dk.pull(image)
        if pulled.returncode != 0:
            ok, info = False, f"could not pull {image}: " + _tail(_txt(pulled), 2)
        else:
            dk.pull("alpine:3.20")
    has_tests = bool((json.loads((sandbox / "package.json").read_text()).get("scripts") or {}).get("test"))
    if not ok:
        step("docker", "fail", info)
        for k in ("install", "runtime", "tests"):
            step(k, "skip", "Docker unavailable: " + info)
    else:
        step("docker", "pass", f"Docker {info}; image {image}; containers run with no capabilities and no network for project code",
             image=image)
        emit("install", "running", "Installing the fixed code in a container (scripts disabled)")
        after = run_in_docker(dk, sandbox, image, "fixed code", emit, has_tests)
        before = None
        if compare_original:
            emit("install", "running", "Installing the original code for comparison")
            before = run_in_docker(dk, target, image, "original code", emit, has_tests)
        # install blocked by packages Guardian already flagged (attacker packages)? retry on cleaned copies,
        # for both versions of the code, so runtime and tests can still run
        remove: set[str] = set()
        reset: set[str] = set()
        for _ in range(3):
            if (after.get("install") or {}).get("ok"):
                break
            rm, rs = flagged_blockers((after.get("install") or {}).get("unfetchable", []), before_report)
            if not (rm - remove or rs - reset):
                break
            remove |= rm
            reset |= rs
            emit("install", "running", "Retrying without packages Guardian flagged: "
                 + ", ".join(sorted(remove) + [f"{n} (registry source)" for n in sorted(reset)]))
            work = out / "verify-clean"
            after = run_in_docker(dk, clean_copy(sandbox, work / "fixed", remove, reset), image, "fixed code (cleaned)",
                                  emit, has_tests)
            if compare_original:
                before = run_in_docker(dk, clean_copy(target, work / "original", remove, reset), image,
                                       "original code (cleaned)", emit, has_tests)
        if remove or reset:
            after["excluded"] = {"removed": sorted(remove), "reset_source": sorted(reset)}
        for k in ("install", "runtime", "tests"):
            r = _compare_step(k, before, after)
            ex = after.get("excluded")
            if k == "install" and ex and (after.get("install") or {}).get("ok"):
                r["status"] = "warn"
                r["excluded"] = ex
                r["detail"] = ("passes only after cleaning the packages Guardian flagged: "
                               + "; ".join([f"removed {n}" for n in ex["removed"]] + [f"{n} fetched from the official registry"
                                                                                     for n in ex["reset_source"]])
                               + ". Fix these in the repository; runtime and tests below ran on the cleaned copy.")
            elif k == "install":
                blocked = blocked_by_findings((after.get("install") or {}).get("unfetchable", []), before_report)
                if blocked:
                    r["blocked_by"] = blocked
                    r["detail"] += (" Blocked by packages Guardian already flagged: "
                                    + "; ".join(f"{b['package']} ({b['title']})" for b in blocked[:4])
                                    + ". Remove them, then verify again to run the build and tests.")
            step(k, r.pop("status"), r.pop("detail"), **r)

    majors = [f["package"] for f in approved if f["bump"] == "major"]
    emit("usage", "running", "Looking for code that uses packages with a major upgrade")
    uses = usages(sandbox, majors)
    n = sum(len(v) for v in uses.values())
    step("usage", "warn" if n else "pass",
         (f"{n} place(s) use {len([k for k, v in uses.items() if v])} package(s) with a major upgrade; re-test these by hand")
         if n else ("no major upgrades approved" if not majors else "the app's own code does not import the upgraded packages"),
         places=uses)

    emit("rescan", "running", "Running all agents on the fixed code (original code as the baseline)")
    try:
        after_report = rescan_full(sandbox, target)
        cmp = compare(before_report, after_report, approved)
        for fx in cmp["fixes"]:
            if fx["status"] != "fixed":
                locs = remaining_locations(fixed_lock, fx["package"], fx["from_version"])
                fx["remaining_in"] = locs
                fx["bundled_in"] = sorted({l["bundled_by"] for l in locs if l["bundled_by"]})
                fx["reason"] = ("only copies bundled inside " + ", ".join(fx["bundled_in"]) + " remain; upgrade "
                                + ("that package" if len(fx["bundled_in"]) == 1 else "those packages") + " instead"
                                if locs and all(l["bundled"] for l in locs) else
                                "npm kept this version at: " + "; ".join(l["where"] for l in locs[:3]) if locs else "")
        lb, la = cmp["levels_before"], cmp["levels_after"]
        step("rescan", "pass" if not any(f["risk_level"] in ("Critical", "High") for f in cmp["introduced"]) else "warn",
             f"{cmp['resolved_count']} known issues resolved; critical {lb['Critical']} → {la['Critical']}, "
             f"high {lb['High']} → {la['High']}")
    except Exception as e:
        cmp = None
        step("rescan", "fail", f"re-scan failed: {type(e).__name__}: {str(e)[:200]}")
    return _finish(out, steps, cmp, started)


def _finish(out: Path, steps: dict, cmp: dict | None, started: float, plan_ok: bool = True) -> dict:
    v = verdict(steps, cmp) if plan_ok else {"verdict": "not-run", "headline": steps.get("prepare", {}).get("detail", ""),
                                            "note": "", "fixed": 0, "total": 0}
    steps["verdict"] = {"status": {"verified": "pass", "partial": "warn", "new-risk": "warn"}.get(v["verdict"], "fail"),
                        "detail": v["headline"]}
    result = {"ok": plan_ok, "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "seconds": round(time.time() - started, 1), **v, "steps": steps, "comparison": cmp,
              "step_titles": STEPS}
    (out / "verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
