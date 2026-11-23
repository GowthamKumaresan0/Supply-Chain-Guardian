"""Fetch a target application safely.

- only public https://github.com/<owner>/<repo> URLs (strict regex, no shell)
- shallow clone, no submodules, no hooks executed
- if the repo has no package-lock.json, resolve one with
  `npm install --package-lock-only --ignore-scripts` (computes versions only:
  nothing is downloaded into node_modules and no package code runs)
- keeps a snapshot of the supply-chain files after every scan, used as the
  baseline for the next scan ("what changed since we last looked")
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"
GH_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?$")
SNAPSHOT_FILES = ["package.json", "package-lock.json", "Dockerfile"]

PRESETS = {
    "nodegoat": {
        "id": "nodegoat", "name": "OWASP NodeGoat", "url": "https://github.com/OWASP/NodeGoat",
        "blurb": "Deliberately vulnerable Node.js app. Includes our simulated supply-chain attack, "
                 "so you can watch the Guardian catch tampering.",
        "tags": ["Node.js", "Express", "MongoDB", "Attack demo"],
    },
    "juice-shop": {
        "id": "juice-shop", "name": "OWASP Juice Shop", "url": "https://github.com/juice-shop/juice-shop",
        "blurb": "Modern, large web shop used for security training. A real-world dependency tree "
                 "with no lockfile in the repo; the Guardian resolves one safely.",
        "tags": ["Node.js", "Angular", "TypeScript", "Real-world"],
    },
}


class FetchError(Exception):
    pass


def rmtree(path: Path) -> None:
    """shutil.rmtree that also removes read-only files (git pack files on Windows)."""
    import os
    import stat

    def _fix(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if path.exists():
        shutil.rmtree(path, onexc=_fix) if sys.version_info >= (3, 12) else shutil.rmtree(path, onerror=_fix)


def slug_for(url: str) -> str:
    m = GH_RE.match(url.strip())
    if not m:
        raise FetchError("Please enter a public GitHub repository URL like https://github.com/owner/repo")
    return f"gh-{m.group(1)}-{m.group(2)}".lower()


def _run(cmd: list[str], cwd: Path | None, timeout: int) -> subprocess.CompletedProcess:
    exe = shutil.which(cmd[0]) or cmd[0]
    return subprocess.run([exe] + cmd[1:], cwd=cwd, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def clone(url: str, emit) -> tuple[Path, str]:
    slug = slug_for(url)
    dest = TARGETS / slug
    rmtree(dest)
    emit("fetch", "running", f"Downloading {url} (latest commit only)")
    r = _run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--no-recurse-submodules",
              "--quiet", url.rstrip("/"), str(dest)], None, 300)
    if r.returncode != 0:
        raise FetchError(f"git clone failed: {r.stderr.strip()[:300]}")
    commit = _run(["git", "rev-parse", "--short", "HEAD"], dest, 30).stdout.strip()
    return dest, commit


def ensure_lockfile(app: Path, emit) -> str:
    """-> 'found' | 'generated'"""
    if not (app / "package.json").exists():
        raise FetchError("No package.json at the repository root. This prototype supports npm projects.")
    if (app / "package-lock.json").exists():
        return "found"
    if (app / "yarn.lock").exists() or (app / "pnpm-lock.yaml").exists():
        emit("discover", "running", "yarn/pnpm lockfile found; resolving an npm lockfile instead (no code runs)")
    else:
        emit("discover", "running", "No lockfile in the repo. Resolving the exact dependency tree with npm "
                                    "(--package-lock-only --ignore-scripts: versions only, no code runs). ~1-2 min")
    base = ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
            "--loglevel=error"]
    r = _run(base, app, 600)
    if r.returncode != 0:
        r = _run(base + ["--legacy-peer-deps"], app, 600)
    if r.returncode != 0 or not (app / "package-lock.json").exists():
        raise FetchError(f"Could not resolve dependencies: {r.stderr.strip()[-300:]}")
    return "generated"


def snapshot_dir(slug: str) -> Path:
    return TARGETS / f"{slug}__snapshot"


def save_snapshot(app: Path, slug: str) -> None:
    snap = snapshot_dir(slug)
    rmtree(snap)
    snap.mkdir(parents=True)
    for f in SNAPSHOT_FILES:
        if (app / f).exists():
            shutil.copy2(app / f, snap / f)
    wf = app / ".github" / "workflows"
    if wf.exists():
        shutil.copytree(wf, snap / ".github" / "workflows")
