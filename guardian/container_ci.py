"""[4b] Container + CI/CD inspection: Dockerfile rules, GitHub Actions rules,
and a Trivy scan of the real base image (no Docker daemon required)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import yaml

from .models import Evidence, Finding

# Node.js majors that are end-of-life as of Nov 2026 (Node 20 EOL: 2026-04-30)
NODE_EOL_MAJORS = set(range(0, 21)) - {22}
PIPE_TO_SHELL = re.compile(r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(sh|bash)\b", re.I)
SHA_PIN = re.compile(r"@[0-9a-f]{40}$")


def _snippet(lines: list[str], hit: int, ctx: int = 2) -> dict:
    start = max(1, hit - ctx)
    return {"start": start, "hit": hit, "lines": lines[start - 1: hit + ctx]}


def _parse_dockerfile(text: str) -> list[tuple[int, str, str]]:
    """-> [(line_no, INSTRUCTION, args)] with line continuations joined."""
    out, buf, start = [], "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if not buf:
            start = i
        buf += (" " if buf else "") + line.rstrip("\\").strip()
        if not line.endswith("\\"):
            instr, _, args = buf.partition(" ")
            out.append((start, instr.upper(), args.strip()))
            buf = ""
    return out


def dockerfile_checks(app_dir: Path) -> tuple[list[Finding], list[str]]:
    path = app_dir / "Dockerfile"
    if not path.exists():
        return [], []
    text = path.read_text(encoding="utf-8")
    raw_lines = text.splitlines()
    instrs = _parse_dockerfile(text)
    out: list[Finding] = []
    images: list[str] = []
    stages: list[list[tuple[int, str, str]]] = []

    def add(rule, sev, title, line, detail, data=None):
        data = dict(data or {})
        data["snippet"] = _snippet(raw_lines, line)
        out.append(Finding(
            id=f"DOCKER-{rule}-L{line}", category="container", title=title, severity=sev,
            component="Dockerfile", scope="build", location=f"Dockerfile:{line}",
            evidence=[Evidence(f"Dockerfile rule {rule}", detail, data)],
        ))

    for ln, ins, args in instrs:
        if ins == "FROM":
            stages.append([])
            image = args.split()[0]
            images.append(image)
            name, _, tag = image.partition("@")[0].partition(":")
            if "@sha256:" not in image:
                if tag in ("", "latest"):
                    add("DF001", "HIGH", f"Base image '{image}' uses a floating tag", ln,
                        f"FROM {args} - the image content changes whenever upstream republishes 'latest'",
                        {"image": image})
                else:
                    add("DF002", "LOW", f"Base image '{image}' is not pinned by digest", ln,
                        f"FROM {args} - tags are mutable; pin with @sha256:<digest>", {"image": image})
            m = re.match(r"(\d+)", tag)
            if name.endswith("node") and m and int(m.group(1)) in NODE_EOL_MAJORS:
                add("DF003", "HIGH", f"Base image runs end-of-life Node.js {m.group(1)}", ln,
                    f"FROM {args} - Node.js {m.group(1)} no longer receives security patches",
                    {"image": image, "node_major": int(m.group(1))})
        if stages:
            stages[-1].append((ln, ins, args))
        if ins == "RUN" and PIPE_TO_SHELL.search(args):
            add("DF004", "CRITICAL", "Dockerfile downloads a remote script and pipes it to a shell", ln,
                f"RUN {args} - unauthenticated remote code executes inside the image build",
                {"command": args})
        if ins == "RUN" and re.search(r"\bnpm (install|i)\b", args):
            add("DF006", "LOW", "Image build uses `npm install` instead of `npm ci`", ln,
                f"RUN {args} - `npm install` may resolve versions outside the lockfile", {"command": args})
        if ins == "ADD" and re.search(r"https?://", args):
            add("DF007", "MEDIUM", "ADD fetches a remote URL without checksum", ln, f"ADD {args}")

    if stages and not any(ins == "USER" for _, ins, _ in stages[-1]):
        ln = stages[-1][0][0]
        add("DF005", "MEDIUM", "Final image stage runs as root (no USER instruction)", ln,
            "No USER instruction in the final stage: the app process runs as uid 0 in the container")
    return out, images


def workflow_checks(app_dir: Path) -> tuple[list[Finding], list[str]]:
    wf_dir = app_dir / ".github" / "workflows"
    out: list[Finding] = []
    files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))) if wf_dir.exists() else []
    for wf in files:
        rel = f".github/workflows/{wf.name}"
        text = wf.read_text(encoding="utf-8")
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            continue
        on = doc.get("on", doc.get(True, {}))  # PyYAML parses bare `on` as True
        triggers = list(on) if isinstance(on, (dict, list)) else [on]
        lines = text.splitlines()

        def line_of(s: str) -> int:
            return next((i for i, ln in enumerate(lines, 1) if s in ln), 0)

        def add(rule, sev, title, needle, detail, data=None):
            ln = line_of(needle)
            data = dict(data or {})
            data["snippet"] = _snippet(lines, ln or 1)
            out.append(Finding(
                id=f"CI-{rule}-{wf.name}-L{ln}", category="ci-cd", title=title, severity=sev,
                component=rel, scope="ci", location=f"{rel}:{ln}",
                evidence=[Evidence(f"workflow rule {rule}", detail, data)],
            ))

        prt = "pull_request_target" in triggers
        if "permissions" not in doc:
            add("CI005", "LOW", f"{wf.name}: no explicit `permissions:` block", "name:",
                "GITHUB_TOKEN gets the repository default permissions (often read/write)")
        for job_name, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps", []) or []:
                uses = step.get("uses")
                if uses and not uses.startswith(("./", "docker://")):
                    ref = uses.split("@", 1)[1] if "@" in uses else ""
                    first_party = uses.startswith(("actions/", "github/"))
                    passes_secret = "secrets." in json.dumps(step.get("with", {}))
                    if not SHA_PIN.search(uses):
                        branch_ref = ref in ("main", "master", "") or not re.match(r"v?\d", ref)
                        sev = ("HIGH" if (not first_party and (branch_ref or passes_secret))
                               else "MEDIUM" if not first_party else "LOW")
                        add("CI001", sev, f"Action '{uses}' is not pinned to a commit SHA", f"uses: {uses}",
                            f"job '{job_name}' uses {uses}: the tag/branch '{ref}' is mutable, so the code "
                            "that runs in CI can change without any change to this repo"
                            + ("; the step receives a repository secret" if passes_secret else ""),
                            {"action": uses, "ref": ref, "third_party": not first_party,
                             "receives_secret": passes_secret})
                    if prt and uses.startswith("actions/checkout") and "pull_request" in json.dumps(step.get("with", {})):
                        add("CI002", "CRITICAL", f"{wf.name}: pull_request_target checks out untrusted PR code",
                            "pull_request_target",
                            "Workflow runs with write token + secrets on `pull_request_target` and checks out "
                            "the PR head: any fork can run code with repository secrets ('pwn request')",
                            {"trigger": "pull_request_target"})
                run = step.get("run") or ""
                if PIPE_TO_SHELL.search(run):
                    add("CI003", "HIGH", f"{wf.name}: remote script piped to shell in CI", run.splitlines()[0],
                        f"job '{job_name}' runs: {run.strip()}", {"command": run.strip()})
    return out, [f".github/workflows/{f.name}" for f in files]


def trivy_image_scan(image: str, cache_dir: Path, out_dir: Path) -> Finding | None:
    """Scan a container image's OS + language packages with Trivy (pulls layers from the registry)."""
    exe = shutil.which("trivy")
    if not exe:
        return None
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", image)
    raw = cache_dir / f"trivy-image-{safe}.json"
    if not raw.exists():
        try:
            subprocess.run([exe, "image", "--quiet", "--cache-dir", str(cache_dir / "trivy"),
                            "--skip-db-update", "--scanners", "vuln", "--format", "json",
                            "--output", str(raw), image], check=True, capture_output=True, timeout=600)
        except Exception as e:
            return Finding(id=f"IMAGE-{image}", category="container", severity="INFO",
                           title=f"Trivy could not scan image {image}", component=image, scope="build",
                           location="Dockerfile", evidence=[Evidence("Trivy", str(e)[:300])])
    shutil.copy(raw, out_dir / raw.name)
    data = json.loads(raw.read_text(encoding="utf-8"))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    top: list[dict] = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
            if sev in ("CRITICAL", "HIGH") and not any(
                    t["id"] == v.get("VulnerabilityID") and t["pkg"] == v.get("PkgName") for t in top):
                top.append({"id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
                            "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion", ""),
                            "severity": sev, "target": res.get("Target")})
    top.sort(key=lambda x: (x["severity"] != "CRITICAL", x["id"] or ""))
    os_info = (data.get("Metadata") or {}).get("OS") or {}
    eosl = bool(os_info.get("EOSL"))
    worst = "CRITICAL" if counts["CRITICAL"] else "HIGH" if counts["HIGH"] else "MEDIUM" if counts["MEDIUM"] else "LOW"
    return Finding(
        id=f"IMAGE-{image}", category="container", severity=worst,
        title=f"Base image {image}: {counts['CRITICAL']} critical / {counts['HIGH']} high OS & runtime vulnerabilities"
              + (" (OS end-of-support)" if eosl else ""),
        component=image, scope="build", location="Dockerfile",
        vuln_ids=[t["id"] for t in top[:10]],
        evidence=[Evidence("Trivy image scan",
                           f"{image} ({os_info.get('Family', '?')} {os_info.get('Name', '?')}"
                           f"{', EOSL' if eosl else ''}): " + ", ".join(f"{k} {v}" for k, v in counts.items() if v),
                           {"counts": counts, "top": top[:10], "os": os_info, "raw_report": raw.name})],
    )
