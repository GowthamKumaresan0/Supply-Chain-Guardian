"""Publish a verified remediation to a Git repository as two branches.

  <prefix>/<repo>-<timestamp>-original   the scanned code + guardian-report/before/
  <prefix>/<repo>-<timestamp>-fixed      built ON TOP of -original: the fixed package.json / lockfile
                                         + guardian-report/after/, BEFORE_AFTER.md, fixes.csv,
                                           VERIFICATION.md, the decisions log and the patch

before/ and after/ each hold REPORT.md, findings.csv, packages.csv, the full JSON report, the SBOM and the
dependency graph, so every remediation keeps a complete, diffable record.

Because the fixed branch is a child of the original branch, the repository's compare view shows exactly
the fix. Every publish uses new branch names, so nothing that already exists on the remote is overwritten.

Authentication uses the git credentials already configured on this machine (credential helper / keychain).
Guardian never asks for, stores or logs a token. Commits use the author name and email set in the Fixes tab.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .track import before_after_markdown, findings_csv, fixes_csv, packages_csv

_URL = re.compile(r"^(https://[\w.-]+/[\w.-]+/[\w.-]+?(\.git)?/?|file:///[\w./-]+)$")  # file:// = local repo (tests)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_settings(s: dict) -> dict:
    repo = (s.get("repo") or "").strip()
    name = (s.get("name") or "").strip()
    email = (s.get("email") or "").strip()
    prefix = (s.get("branch_prefix") or "guardian").strip().strip("/") or "guardian"
    if not _URL.match(repo):
        raise ValueError("Repository must be an https URL like https://github.com/owner/repo")
    if not name:
        raise ValueError("Author name is required")
    if not _EMAIL.match(email):
        raise ValueError("Author email is not valid")
    if not re.match(r"^[\w./-]+$", prefix) or ".." in prefix:
        raise ValueError("Branch prefix may only contain letters, digits, '-', '_', '.' and '/'")
    return {"repo": repo.rstrip("/"), "name": name[:100], "email": email[:200], "branch_prefix": prefix}


def web_url(repo: str) -> str | None:
    m = re.match(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", repo)
    return f"https://github.com/{m.group(1)}/{m.group(2)}" if m else None


# ----------------------------------------------------------------------------- report markdown

def _row(cells) -> str:
    return "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |"


def report_markdown(r: dict, decisions: dict | None = None) -> str:
    t, W = r["target"], r["checkpoint"]["what_is_in_the_app"]
    L = r["checkpoint"]["what_looks_risky"]["by_risk_level"]
    ai = r.get("ai") or {}
    lines = [f"# Supply-chain report: {t['name']}@{t.get('version', '')}", "",
             f"- Repository: {t.get('upstream') or t.get('path')}" + (f" @ `{t['commit']}`" if t.get("commit") else ""),
             f"- Generated: {r['generated_at']} by Supply Chain Guardian {r['tool']['version']}",
             f"- AI explanations: {ai.get('model') if ai.get('mode') == 'llm' else 'not used (deterministic templates)'}", "",
             "## What is in the application", "",
             _row(["Components", "Direct", "Transitive", "Max depth", "Container images", "CI workflows"]),
             _row(["---"] * 6),
             _row([W.get("total_components"), W.get("direct"), W.get("transitive"), W.get("max_depth"),
                   len(W.get("container_images", [])), len(W.get("ci_workflows", []))]), "",
             "## Risk", "", _row(["Critical", "High", "Medium", "Low", "Info"]), _row(["---"] * 5),
             _row([L.get(k, 0) for k in ("Critical", "High", "Medium", "Low", "Info")]), ""]
    if ai.get("executive_summary"):
        lines += ["## Summary", "", ai["executive_summary"], "", "_Drafted by AI from verified evidence; all figures are tool-generated._", ""]
    lines += ["## Top findings", "", _row(["#", "Risk", "Finding", "Component", "Evidence"]), _row(["---"] * 5)]
    for i, f in enumerate(r["findings"][:20], 1):
        lines.append(_row([i, f"{f['risk_level']} {f['risk_score']}", f["title"][:90], f"`{f['component']}`",
                           ", ".join(sorted({e["source"] for e in f["evidence"]}))[:60]]))
    rem = r.get("remediation") or {}
    if rem.get("fixes"):
        d = decisions or {}
        n = {k: sum(1 for f in rem["fixes"] if (d.get(f["id"]) or {}).get("decision", "pending") == k)
             for k in ("approved", "rejected", "pending")}
        lines += ["", "## Proposed fixes", "",
                  f"{len(rem['fixes'])} fixes proposed: {n['approved']} approved, {n['rejected']} rejected, {n['pending']} pending; "
                  f"{len(rem.get('skipped') or [])} need a manual fix."]
    lines += ["", f"Full machine-readable report: `guardian_report.json`."]
    return "\n".join(lines) + "\n"


def verification_markdown(v: dict) -> str:
    lines = [f"# Verification of the approved fixes", "", f"**Verdict: {v.get('headline', '')}**", "",
             f"- Finished: {v.get('finished_at')} ({v.get('seconds')} s)",
             f"- Approved fixes confirmed by the re-scan: {v.get('fixed', 0)} of {v.get('total', 0)}"]
    if v.get("note"):
        lines.append(f"- {v['note']}")
    lines += ["", "## Checks", "", _row(["Check", "Result", "Detail"]), _row(["---"] * 3)]
    for k, title in (v.get("step_titles") or []):
        s = (v.get("steps") or {}).get(k)
        if s and k != "verdict":
            lines.append(_row([title, s["status"], s.get("detail", "")[:220]]))
    c = v.get("comparison")
    if c:
        lb, la = c["levels_before"], c["levels_after"]
        lines += ["", "## Before and after the fixes", "", _row(["", "Before", "After"]), _row(["---"] * 3)]
        for k in ("Critical", "High", "Medium", "Low"):
            lines.append(_row([k, lb.get(k, 0), la.get(k, 0)]))
        lines += [_row(["All findings", c["findings_before"], c["findings_after"]]),
                  _row(["Vulnerable packages", c.get("vulnerable_packages_before"), c.get("vulnerable_packages_after")]), "",
                  f"Known issues resolved: {c['resolved_count']}."]
        if c.get("expected_changes"):
            lines.append(f"{c['expected_changes']} changes made by the fixes themselves are expected and not counted as risk.")
        lines += ["", "## Approved fixes", "", _row(["Package", "Change", "Advisories fixed", "Result"]), _row(["---"] * 4)]
        order = {"not fixed": 0, "partly fixed": 1, "fixed": 2}
        for f in sorted(c["fixes"], key=lambda f: (order.get(f["status"], 3), f["package"])):
            lines.append(_row([f"`{f['package']}`", f"{f['from_version']} → {f['to_version']} ({f['bump']})",
                               f"{f['fixed']} / {f['of']}", f["status"] + (f" ({f['reason']})" if f.get("reason") else "")]))
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- publish

Runner = Callable[..., subprocess.CompletedProcess]


def _git(args: list[str], cwd: Path, run: Runner, timeout: int = 600) -> str:
    p = run(["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
            env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                 "HOME": str(Path.home())})
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).strip().splitlines()
        tail = " | ".join(msg[-3:])
        if "could not read Username" in tail or "Authentication failed" in tail or "terminal prompts disabled" in tail:
            raise PermissionError("git has no saved credentials for this repository. Push to it once from a terminal "
                                  "(git will store your token in the keychain), then publish again.")
        if "Permission to" in tail or "403" in tail:
            raise PermissionError("your git account does not have write access to this repository.")
        raise RuntimeError(f"git {args[0]} failed: {tail}")
    return p.stdout


def _copy_code(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        if item.name in (".git", "node_modules"):
            continue
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target, ignore=shutil.ignore_patterns(".git", "node_modules"), symlinks=True)
        else:
            shutil.copy2(item, target)


def _write_snapshot(folder: Path, report: dict, src: Path, decisions: dict) -> None:
    """REPORT.md + CSVs + raw JSON/SBOM/graph for one state of the code (before or after the fixes)."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "REPORT.md").write_text(report_markdown(report, decisions), encoding="utf-8")
    (folder / "findings.csv").write_text(findings_csv(report), encoding="utf-8")
    (folder / "packages.csv").write_text(packages_csv(report), encoding="utf-8")
    (folder / "guardian_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    for name in ("sbom.cdx.json", "deptree_graph.json"):
        if (src / name).exists():
            shutil.copy2(src / name, folder / name)


def publish(out: Path, settings: dict, emit=lambda *a: None, run: Runner = subprocess.run,
            now: datetime | None = None) -> dict:
    """Create and push the -original and -fixed branches. Needs a finished verification (sandbox present)."""
    s = validate_settings(settings)
    report = json.loads((out / "guardian_report.json").read_text(encoding="utf-8"))
    vpath, sandbox = out / "verification.json", out / "sandbox"
    if not vpath.exists() or not sandbox.exists():
        raise FileNotFoundError("Run Verify first: publishing needs the verified fixed code.")
    verification = json.loads(vpath.read_text(encoding="utf-8"))
    after_dir = out / "verify"
    if not (after_dir / "guardian_report.json").exists():
        raise FileNotFoundError("The re-scan of the fixed code is missing: run Verify again, then publish.")
    after = json.loads((after_dir / "guardian_report.json").read_text(encoding="utf-8"))
    decisions = json.loads((out / "approvals.json").read_text(encoding="utf-8")) if (out / "approvals.json").exists() else {}
    target = Path(report["target"]["path"])
    slug = re.sub(r"[^\w.-]+", "-", report["target"].get("slug") or target.name).strip("-")
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    base = f"{s['branch_prefix']}/{slug}-{stamp}"
    b_orig, b_fixed = f"{base}-original", f"{base}-fixed"
    ident = ["-c", f"user.name={s['name']}", "-c", f"user.email={s['email']}", "-c", "commit.gpgsign=false"]

    work = Path(tempfile.mkdtemp(prefix="guardian-publish-")) / "repo"
    work.mkdir()
    try:
        emit("prepare", "running", f"Preparing branches {b_orig} and {b_fixed}")
        _git(["init", "-q", "-b", b_orig], work, run)
        _copy_code(target, work)
        rep = work / "guardian-report"
        _write_snapshot(rep / "before", report, out, decisions)
        _git([*ident, "add", "-A"], work, run)
        n_find = len(report["findings"])
        _git([*ident, "commit", "-q", "-m", f"Original code of {report['target']['name']} with the Guardian report",
              "-m", f"Scanned by Supply Chain Guardian: {n_find} findings. Source: "
                    f"{report['target'].get('upstream') or target.name}"
                    + (f" @ {report['target']['commit']}" if report["target"].get("commit") else "")], work, run)
        emit("original", "done", f"Committed the original code and report on {b_orig}")

        _git(["checkout", "-q", "-b", b_fixed], work, run)
        for name in ("package.json", "package-lock.json"):
            if (sandbox / name).exists():
                shutil.copy2(sandbox / name, work / name)
        _write_snapshot(rep / "after", after, after_dir, decisions)
        plan = report.get("remediation") or {"fixes": [], "skipped": []}
        (rep / "BEFORE_AFTER.md").write_text(before_after_markdown(report, after, verification, plan, decisions), encoding="utf-8")
        (rep / "fixes.csv").write_text(fixes_csv(plan, decisions, verification), encoding="utf-8")
        (rep / "VERIFICATION.md").write_text(verification_markdown(verification), encoding="utf-8")
        shutil.copy2(vpath, rep / "verification.json")
        for name in ("remediation.patch", "approvals.json", "remediation_result.json"):
            if (out / name).exists():
                shutil.copy2(out / name, rep / name)
        _git([*ident, "add", "-A"], work, run)
        approved = sum(1 for d in decisions.values() if d.get("decision") == "approved")
        _git([*ident, "commit", "-q", "-m", f"Apply {approved} approved dependency fixes",
              "-m", f"Verification: {verification.get('headline', '')}. "
                    f"{verification.get('fixed', 0)} of {verification.get('total', 0)} fixes confirmed by the re-scan."],
             work, run)
        emit("fixed", "done", f"Committed the fixed code and verification report on {b_fixed}")

        emit("push", "running", f"Pushing both branches to {s['repo']}")
        _git(["push", "-q", s["repo"], f"{b_orig}:refs/heads/{b_orig}", f"{b_fixed}:refs/heads/{b_fixed}"], work, run, timeout=900)
        emit("push", "done", "Both branches pushed")
        web = web_url(s["repo"])
        result = {"ok": True, "repo": s["repo"], "original_branch": b_orig, "fixed_branch": b_fixed,
                  "published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "author": f"{s['name']} <{s['email']}>",
                  "links": {"original": f"{web}/tree/{b_orig}", "fixed": f"{web}/tree/{b_fixed}",
                            "compare": f"{web}/compare/{b_orig}...{b_fixed}"} if web else {}}
        (out / "publish.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)
