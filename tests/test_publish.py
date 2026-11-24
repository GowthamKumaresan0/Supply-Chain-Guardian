"""Publishing the original and the fixed code as two branches (pushed to a local bare repository)."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest

from guardian import publish as P


def git(*a, cwd):
    return subprocess.run(["git", *a], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def report_json(target):
    return {"target": {"name": "demo-app", "version": "1.0.0", "path": str(target), "slug": "demo",
                       "upstream": "https://github.com/x/demo", "commit": "abc123"},
            "generated_at": "2026-11-24T00:00:00+00:00", "tool": {"version": "1.0"}, "ai": {"mode": "fallback"},
            "checkpoint": {"what_is_in_the_app": {"total_components": 4, "direct": 2, "transitive": 2, "max_depth": 2,
                                                  "container_images": ["node:18"], "ci_workflows": ["ci.yml"]},
                           "what_looks_risky": {"by_risk_level": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0}}},
            "findings": [{"id": "VULN-lodash@4.17.20-GHSA-a", "category": "vulnerability", "risk_level": "Critical",
                          "risk_score": 90, "title": "Command Injection in lodash", "component": "lodash@4.17.20",
                          "vuln_ids": ["GHSA-a"], "evidence": [{"source": "OSV.dev"}]}],
            "vulnerability_scan": {"vulnerable_packages": 1},
            "inventory": [{"name": "lodash", "version": "4.17.20", "scope": "runtime", "direct": True, "depth": 1,
                           "parents": 1, "install_script": False, "source": "registry.npmjs.org", "lock_path": "node_modules/lodash"}],
            "remediation": {"fixes": [{"id": "FIX-lodash@4.17.20", "package": "lodash", "from_version": "4.17.20",
                                       "to_version": "4.17.21", "bump": "patch", "kind": "direct", "advisories": ["GHSA-a"]}],
                            "skipped": []}}


VERIFICATION = {"headline": "All approved fixes are verified", "finished_at": "2026-11-24T01:00:00+00:00", "seconds": 30,
                "fixed": 1, "total": 1, "note": "", "step_titles": [["install", "Clean install"], ["verdict", "Verdict"]],
                "steps": {"install": {"status": "pass", "detail": "succeeded in 5s"}},
                "comparison": {"levels_before": {"Critical": 1, "High": 0, "Medium": 0, "Low": 0},
                               "levels_after": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                               "findings_before": 1, "findings_after": 0, "vulnerable_packages_before": 1,
                               "vulnerable_packages_after": 0, "resolved_count": 1, "expected_changes": 2,
                               "fixes": [{"id": "FIX-lodash@4.17.20", "package": "lodash", "from_version": "4.17.20", "to_version": "4.17.21",
                                          "bump": "patch", "fixed": 1, "of": 1, "status": "fixed"}]}}


@pytest.fixture
def scan(tmp_path, app_dir):
    (app_dir / "node_modules" / "x").mkdir(parents=True)
    (app_dir / "node_modules" / "x" / "index.js").write_text("// must not be published")
    out = tmp_path / "out"
    (out / "sandbox").mkdir(parents=True)
    pj = json.loads((app_dir / "package.json").read_text())
    pj["dependencies"]["lodash"] = "^4.17.21"
    (out / "sandbox" / "package.json").write_text(json.dumps(pj, indent=2))
    (out / "sandbox" / "package-lock.json").write_text((app_dir / "package-lock.json").read_text())
    (out / "guardian_report.json").write_text(json.dumps(report_json(app_dir)))
    (out / "verification.json").write_text(json.dumps(VERIFICATION))
    after = report_json(app_dir)
    after.update(generated_at="2026-11-24T01:00:00+00:00", findings=[], vulnerability_scan={"vulnerable_packages": 0},
                 inventory=[{**after["inventory"][0], "version": "4.17.21"}])
    after["checkpoint"]["what_looks_risky"]["by_risk_level"] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    (out / "verify").mkdir()
    (out / "verify" / "guardian_report.json").write_text(json.dumps(after))
    (out / "approvals.json").write_text(json.dumps({"FIX-lodash@4.17.20": {"decision": "approved"}}))
    (out / "remediation.patch").write_text("--- a/package.json\n+++ b/package.json\n")
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    return out, bare


def test_validate_settings():
    ok = P.validate_settings({"repo": "https://github.com/N0VA06/bosch-team17-cve-scanner/", "name": "Vijay", "email": "v@x.io"})
    assert ok == {"repo": "https://github.com/N0VA06/bosch-team17-cve-scanner", "name": "Vijay", "email": "v@x.io",
                  "branch_prefix": "guardian"}
    for bad in ({"repo": "git@github.com:a/b.git", "name": "a", "email": "a@b.co"},
                {"repo": "https://github.com/a/b", "name": "", "email": "a@b.co"},
                {"repo": "https://github.com/a/b", "name": "a", "email": "nope"},
                {"repo": "https://github.com/a/b", "name": "a", "email": "a@b.co", "branch_prefix": "../x"}):
        with pytest.raises(ValueError):
            P.validate_settings(bad)
    assert P.web_url("https://github.com/a/b.git") == "https://github.com/a/b" and P.web_url("file:///tmp/x") is None


def test_publish_two_branches(scan, tmp_path):
    out, bare = scan
    settings = {"repo": f"file://{bare}", "name": "Vijay Srinivas", "email": "vijay@example.com"}
    events = []
    r = P.publish(out, settings, emit=lambda *a: events.append(a), now=datetime(2026, 11, 24, 6, 0, 0, tzinfo=timezone.utc))
    assert r["original_branch"] == "guardian/demo-20261124-060000-original"
    assert r["fixed_branch"] == "guardian/demo-20261124-060000-fixed"
    heads = git("for-each-ref", "--format=%(refname:short)", "refs/heads", cwd=bare).split()
    assert sorted(heads) == sorted([r["original_branch"], r["fixed_branch"]])
    # fixed is a child of original, so compare shows exactly the fix
    assert git("rev-parse", f"{r['fixed_branch']}^", cwd=bare) == git("rev-parse", r["original_branch"], cwd=bare)
    orig_files = git("ls-tree", "-r", "--name-only", r["original_branch"], cwd=bare).split()
    assert "package.json" in orig_files and "guardian-report/before/REPORT.md" in orig_files
    assert {"guardian-report/before/findings.csv", "guardian-report/before/packages.csv",
            "guardian-report/before/guardian_report.json"} <= set(orig_files)
    assert not any(f.startswith("node_modules/") for f in orig_files)
    changed = git("diff", "--name-only", r["original_branch"], r["fixed_branch"], cwd=bare).split()
    assert {"package.json", "guardian-report/VERIFICATION.md", "guardian-report/remediation.patch",
            "guardian-report/BEFORE_AFTER.md", "guardian-report/fixes.csv", "guardian-report/after/REPORT.md",
            "guardian-report/after/findings.csv", "guardian-report/after/packages.csv"} <= set(changed)
    assert not any(c.startswith("guardian-report/before/") for c in changed)          # the starting point is untouched
    ba = git("show", f"{r['fixed_branch']}:guardian-report/BEFORE_AFTER.md", cwd=bare)
    assert "## Resolved by the fixes (1)" in ba and "Command Injection in lodash" in ba and "`lodash` | 4.17.20 | 4.17.21" in ba
    assert '"^4.17.21"' in git("show", f"{r['fixed_branch']}:package.json", cwd=bare)
    assert git("log", "-1", "--format=%an <%ae>", r["fixed_branch"], cwd=bare) == "Vijay Srinivas <vijay@example.com>"
    assert "All approved fixes are verified" in git("show", f"{r['fixed_branch']}:guardian-report/VERIFICATION.md", cwd=bare)
    assert "Command Injection in lodash" in git("show", f"{r['original_branch']}:guardian-report/before/REPORT.md", cwd=bare)
    assert (out / "publish.json").exists() and [e[0] for e in events][-1] == "push"


def test_publish_needs_verification(scan):
    out, bare = scan
    (out / "verification.json").unlink()
    with pytest.raises(FileNotFoundError):
        P.publish(out, {"repo": f"file://{bare}", "name": "a", "email": "a@b.co"})


def test_missing_credentials_message(scan, monkeypatch):
    out, _ = scan
    real = subprocess.run

    def fake(cmd, **kw):
        if cmd[:2] == ["git", "push"]:
            return subprocess.CompletedProcess(cmd, 128, "", "fatal: could not read Username for 'https://github.com': terminal prompts disabled")
        return real(cmd, **kw)
    with pytest.raises(PermissionError) as e:
        P.publish(out, {"repo": "https://github.com/a/b", "name": "a", "email": "a@b.co"}, run=fake)
    assert "Push to it once from a terminal" in str(e.value)


def test_publish_settings_api(tmp_path, monkeypatch):
    from guardian import server
    monkeypatch.setattr(server, "OUTPUT", tmp_path / "output")
    c = server.app.test_client()
    assert c.get("/api/publish/settings").get_json() == {}
    assert c.post("/api/publish/settings", json={"repo": "ftp://x", "name": "a", "email": "a@b.co"}).status_code == 400
    ok = c.post("/api/publish/settings", json={"repo": "https://github.com/a/b", "name": "A", "email": "a@b.co"})
    assert ok.status_code == 200 and c.get("/api/publish/settings").get_json()["repo"] == "https://github.com/a/b"


def test_publish_needs_the_rescan(scan):
    out, bare = scan
    (out / "verify" / "guardian_report.json").unlink()
    with pytest.raises(FileNotFoundError):
        P.publish(out, {"repo": f"file://{bare}", "name": "a", "email": "a@b.co"})


def test_report_counts_auto_applied_fixes(app_dir):
    rem = {"fixes": [{"id": "A", "bump": "patch"}, {"id": "B", "bump": "minor"}, {"id": "C", "bump": "major"},
                     {"id": "D", "bump": "major"}, {"id": "E", "bump": "patch"}], "skipped": []}
    r = {**report_json(app_dir), "remediation": rem}
    md = P.report_markdown(r, {"C": {"decision": "approved"}, "E": {"decision": "undone"}})
    assert "5 fixes proposed: 1 approved, 2 auto-applied (safe patch/minor), 1 rejected or undone, 1 pending" in md
