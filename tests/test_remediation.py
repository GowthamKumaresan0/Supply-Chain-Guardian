"""Fix proposals, human approval, sandbox apply + verification."""
from __future__ import annotations

import json

import pytest

from guardian import remediation as rem
from guardian.discover import discover
from guardian.models import Finding


def vuln(component, fixed, vid, risk=80, level="Critical", category="vulnerability", scope="runtime"):
    return Finding(id=f"VULN-{component}-{vid}", category=category, title=vid, severity="HIGH", component=component,
                   scope=scope, vuln_ids=[vid], fixed_version=fixed, risk_score=risk, risk_level=level)


def test_choose_version():
    assert rem.choose_version("4.17.20", [["4.17.21"], ["4.17.19", "4.17.21"]]) == ("4.17.21", "patch")
    # must satisfy every advisory: the higher of the two nearest fixes wins
    assert rem.choose_version("1.2.0", [["1.2.3"], ["1.2.6", "0.2.4"]]) == ("1.2.6", "patch")
    # prefer staying on the current major when a fix exists there
    assert rem.choose_version("2.1.0", [["3.0.0", "2.4.1"]]) == ("2.4.1", "minor")
    assert rem.choose_version("2.1.0", [["3.0.0"]]) == ("3.0.0", "major")
    assert rem.choose_version("5.0.0", [["4.0.0"]])[0] is None


def test_plan_direct_and_transitive(app_dir):
    inv = discover(app_dir)
    findings = [vuln("lodash@4.17.20", "4.17.21", "GHSA-a"), vuln("lodash@4.17.20", "4.17.21", "GHSA-b", risk=60, level="High"),
                vuln("minimist@1.2.0", "1.2.6, 0.2.4", "GHSA-c", risk=70, level="High"),
                vuln("flatmap-stream@0.1.1", "", "MAL-1", risk=100, category="malicious-package")]
    plan = rem.plan_fixes(app_dir, findings, inv)
    by = {f["package"]: f for f in plan["fixes"]}
    lod = by["lodash"]
    assert lod["kind"] == "direct" and lod["old_spec"] == "^4.17.20" and lod["new_spec"] == "^4.17.21"
    assert lod["advisories"] == ["GHSA-a", "GHSA-b"] and lod["bump"] == "patch" and lod["max_risk"] == 80
    mini = by["minimist"]
    assert mini["kind"] == "override" and mini["to_version"] == "1.2.6"
    # the side-by-side diff shows the old and the new package.json lines
    assert any(r["t"] == "chg" and '"^4.17.20"' in r["o"] and '"^4.17.21"' in r["n"] for r in lod["diff"])
    assert any(r["t"] == "add" and '"minimist@1.2.0": "1.2.6"' in (r["n"] or "") for r in mini["diff"])
    assert plan["fixes"][0]["package"] == "lodash"                       # highest risk first
    assert plan["skipped"][0]["package"] == "flatmap-stream@0.1.1"
    assert "manually" in plan["skipped"][0]["reason"]


def test_apply_to_manifest_combines_fixes():
    pj = {"dependencies": {"lodash": "^4.17.20"}}
    out = rem.apply_to_manifest(pj, [
        {"kind": "direct", "section": "dependencies", "package": "lodash", "new_spec": "^4.17.21"},
        {"kind": "override", "package": "minimist", "from_version": "1.2.0", "to_version": "1.2.6"}])
    assert out == {"dependencies": {"lodash": "^4.17.21"}, "overrides": {"minimist@1.2.0": "1.2.6"}}
    assert pj == {"dependencies": {"lodash": "^4.17.20"}}                # original untouched


def test_side_by_side_marks_changes():
    rows = rem.side_by_side("a\nb\nc\n", "a\nB\nc\nd\n")
    assert [r["t"] for r in rows] == ["same", "chg", "same", "add"]


def test_decisions_keep_history(tmp_path):
    rem.record_decision(tmp_path, "FIX-x@1", "approved", "Asha", "looks fine")
    d = rem.record_decision(tmp_path, "FIX-x@1", "rejected", "Ravi", "breaks tests")
    assert d["decision"] == "rejected" and [h["reviewer"] for h in d["history"]] == ["Asha", "Ravi"]
    assert rem.load_decisions(tmp_path)["FIX-x@1"]["comment"] == "breaks tests"
    with pytest.raises(ValueError):
        rem.record_decision(tmp_path, "FIX-x@1", "maybe")


def _fake_npm(versions):
    """Stub for npm --package-lock-only: sets (or re-adds pruned) lockfile entries to the given versions."""
    def run(cwd):
        lock = json.loads((cwd / "package-lock.json").read_text())
        for key, ver in versions.items():
            lock["packages"].setdefault(key, {})["version"] = ver
        (cwd / "package-lock.json").write_text(json.dumps(lock, indent=2))
        return True, "npm install --package-lock-only --ignore-scripts"
    return run


def test_apply_in_sandbox_and_verify(app_dir, tmp_path, monkeypatch):
    inv = discover(app_dir)
    plan = rem.plan_fixes(app_dir, [vuln("lodash@4.17.20", "4.17.21", "GHSA-a"),
                                    vuln("minimist@1.2.0", "1.2.6", "GHSA-c", risk=70, level="High")], inv)
    out = tmp_path / "out"
    out.mkdir()
    assert rem.apply_fixes(app_dir, out, plan, {}, None) == {"ok": False, "error": "No fixes are approved yet."}

    rem.record_decision(out, "FIX-lodash@4.17.20", "approved", "Asha")
    rem.record_decision(out, "FIX-minimist@1.2.0", "approved", "Asha")
    # the old minimist entry is pruned first, so npm must re-resolve it with the override
    monkeypatch.setattr(rem, "_run_npm", _fake_npm({"node_modules/lodash": "4.17.21", "node_modules/minimist": "1.2.6"}))

    def rescan(sandbox):
        sinv = discover(sandbox)
        installed = {}
        for c in sinv.components.values():
            installed.setdefault(c.name, []).append(c.version)
        return {}, installed

    original = (app_dir / "package.json").read_text()
    r = rem.apply_fixes(app_dir, out, plan, rem.load_decisions(out), rescan)
    assert r["ok"] and r["total"] == 2 and r["resolved"] == 2 and r["pruned_lock_entries"] == 1
    st = {x["package"]: x for x in r["results"]}
    assert st["lodash"]["status"] == "resolved" and st["lodash"]["installed_now"] == ["4.17.21"]
    assert st["minimist"]["status"] == "resolved" and st["minimist"]["installed_now"] == ["1.2.6"]
    sandbox_pj = json.loads((out / "sandbox" / "package.json").read_text())
    assert sandbox_pj["dependencies"]["lodash"] == "^4.17.21" and sandbox_pj["overrides"] == {"minimist@1.2.0": "1.2.6"}
    assert (app_dir / "package.json").read_text() == original          # original repository never changed
    patch = (out / "remediation.patch").read_text()
    assert "+++ b/package.json" in patch and "+++ b/package-lock.json" in patch


def test_npm_failure_is_reported(app_dir, tmp_path, monkeypatch):
    inv = discover(app_dir)
    plan = rem.plan_fixes(app_dir, [vuln("lodash@4.17.20", "4.17.21", "GHSA-a")], inv)
    out = tmp_path / "o"
    out.mkdir()
    rem.record_decision(out, "FIX-lodash@4.17.20", "approved", "Asha")
    monkeypatch.setattr(rem, "_run_npm", lambda cwd: (False, "npm is not installed, so the lockfile cannot be regenerated"))
    r = rem.apply_fixes(app_dir, out, plan, rem.load_decisions(out), None)
    assert not r["ok"] and "npm is not installed" in r["error"]


# ------------------------------------------------------------------ API

@pytest.fixture
def report(tmp_path, app_dir, monkeypatch):
    from guardian import server
    out_root = tmp_path / "output"
    out = out_root / "demo"
    out.mkdir(parents=True)
    inv = discover(app_dir)
    plan = rem.plan_fixes(app_dir, [vuln("lodash@4.17.20", "4.17.21", "GHSA-a")], inv)
    (out / "guardian_report.json").write_text(json.dumps({"target": {"path": str(app_dir)}, "remediation": plan}))
    monkeypatch.setattr(server, "OUTPUT", out_root)
    server.app.config["TESTING"] = True
    return server.app.test_client(), out


def test_fix_api(report, monkeypatch):
    c, out = report
    st = c.get("/api/report/demo/fixes").get_json()
    assert [f["id"] for f in st["plan"]["fixes"]] == ["FIX-lodash@4.17.20"] and st["decisions"] == {}
    assert c.post("/api/report/demo/fixes/FIX-nope/decision", json={"decision": "approved"}).status_code == 404
    assert c.post("/api/report/demo/fixes/FIX-lodash@4.17.20/decision", json={"decision": "maybe"}).status_code == 400
    assert c.post("/api/report/demo/fixes/apply").status_code == 400            # nothing approved
    ok = c.post("/api/report/demo/fixes/FIX-lodash@4.17.20/decision", json={"decision": "approved", "reviewer": "Asha"})
    assert ok.status_code == 200 and ok.get_json()["reviewer"] == "Asha"
    assert c.get("/api/report/demo/fixes/patch").status_code == 404
    from guardian import server
    monkeypatch.setattr(rem, "_run_npm", _fake_npm({"node_modules/lodash": "4.17.21"}))
    monkeypatch.setattr(server, "_rescan", lambda sb: ({}, {"lodash": ["4.17.21"]}))
    r = c.post("/api/report/demo/fixes/apply")
    assert r.status_code == 200 and r.get_json()["resolved"] == 1
    assert c.get("/api/report/demo/fixes/patch").status_code == 200
    assert c.get("/api/report/demo/fixes").get_json()["result"]["resolved"] == 1


def test_partial_coverage_and_ghsa_range_fix(app_dir):
    from guardian.advisories import fixed_from_range
    assert fixed_from_range("<4.17.21") == "4.17.21"
    assert fixed_from_range(">=1.0.0 <1.2.6 || <0.2.4") == "1.2.6, 0.2.4"
    assert fixed_from_range("<=1.0.0") == ""
    inv = discover(app_dir)
    plan = rem.plan_fixes(app_dir, [vuln("lodash@4.17.20", "4.17.21", "GHSA-a"), vuln("lodash@4.17.20", "", "GHSA-x")], inv)
    fx = plan["fixes"][0]
    assert fx["advisories"] == ["GHSA-a"] and fx["not_covered"] == ["GHSA-x"] and "Not covered" in fx["why"]


def test_bundled_copies_are_flagged(app_dir):
    lock = json.loads((app_dir / "package-lock.json").read_text())
    lock["packages"]["node_modules/mkdirp/node_modules/minimist"] = {"version": "1.2.0", "inBundle": True}
    (app_dir / "package-lock.json").write_text(json.dumps(lock))
    inv = discover(app_dir)
    fx = rem.plan_fixes(app_dir, [vuln("minimist@1.2.0", "1.2.6", "GHSA-c")], inv)["fixes"][0]
    assert fx["bundled_in"] == ["mkdirp"] and "bundled inside mkdirp" in fx["why"]


def test_bulk_decisions_and_optional_reviewer(tmp_path):
    out = rem.record_decisions(tmp_path, ["FIX-a@1", "FIX-b@1"], "approved", bulk=True)
    assert set(out) == {"FIX-a@1", "FIX-b@1"} and out["FIX-a@1"]["reviewer"] == "" and out["FIX-a@1"]["bulk"]
    single = rem.record_decision(tmp_path, "FIX-a@1", "rejected", comment="breaks login")
    assert single["reviewer"] == "" and len(single["history"]) == 2
    assert rem.load_decisions(tmp_path)["FIX-b@1"]["decision"] == "approved"


def test_bulk_api(report):
    c, out = report
    assert c.post("/api/report/demo/fixes/decisions", json={"ids": ["FIX-nope"], "decision": "approved"}).status_code == 400
    r = c.post("/api/report/demo/fixes/decisions", json={"ids": "all", "decision": "approved", "reviewer": "Team"})
    assert r.status_code == 200 and r.get_json()["updated"] == 1
    st = c.get("/api/report/demo/fixes").get_json()["decisions"]
    assert st["FIX-lodash@4.17.20"]["decision"] == "approved" and st["FIX-lodash@4.17.20"]["reviewer"] == "Team"
    # a single decision with no reviewer and no comment is accepted
    assert c.post("/api/report/demo/fixes/FIX-lodash@4.17.20/decision", json={"decision": "pending"}).status_code == 200
    assert c.post("/api/report/demo/fixes/decisions", json={"ids": "all", "decision": "maybe"}).status_code == 400


def test_bundled_copy_is_reported_not_applied(app_dir, tmp_path, monkeypatch):
    lock = json.loads((app_dir / "package-lock.json").read_text())
    lock["packages"]["node_modules/minimist"]["inBundle"] = True          # ships inside its parent's tarball
    (app_dir / "package-lock.json").write_text(json.dumps(lock))
    inv = discover(app_dir)
    plan = rem.plan_fixes(app_dir, [vuln("minimist@1.2.0", "1.2.6", "GHSA-c", risk=70, level="High")], inv)
    out = tmp_path / "out"
    out.mkdir()
    rem.record_decision(out, "FIX-minimist@1.2.0", "approved")
    monkeypatch.setattr(rem, "_run_npm", _fake_npm({}))
    rescan = lambda sb: ({"minimist@1.2.0": ["GHSA-c"]}, {"minimist": ["1.2.0"]})
    r = rem.apply_fixes(app_dir, out, plan, rem.load_decisions(out), rescan)
    x = r["results"][0]
    assert r["pruned_lock_entries"] == 0 and x["status"] == "not applied" and "bundled" in x["note"]


def test_prune_paths_keeps_bundled(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"packages": {"node_modules/a/node_modules/x": {"version": "1"},
                                          "node_modules/a/node_modules/x/node_modules/y": {"version": "1"},
                                          "node_modules/b/node_modules/x": {"version": "1", "inBundle": True}}}))
    assert rem.prune_paths(p, ["node_modules/a/node_modules/x", "node_modules/b/node_modules/x", "node_modules/none"]) == 1
    assert list(json.loads(p.read_text())["packages"]) == ["node_modules/b/node_modules/x"]


def test_stale_siblings_are_reresolved(app_dir, tmp_path, monkeypatch):
    """Regression: an upgraded parent kept old siblings it no longer accepts (zaproxy › request › combined-stream)."""
    inv = discover(app_dir)
    plan = rem.plan_fixes(app_dir, [vuln("lodash@4.17.20", "4.17.21", "GHSA-a")], inv)
    out = tmp_path / "out"
    out.mkdir()
    rem.record_decision(out, "FIX-lodash@4.17.20", "approved")
    runs = []
    def npm(cwd):
        runs.append(1)
        return _fake_npm({"node_modules/lodash": "4.17.21"})(cwd)
    monkeypatch.setattr(rem, "_run_npm", npm)
    rounds = iter([["node_modules/mkdirp"], []])
    monkeypatch.setattr(rem, "invalid_lock_paths", lambda app: next(rounds))
    r = rem.apply_fixes(app_dir, out, plan, rem.load_decisions(out), lambda sb: ({}, {"lodash": ["4.17.21"]}))
    assert len(runs) == 2 and r["reresolve_rounds"] == 1 and r["pruned_lock_entries"] == 1
