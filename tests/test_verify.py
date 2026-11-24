"""Verification after approval: build, runtime load, tests, re-scan comparison and verdict (Docker faked)."""
from __future__ import annotations

import json
import subprocess

import pytest

from guardian import verify as V


def report(levels, findings, vuln_pkgs):
    return {"checkpoint": {"what_looks_risky": {"by_risk_level": levels}}, "findings": findings,
            "vulnerability_scan": {"vulnerable_packages": vuln_pkgs}}


def f(comp, vid, level="High", score=70, cat="vulnerability"):
    return {"id": f"VULN-{comp}-{vid}", "category": cat, "component": comp, "title": vid, "vuln_ids": [vid],
            "risk_level": level, "risk_score": score}


FIXES = [{"id": "FIX-marked@0.3.5", "package": "marked", "from_version": "0.3.5", "to_version": "4.0.10", "bump": "major",
          "advisories": ["GHSA-1", "GHSA-2"]},
         {"id": "FIX-minimist@1.2.0", "package": "minimist", "from_version": "1.2.0", "to_version": "1.2.6", "bump": "patch",
          "advisories": ["GHSA-3", "GHSA-4"]}]


def test_compare_confirms_fixes_and_finds_regressions():
    before = report({"Critical": 2, "High": 3}, [f("marked@0.3.5", "GHSA-1", "Critical", 90), f("marked@0.3.5", "GHSA-2"),
                                                f("minimist@1.2.0", "GHSA-3"), f("minimist@1.2.0", "GHSA-4")], 2)
    after = report({"Critical": 0, "High": 2}, [f("minimist@1.2.0", "GHSA-3"), f("marked@4.0.10", "GHSA-9", "High", 75)], 2)
    c = V.compare(before, after, FIXES)
    st = {x["package"]: x for x in c["fixes"]}
    assert st["marked"]["status"] == "fixed" and st["marked"]["new_issues_in_new_version"] == ["GHSA-9"]
    assert st["minimist"]["status"] == "partly fixed" and st["minimist"]["left"] == ["GHSA-3"]
    assert c["resolved_count"] == 3 and c["introduced_count"] == 1
    assert c["levels_before"]["Critical"] == 2 and c["levels_after"]["Critical"] == 0


def test_verdicts():
    ok_fix = {"fixes": [{"status": "fixed"}], "introduced": []}
    assert V.verdict({"install": {"status": "pass"}}, ok_fix)["verdict"] == "verified"
    assert V.verdict({"install": {"status": "fail"}}, ok_fix)["verdict"] == "build-failed"
    assert V.verdict({"tests": {"status": "fail"}}, ok_fix)["verdict"] == "regression"
    assert V.verdict({}, {"fixes": [{"status": "fixed"}], "introduced": [{"risk_level": "Critical"}]})["verdict"] == "new-risk"
    assert V.verdict({}, {"fixes": [{"status": "partly fixed"}], "introduced": []})["verdict"] == "partial"
    pre = V.verdict({"tests": {"status": "warn", "pre_existing": True}}, ok_fix)
    assert pre["verdict"] == "verified" and "tests" in pre["note"]


def test_compare_step_judges_against_original():
    ok, bad = {"ok": True, "seconds": 3}, {"ok": False, "exit_code": 1}
    assert V._compare_step("tests", {"tests": bad}, {"tests": ok})["status"] == "pass"
    pre = V._compare_step("tests", {"tests": bad}, {"tests": bad})
    assert pre["status"] == "warn" and pre["pre_existing"]                           # failed before too: not the fix
    assert V._compare_step("tests", {"tests": ok}, {"tests": bad})["status"] == "fail"  # broke a passing build
    rt = V._compare_step("runtime", {"runtime": {"ok": ["a"], "failed": []}},
                         {"runtime": {"ok": [], "failed": [{"name": "a", "error": "x"}], "node": "v12"}})
    assert rt["status"] == "fail" and "newly failing: a" in rt["detail"]
    assert V._compare_step("tests", None, {"tests": {"skipped": True, "reason": "no test script"}})["status"] == "skip"


def test_pick_image_and_usages(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM --platform=linux/amd64 node:12-alpine AS build\nFROM node:latest\n")
    assert V.pick_node_image(tmp_path) == "node:12-alpine"
    (tmp_path / "Dockerfile").unlink()
    (tmp_path / "package.json").write_text(json.dumps({"engines": {"node": ">=18"}}))
    assert V.pick_node_image(tmp_path) == "node:18-alpine"
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.js").write_text("const marked = require('marked');\nimport y from '@scope/pkg/sub';\nrequire('./local')\n")
    (tmp_path / "node_modules" / "z").mkdir(parents=True)
    (tmp_path / "node_modules" / "z" / "i.js").write_text("require('marked')")
    u = V.usages(tmp_path, ["marked", "@scope/pkg", "other"])
    assert u == {"marked": ["app/x.js:1"], "@scope/pkg": ["app/x.js:2"], "other": []}


def test_npm_failure_names():
    log = ("npm ERR! 404 Not Found - GET https://registry.npmjs.org/expresss - Not found\n"
           "npm ERR! request to http://203.0.113.10/underscore/-/underscore-1.9.1.tgz failed, reason: connect ETIMEDOUT")
    names = V._npm_failures(log)
    assert "expresss" in names and any("203.0.113.10" in n for n in names)
    # npm's explicit message gives name@version, which wins over the bare name
    log2 = "npm ERR! 404 Not Found - GET https://registry.npmjs.org/expresss/-/expresss-1.0.2.tgz\n" \
           "npm ERR! 404  'expresss@1.0.2' is not in the npm registry."
    assert V._npm_failures(log2) == ["expresss@1.0.2"]


class FakeDocker:
    """Records commands; scripted outcomes per (label, step)."""
    def __init__(self, outcomes, available=True):
        self.outcomes, self.ok, self.vols = outcomes, available, []

    def available(self):
        return (True, "29.0") if self.ok else (False, "Docker is not installed")

    def pull(self, image):
        return subprocess.CompletedProcess([], 0, b"", b"")

    def volume_from(self, folder):
        self.vols.append(folder.name)
        return folder.name

    def node(self, vol, image, script, network, timeout):
        kind = "install" if script.startswith("npm ci") else "runtime" if "GUARDIAN_RUNTIME" in script else "tests"
        assert network == (kind == "install")                       # project code never gets the network
        code, out = self.outcomes[(vol, kind)]
        return subprocess.CompletedProcess([], code, out.encode(), b"")

    def remove(self, vol):
        pass


def _setup(tmp_path, app_dir):
    out = tmp_path / "out"
    out.mkdir()
    plan = {"skipped": []}
    plan["fixes"] = [{"id": "FIX-lodash@4.17.20", "package": "lodash", "from_version": "4.17.20", "to_version": "4.17.21",
                      "bump": "patch", "kind": "direct", "section": "dependencies", "new_spec": "^4.17.21",
                      "advisories": ["GHSA-a"]}]
    before = report({"Critical": 1, "High": 0}, [f("lodash@4.17.20", "GHSA-a", "Critical", 90)], 1)
    (out / "guardian_report.json").write_text(json.dumps(before))
    sandbox = out / "sandbox"

    def apply(t, o, p, d):
        import shutil
        shutil.copytree(app_dir, sandbox)
        return {"ok": True, "sandbox": str(sandbox), "lockfile_command": "npm install --package-lock-only --ignore-scripts"}
    return out, plan, sandbox, apply


def test_run_verification_end_to_end(tmp_path, app_dir, monkeypatch):
    out, plan, sandbox, apply = _setup(tmp_path, app_dir)
    monkeypatch.setattr(V, "lockfile_problems", lambda app, run=None: [])
    dk = FakeDocker({("sandbox", "install"): (0, "added 4 packages"),
                     ("sandbox", "runtime"): (0, 'GUARDIAN_RUNTIME {"node":"v18","ok":["lodash","mkdirp"],"failed":[]}'),
                     ("demo-app", "install"): (0, "ok"),
                     ("demo-app", "runtime"): (0, 'GUARDIAN_RUNTIME {"node":"v18","ok":["lodash","mkdirp"],"failed":[]}')})
    events = []
    after = report({"Critical": 0, "High": 0}, [], 0)
    r = V.run_verification(app_dir, out, plan, {"FIX-lodash@4.17.20": {"decision": "approved"}}, apply_fixes=apply,
                           rescan_full=lambda sb, orig: after, emit=lambda *a: events.append(a), docker=dk)
    assert r["verdict"] == "verified" and r["fixed"] == 1 and r["total"] == 1
    s = r["steps"]
    assert s["install"]["status"] == "pass" and s["runtime"]["status"] == "pass"
    assert s["tests"]["status"] == "skip"                        # the demo app has no test script
    assert dk.vols == ["sandbox", "demo-app"]                     # fixed code and original both built
    assert (out / "verification.json").exists()
    assert {e[0] for e in events} >= {"prepare", "lockfile", "docker", "install", "runtime", "usage", "rescan"}


def test_build_failure_before_and_after_is_not_blamed_on_fixes(tmp_path, app_dir, monkeypatch):
    out, plan, sandbox, apply = _setup(tmp_path, app_dir)
    monkeypatch.setattr(V, "lockfile_problems", lambda app, run=None: [])
    log = "npm ERR! 404 Not Found - GET https://registry.npmjs.org/expresss - Not found"
    dk = FakeDocker({("sandbox", "install"): (1, log), ("demo-app", "install"): (1, log)})
    r = V.run_verification(app_dir, out, plan, {"FIX-lodash@4.17.20": {"decision": "approved"}}, apply_fixes=apply,
                           rescan_full=lambda sb, orig: report({"Critical": 0}, [], 0), emit=lambda *a: None, docker=dk)
    assert r["steps"]["install"]["status"] == "warn" and "expresss" in r["steps"]["install"]["detail"]
    assert r["verdict"] == "verified" and "install" in r["note"]


def test_no_docker_and_no_approvals(tmp_path, app_dir, monkeypatch):
    out, plan, sandbox, apply = _setup(tmp_path, app_dir)
    r = V.run_verification(app_dir, out, plan, {}, apply_fixes=apply, rescan_full=None, emit=lambda *a: None)
    assert r["verdict"] == "not-run" and "Approve fixes" in r["headline"]
    monkeypatch.setattr(V, "lockfile_problems", lambda app, run=None: [])
    r = V.run_verification(app_dir, out, plan, {"FIX-lodash@4.17.20": {"decision": "approved"}}, apply_fixes=apply,
                           rescan_full=lambda sb, orig: report({"Critical": 0}, [], 0), emit=lambda *a: None,
                           docker=FakeDocker({}, available=False))
    assert r["steps"]["docker"]["status"] == "fail" and r["steps"]["install"]["status"] == "skip"


def test_verify_api(tmp_path, monkeypatch):
    from guardian import server
    out = tmp_path / "output" / "demo"
    out.mkdir(parents=True)
    (out / "guardian_report.json").write_text(json.dumps({"target": {"path": str(tmp_path)}, "remediation": {"fixes": []}}))
    monkeypatch.setattr(server, "OUTPUT", tmp_path / "output")
    c = server.app.test_client()
    st = c.get("/api/report/demo/verify").get_json()
    assert st["result"] is None and [s[0] for s in st["steps"]][0] == "prepare"
    jid = c.post("/api/report/demo/verify").get_json()["job"]
    import time
    for _ in range(50):
        if server.JOBS[jid]["status"] != "running":
            break
        time.sleep(0.05)
    assert server.JOBS[jid]["status"] == "done"
    assert c.get("/api/report/demo/verify").get_json()["result"]["verdict"] == "not-run"


def test_blocked_by_tampered_package_and_copy_counts():
    rep = {"findings": [{"id": "DIFF-ADD-expresss", "category": "suspicious-change", "component": "expresss@1.0.2",
                         "title": "New direct dependency expresss looks like express"}]}
    b = V.blocked_by_findings(["expresss@1.0.2", "lodash@4.17.21"], rep)
    assert b == [{"package": "expresss@1.0.2", "finding": "DIFF-ADD-expresss", "title": "New direct dependency expresss looks like express"}]
    inv = lambda n: [{"name": "minimist", "version": "1.2.0"}] * n
    before = {**report({"Critical": 1}, [f("minimist@1.2.0", "GHSA-3")], 1), "inventory": inv(6)}
    after = {**report({"Critical": 1}, [f("minimist@1.2.0", "GHSA-3")], 1), "inventory": inv(2)}
    fx = [{"id": "FIX-minimist@1.2.0", "package": "minimist", "from_version": "1.2.0", "to_version": "1.2.6",
           "bump": "patch", "advisories": ["GHSA-3"], "bundled_in": ["fsevents", "nyc"]}]
    c = V.compare(before, after, fx)["fixes"][0]
    assert c["status"] == "partly fixed" and c["copies_before"] == 6 and c["copies_left"] == 2


def test_tests_that_run_nothing_are_not_a_pass():
    empty = {"ok": True, "seconds": 0.4, "log": 'Running "mochaTest:unit" (mochaTest) task\nNo files to check...OK\nDone.'}
    r = V._compare_step("tests", {"tests": empty}, {"tests": empty})
    assert r["status"] == "warn" and r["no_tests"]
    real = {"ok": True, "seconds": 3, "log": "  12 passing (40ms)"}
    assert V._compare_step("tests", None, {"tests": real})["status"] == "pass"
    assert not V.ran_no_tests("12 passing\n0 failing")


def test_integrity_algorithm_change_is_not_tampering():
    from guardian.anomalies import integrity_conflict
    assert not integrity_conflict("sha1-AAAA", "sha512-BBBB")                  # regenerated lockfile: not comparable
    assert integrity_conflict("sha512-AAAA", "sha512-BBBB")                    # same algorithm, different content
    assert not integrity_conflict("sha512-AAAA sha1-X", "sha512-AAAA")         # common algorithm agrees
    assert integrity_conflict("sha1-X sha512-AAAA", "sha512-CCCC sha1-X")


def test_prune_overridden_entries(tmp_path):
    from guardian.remediation import prune_overridden
    lock = {"packages": {"": {}, "node_modules/tmp": {"version": "0.2.6"},
                         "node_modules/cypress/node_modules/tmp": {"version": "0.1.0"},
                         "node_modules/cypress/node_modules/tmp/node_modules/os-tmpdir": {"version": "1.0.2"},
                         "node_modules/nyc/node_modules/tmp": {"version": "0.1.0", "inBundle": True}}}
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    n = prune_overridden(p, [{"kind": "override", "package": "tmp", "from_version": "0.1.0"},
                             {"kind": "direct", "package": "tmp", "from_version": "0.2.6"}])
    left = json.loads(p.read_text())["packages"]
    assert n == 1 and "node_modules/cypress/node_modules/tmp" not in left
    assert "node_modules/cypress/node_modules/tmp/node_modules/os-tmpdir" not in left
    assert "node_modules/nyc/node_modules/tmp" in left and "node_modules/tmp" in left   # bundled + other versions kept


def test_explain_lockfile_problems():
    fixes = [{"id": "FIX-tmp@0.1.0", "package": "tmp", "from_version": "0.1.0", "to_version": "0.2.6"}]
    out = V.explain_problems(["invalid: tmp@0.1.0 node_modules/cypress/node_modules/tmp",
                              "missing: left-pad@1.3.0, required by app@1.0.0"], fixes)
    assert out[0]["kind"] == "override-not-applied" and "cypress › tmp is still 0.1.0" in out[0]["text"]
    assert out[1]["kind"] == "missing"


def test_lockfile_problem_is_a_regression_not_a_build_failure():
    v = V.verdict({"lockfile": {"status": "fail"}, "install": {"status": "pass"}}, {"fixes": [{"status": "fixed"}], "introduced": []})
    assert v["verdict"] == "regression"


def test_new_issues_are_attributed_to_the_fix_that_caused_them():
    fx = [{"id": "FIX-fsevents@1.2.9", "package": "fsevents", "from_version": "1.2.9", "to_version": "1.2.11",
           "bump": "patch", "advisories": ["GHSA-f"]}]
    tar = {**f("tar@4.4.13", "GHSA-t", "Critical", 100),
           "dependency_paths": [["app@1.0.0", "nodemon@1.19.1", "fsevents@1.2.11", "node-pre-gyp@0.14.0", "tar@4.4.13"]]}
    before = {**report({"Critical": 1}, [f("fsevents@1.2.9", "GHSA-f")], 1),
              "inventory": [{"name": "fsevents", "version": "1.2.9"}]}
    after = {**report({"Critical": 1}, [tar], 1),
             "inventory": [{"name": "fsevents", "version": "1.2.11"}, {"name": "tar", "version": "4.4.13"}]}
    c = V.compare(before, after, fx)
    assert c["introduced"][0]["via"] == ["FIX-fsevents@1.2.9"] and c["introduced_by_fix"] == {"FIX-fsevents@1.2.9": 1}
    assert c["dependency_changes"]["upgraded"] == 1 and c["dependency_changes"]["added"] == 1
    v = V.verdict({}, c)
    assert v["verdict"] == "new-risk" and "reject FIX-fsevents@1.2.9" in v["headline"]


def test_explain_names_the_parent_that_no_longer_fits():
    fixes = [{"id": "FIX-request@2.36.0", "package": "request", "from_version": "2.36.0", "to_version": "2.68.0"}]
    lock = {"node_modules/zaproxy": {"version": "0.2.0", "dependencies": {"request": "~2.36.0"}},
            "node_modules/zaproxy/node_modules/request": {"version": "2.68.0", "dependencies": {"combined-stream": "~1.0.5"}},
            "node_modules/zaproxy/node_modules/combined-stream": {"version": "0.0.7"}}
    out = V.explain_problems(["invalid: combined-stream@0.0.7 node_modules/zaproxy/node_modules/combined-stream"], fixes, lock)
    assert out[0]["kind"] == "dependency-mismatch" and out[0]["fix"] == "FIX-request@2.36.0"
    assert "zaproxy › request 2.68.0 needs combined-stream ~1.0.5, but 0.0.7 is installed" in out[0]["text"]


def test_remaining_locations_reports_bundles():
    lock = {"node_modules/npm/node_modules/os-locale/node_modules/cross-spawn": {"version": "6.0.5", "inBundle": True},
            "node_modules/cross-spawn": {"version": "6.0.6"},
            "node_modules/a/node_modules/cross-spawn": {"version": "6.0.5"}}
    locs = V.remaining_locations(lock, "cross-spawn", "6.0.5")
    assert locs == [{"where": "a › cross-spawn", "bundled": False, "bundled_by": None},
                    {"where": "npm › os-locale › cross-spawn", "bundled": True, "bundled_by": "npm"}]
