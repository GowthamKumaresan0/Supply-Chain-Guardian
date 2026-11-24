"""Detailed before/after tracking: full lists, expected changes, CSV exports."""
from __future__ import annotations

import csv
import io

from guardian import track as T


def fnd(i, comp, level="High", score=70, cat="vulnerability", vid=None):
    return {"id": i, "category": cat, "component": comp, "title": f"title {i}", "risk_level": level, "risk_score": score,
            "vuln_ids": [vid or i], "scope": "runtime", "evidence": [{"source": "OSV.dev"}]}


def rep(findings, inventory, when="2026-11-24T00:00:00Z"):
    return {"target": {"name": "app", "version": "1.0.0", "path": "/x"}, "generated_at": when, "findings": findings,
            "inventory": inventory, "vulnerability_scan": {"vulnerable_packages": len({f["component"] for f in findings})}}


BEFORE = rep([fnd(f"V{i}", f"pkg{i}@1.0.0") for i in range(200)] + [fnd("K", "keep@1.0.0", "Critical", 95)],
             [{"name": f"pkg{i}", "version": "1.0.0"} for i in range(200)] + [{"name": "keep", "version": "1.0.0"},
                                                                              {"name": "gone", "version": "2.0.0"}])
AFTER = rep([fnd("K", "keep@1.0.0", "Critical", 95), fnd("N", "tar@4.4.13", "Critical", 100),
             {**fnd("DIFF-VER-pkg1@1.0.1", "pkg1@1.0.1", "Critical", 95, "suspicious-change"), "vuln_ids": []}],
            [{"name": f"pkg{i}", "version": "1.0.1"} for i in range(200)] + [{"name": "keep", "version": "1.0.0"},
                                                                             {"name": "tar", "version": "4.4.13"}],
            when="2026-11-24T01:00:00Z")


def test_diff_reports_is_complete_and_excludes_expected_changes():
    d = T.diff_reports(BEFORE, AFTER)
    assert len(d["resolved"]) == 200                          # nothing capped
    assert [f["id"] for f in d["new"]] == ["N"] and len(d["expected"]) == 1
    assert d["levels_after"]["Critical"] == 2                 # keep + tar, not the DIFF finding
    assert len(d["upgraded"]) == 200 and d["added"] == [("tar", ["4.4.13"])] and d["removed"] == [("gone", ["2.0.0"])]


def test_before_after_markdown_sections():
    plan = {"fixes": [{"id": "FIX-pkg1@1.0.0", "package": "pkg1", "from_version": "1.0.0", "to_version": "1.0.1",
                       "bump": "patch", "kind": "override", "advisories": ["V1"]},
                      {"id": "FIX-x@1", "package": "x", "from_version": "1", "to_version": "2", "bump": "major",
                       "kind": "direct", "advisories": ["X"]}], "skipped": [{"package": "evil@0.1.1", "reason": "malware"}]}
    decisions = {"FIX-pkg1@1.0.0": {"decision": "approved", "reviewer": "Asha", "at": "2026-11-24T00:30:00+00:00"},
                 "FIX-x@1": {"decision": "rejected", "reviewer": "Ravi", "comment": "breaks login"}}
    v = {"headline": "Some approved fixes are only partly effective", "fixed": 1, "total": 1,
         "comparison": {"fixes": [{"id": "FIX-pkg1@1.0.0", "fixed": 1, "of": 1, "status": "fixed"}],
                        "introduced": [{"id": "N", "via": ["FIX-pkg1@1.0.0"]}]}}
    md = T.before_after_markdown(BEFORE, AFTER, v, plan, decisions)
    for heading in ("## Summary", "## Approved fixes", "## Fixes not applied", "## Needs a manual fix",
                    "## Resolved by the fixes (200)", "## New after the fixes (1)", "## Still open after the fixes (2)",
                    "### Upgraded (200)", "### Added (1)", "### Removed (1)"):
        assert heading in md, heading
    assert "| Critical | 1 | 2 | ▲ 1 (100%) |" in md
    assert "| `x` | 1 → 2 | major | rejected | Ravi | breaks login |" in md
    assert "| title N | N | pkg1@1.0.0 |" in md and "FIX-pkg1" not in md.split("## New after")[1].split("##")[0]
    assert md.count("title V") >= 200                          # every resolved finding is listed


def test_csv_exports():
    rows = list(csv.DictReader(io.StringIO(T.findings_csv(AFTER))))
    assert rows[1]["component"] == "tar@4.4.13" and rows[1]["risk_level"] == "Critical"
    pk = list(csv.DictReader(io.StringIO(T.packages_csv(AFTER))))
    assert pk[0]["name"] == "keep" and len(pk) == 202
    plan = {"fixes": [{"id": "FIX-a@1", "package": "a", "from_version": "1", "to_version": "2", "bump": "major",
                       "kind": "direct", "advisories": ["X", "Y"]}]}
    fx = list(csv.DictReader(io.StringIO(T.fixes_csv(plan, {"FIX-a@1": {"decision": "approved", "reviewer": "A"}},
                                                     {"comparison": {"fixes": [{"id": "FIX-a@1", "fixed": 1, "of": 2,
                                                                                "status": "partly fixed", "reason": "bundled"}]}}))))
    assert fx[0]["decision"] == "approved" and fx[0]["verified_result"] == "partly fixed" and fx[0]["advisories_fixed"] == "1/2"


def test_resolved_and_new_count_vulnerabilities_like_verify():
    before = rep([fnd("V", "a@1"), {**fnd("HEALTH-x", "b@1", cat="manifest-hygiene"), "vuln_ids": []}], [])
    after = rep([], [])
    d = T.diff_reports(before, after)
    assert [f["id"] for f in d["resolved"]] == ["V"] and [f["id"] for f in d["other_resolved"]] == ["HEALTH-x"]
