"""Detailed before/after tracking of a remediation: CSV exports and a full BEFORE_AFTER.md.

Used by the publish step (committed next to the code) and by the Verify tab download.
Numbers match the Verify tab: change-detection findings that only exist after the fixes describe the
fixes themselves, so they are listed as expected changes and not counted as risk."""
from __future__ import annotations

import csv
import io

from .remediation import effective_decision, is_selected

LEVELS = ("Critical", "High", "Medium", "Low", "Info")
VULN = ("vulnerability", "malicious-package")


def _sig(f: dict) -> tuple:
    return (f["category"], f["component"], (f.get("vuln_ids") or [f["title"]])[0])


def _csv(header: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


def findings_csv(report: dict) -> str:
    return _csv(["id", "risk_level", "risk_score", "category", "component", "scope", "title", "advisories", "cvss",
                 "fixed_version", "cisa_kev", "epss", "new_vs_baseline", "evidence_sources"],
                [[f["id"], f["risk_level"], f["risk_score"], f["category"], f["component"], f.get("scope", ""), f["title"],
                  " ".join(f.get("vuln_ids") or []), f.get("cvss") if f.get("cvss") is not None else "",
                  f.get("fixed_version", ""), "yes" if f.get("kev") else "", f.get("epss") if f.get("epss") is not None else "",
                  "yes" if f.get("changed") else "", "; ".join(sorted({e["source"] for e in f.get("evidence", [])}))]
                 for f in report.get("findings", [])])


def packages_csv(report: dict) -> str:
    return _csv(["name", "version", "scope", "direct", "depth", "required_by", "install_script", "source", "lockfile_path"],
                [[c["name"], c["version"], c.get("scope", ""), "yes" if c.get("direct") else "", c.get("depth", ""),
                  c.get("parents", ""), "yes" if c.get("install_script") else "", c.get("source", ""), c.get("lock_path", "")]
                 for c in sorted(report.get("inventory", []), key=lambda c: (c["name"], c["version"], c.get("lock_path", "")))])


def fixes_csv(plan: dict, decisions: dict, verification: dict | None) -> str:
    vf = {f["id"]: f for f in ((verification or {}).get("comparison") or {}).get("fixes", []) if f.get("id")}
    rows = []
    for f in plan.get("fixes", []):
        d, v = decisions.get(f["id"]) or {}, vf.get(f["id"]) or {}
        rows.append([f["id"], f["package"], f["from_version"], f["to_version"], f["bump"], f["kind"],
                     " ".join(f.get("advisories", [])), effective_decision(f, decisions), d.get("reviewer", ""), d.get("at", ""),
                     d.get("comment", ""), v.get("status", ""), f"{v['fixed']}/{v['of']}" if v else "", v.get("reason", "")])
    return _csv(["fix", "package", "from", "to", "update", "kind", "advisories", "decision", "reviewer", "decided_at",
                 "comment", "verified_result", "advisories_fixed", "reason"], rows)


def _row(cells) -> str:
    return "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |"


def _versions(r: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for c in r.get("inventory", []):
        out.setdefault(c["name"], set()).add(c["version"])
    return out


def diff_reports(before: dict, after: dict) -> dict:
    """Full (uncapped) before/after comparison."""
    b_sigs = {_sig(f) for f in before["findings"]}
    expected = [f for f in after["findings"] if f["id"].startswith("DIFF-") and _sig(f) not in b_sigs]
    exp_ids = {f["id"] for f in expected}
    after_eff = [f for f in after["findings"] if f["id"] not in exp_ids]
    a_sigs = {_sig(f) for f in after_eff}
    count = lambda fs: {k: sum(1 for f in fs if f["risk_level"] == k) for k in LEVELS}
    bv, av = _versions(before), _versions(after)
    return {
        "levels_before": count(before["findings"]), "levels_after": count(after_eff),
        # same rule as the Verify tab: resolved / new count known vulnerabilities and malware
        "resolved": sorted([f for f in before["findings"] if f["category"] in VULN and _sig(f) not in a_sigs],
                           key=lambda f: -f["risk_score"]),
        "new": sorted([f for f in after_eff if f["category"] in VULN and _sig(f) not in b_sigs], key=lambda f: -f["risk_score"]),
        "other_resolved": sorted([f for f in before["findings"] if f["category"] not in VULN and _sig(f) not in a_sigs],
                                 key=lambda f: -f["risk_score"]),
        "open": sorted(after_eff, key=lambda f: -f["risk_score"]),
        "expected": expected, "findings_before": len(before["findings"]), "findings_after": len(after_eff),
        "components_before": len(before.get("inventory", [])), "components_after": len(after.get("inventory", [])),
        "upgraded": sorted((n, sorted(bv[n]), sorted(av[n])) for n in set(bv) & set(av) if bv[n] != av[n]),
        "added": sorted((n, sorted(av[n])) for n in set(av) - set(bv)),
        "removed": sorted((n, sorted(bv[n])) for n in set(bv) - set(av)),
    }


def _ftable(fs: list[dict], via: dict | None = None, limit: int | None = None) -> list[str]:
    head = ["Risk", "Category", "Component", "Finding", "Advisories"] + (["Came in via"] if via is not None else [])
    lines = [_row(head), _row(["---"] * len(head))]
    for f in fs[:limit] if limit else fs:
        cells = [f"{f['risk_level']} {f['risk_score']}", f["category"], f"`{f['component']}`", f["title"][:110],
                 ", ".join((f.get("vuln_ids") or [])[:3])]
        if via is not None:
            cells.append(", ".join(x.replace("FIX-", "") for x in via.get(f["id"], [])) or "")
        lines.append(_row(cells))
    if limit and len(fs) > limit:
        lines.append(f"\n_{len(fs) - limit} more in the CSV files._")
    return lines


def before_after_markdown(before: dict, after: dict, verification: dict | None, plan: dict, decisions: dict) -> str:
    d = diff_reports(before, after)
    v = verification or {}
    cmp = v.get("comparison") or {}
    via = {f["id"]: f.get("via", []) for f in cmp.get("introduced", []) if f.get("id")}
    vf = {f["id"]: f for f in cmp.get("fixes", []) if f.get("id")}
    t = before["target"]
    eff = {f["id"]: effective_decision(f, decisions) for f in plan.get("fixes", [])}
    dec = lambda fid: eff.get(fid, "pending")
    approved = [f for f in plan.get("fixes", []) if is_selected(f, decisions)]
    others = [f for f in plan.get("fixes", []) if not is_selected(f, decisions)]
    n_auto = sum(1 for f in approved if dec(f["id"]) == "auto-applied")
    pct = lambda b, a: f"{'▼' if a < b else '▲' if a > b else '±'} {abs(a - b)}" + (f" ({round(abs(a - b) * 100 / b)}%)" if b else "")

    out = [f"# Before / after: {t['name']}@{t.get('version', '')}", "",
           f"- Source: {t.get('upstream') or t.get('path')}" + (f" @ `{t['commit']}`" if t.get("commit") else ""),
           f"- Original scan: {before['generated_at']} · re-scan of the fixed code: {after['generated_at']}",
           f"- Verdict: **{v.get('headline', 'not verified')}**" + (f" ({v.get('fixed', 0)} of {v.get('total', 0)} applied fixes confirmed)" if v else ""),
           "", "## Summary", "", _row(["", "Before", "After", "Change"]), _row(["---"] * 4)]
    for k in LEVELS:
        out.append(_row([k, d["levels_before"][k], d["levels_after"][k], pct(d["levels_before"][k], d["levels_after"][k])]))
    vb = before.get("vulnerability_scan", {}).get("vulnerable_packages", 0) or 0
    va = after.get("vulnerability_scan", {}).get("vulnerable_packages", 0) or 0
    out += [_row(["All findings", d["findings_before"], d["findings_after"], pct(d["findings_before"], d["findings_after"])]),
            _row(["Vulnerable packages", vb, va, pct(vb, va)]),
            _row(["Installed components", d["components_before"], d["components_after"], pct(d["components_before"], d["components_after"])]),
            "", f"- Known issues resolved: **{len(d['resolved'])}**",
            f"- New issues after the fixes: **{len(d['new'])}**",
            f"- Expected changes made by the fixes themselves (not counted as risk): {len(d['expected'])}",
            f"- Packages upgraded: {len(d['upgraded'])} · added: {len(d['added'])} · removed: {len(d['removed'])}", ""]

    out += ["## Applied fixes", "",
            f"{len(approved)} fixes went into the fixed code: {len(approved) - n_auto} approved by a reviewer, "
            f"{n_auto} safe patch/minor updates applied automatically.", "",
            _row(["Package", "Change", "Update", "Kind", "Decision", "Advisories fixed", "Result", "Reviewer", "Decided"]),
            _row(["---"] * 9)]
    order = {"not fixed": 0, "partly fixed": 1, "fixed": 2}
    for f in sorted(approved, key=lambda f: (order.get(vf.get(f["id"], {}).get("status"), 3), f["package"])):
        r, dd = vf.get(f["id"], {}), decisions.get(f["id"]) or {}
        out.append(_row([f"`{f['package']}`", f"{f['from_version']} → {f['to_version']}", f["bump"], f["kind"], dec(f["id"]),
                         f"{r['fixed']} / {r['of']}" if r else "", (r.get("status", "") + (f": {r['reason']}" if r.get("reason") else "")),
                         dd.get("reviewer", "") or ("Guardian (automated)" if dec(f["id"]) == "auto-applied" else "-"),
                         (dd.get("at") or "")[:16].replace("T", " ")]))
    if others:
        out += ["", "## Fixes not applied (rejected, undone or pending)", "", _row(["Package", "Change", "Update", "Decision", "Reviewer", "Comment"]),
                _row(["---"] * 6)]
        for f in sorted(others, key=lambda f: (dec(f["id"]), f["package"])):
            dd = decisions.get(f["id"]) or {}
            out.append(_row([f"`{f['package']}`", f"{f['from_version']} → {f['to_version']}", f["bump"], dec(f["id"]),
                             dd.get("reviewer", "") or "-", dd.get("comment", "")]))
    skipped = plan.get("skipped") or []
    if skipped:
        out += ["", "## Needs a manual fix", "", _row(["Package", "Why"]), _row(["---", "---"])]
        out += [_row([f"`{s['package']}`", s["reason"]]) for s in skipped]

    out += ["", f"## Resolved by the fixes ({len(d['resolved'])})", ""] + _ftable(d["resolved"])
    if d["other_resolved"]:
        out += ["", f"## Other findings no longer present ({len(d['other_resolved'])})", "",
                "Supply-chain and hygiene findings (not known vulnerabilities) that disappeared with the fixes.", ""]
        out += _ftable(d["other_resolved"])
    out += ["", f"## New after the fixes ({len(d['new'])})", ""] + (_ftable(d["new"], via) if d["new"] else ["None."])
    out += ["", f"## Still open after the fixes ({len(d['open'])})", ""] + _ftable(d["open"], limit=150)

    out += ["", "## Dependency changes", "", f"### Upgraded ({len(d['upgraded'])})", "", _row(["Package", "Before", "After"]), _row(["---"] * 3)]
    out += [_row([f"`{n}`", ", ".join(b), ", ".join(a)]) for n, b, a in d["upgraded"]]
    out += ["", f"### Added ({len(d['added'])})", ""] + ([", ".join(f"`{n}@{'/'.join(v)}`" for n, v in d["added"])] if d["added"] else ["None."])
    out += ["", f"### Removed ({len(d['removed'])})", ""] + ([", ".join(f"`{n}@{'/'.join(v)}`" for n, v in d["removed"])] if d["removed"] else ["None."])
    out += ["", "## Files", "",
            "- `before/` and `after/`: REPORT.md, findings.csv, packages.csv, the full JSON report, SBOM and dependency graph",
            "- `fixes.csv`: every proposed fix with the decision, reviewer and verified result",
            "- `VERIFICATION.md` / `verification.json`: build, runtime, tests and re-scan checks",
            "- `remediation.patch`: the exact package.json and lockfile change"]
    return "\n".join(out) + "\n"
