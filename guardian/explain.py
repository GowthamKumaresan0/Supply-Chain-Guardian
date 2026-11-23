"""[5] AI explanation agent.

Only the top-ranked findings are sent (free-tier budget), in ONE request.
The LLM sees the verified evidence only and must not add facts. Its output is
stored under `finding.ai` and always labelled as AI inference in the report.
Guardrail: any advisory ID the model mentions that is not in the evidence is
stripped and flagged. If the API is unavailable, a deterministic template is used."""
from __future__ import annotations

import json
import re

from .llm import LLM
from .models import Finding

ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|MAL-\d{4}-\d+)\b")

PROMPT = """You are the analysis component of a software supply-chain security tool.
You receive findings that were VERIFIED by deterministic scanners (OSV.dev, Trivy, lockfile diff,
Dockerfile/CI rules). Explain them for a developer audience.

Rules:
- Use ONLY the facts in the evidence. Do not invent CVE/GHSA IDs, versions, exploit details or fixes.
- If something is uncertain, say so explicitly.
- Be concise: 1-3 sentences per field.
- This is Day 1 (detection). The next step suggestion is advisory; a human will approve any change.

Return JSON exactly in this shape:
{{
  "executive_summary": "3-5 sentences: what is in the app, what changed, what looks risky",
  "findings": [
    {{
      "id": "<finding id, copied exactly>",
      "explanation": "what the evidence shows, in plain English",
      "why_it_matters": "impact for THIS application given its scope (runtime/dev/build/ci) and dependency path",
      "likely_attack_scenario": "how an attacker could use it, or 'not applicable'",
      "risk_reasoning": "2-3 sentences justifying (or challenging) the deterministic risk level: weigh severity, scope (does it ship to production?), dependency path, whether it is newly introduced, and fix availability",
      "evidence_used": ["the evidence sources you relied on, copied from the [source] tags, e.g. OSV.dev"],
      "suggested_next_step": "one concrete action for Day 2 remediation",
      "ai_confidence": "High|Medium|Low"
    }}
  ],
  "prioritisation_rationale": "2-3 sentences: which findings to fix first and why"
}}

Application context:
{context}

Findings:
{findings}
"""


def select_top(findings: list[Finding], n: int) -> list[Finding]:
    """Top-n by risk, but make sure each category's best finding is represented."""
    picked: list[Finding] = []
    seen_comp: set[str] = set()

    def take(pred) -> None:
        for f in findings:  # already ranked
            if len(picked) >= n:
                return
            if f.component not in seen_comp and pred(f):
                picked.append(f)
                seen_comp.add(f.component)

    take(lambda f: f.changed and f.risk_score >= 80)          # 1. what changed AND is risky
    seen_cat = {f.category for f in picked}
    for cat in dict.fromkeys(f.category for f in findings):     # 2. best of each other category
        take(lambda f, c=cat: f.category == c and c not in seen_cat and f.risk_score >= 60
             and not any(p.category == c for p in picked))
    take(lambda f: True)                                        # 3. fill by rank
    order = {id(f): i for i, f in enumerate(findings)}
    return sorted(picked[:n], key=lambda f: order[id(f)])


def _compact(f: Finding) -> dict:
    return {
        "id": f.id, "category": f.category, "title": f.title, "component": f.component,
        "scope": f.scope, "location": f.location, "severity": f.severity,
        "risk_score": f.risk_score, "risk_level": f.risk_level,
        "changed_vs_baseline": f.changed,
        "dependency_path": " > ".join(f.dependency_paths[0]) if f.dependency_paths else "",
        "advisory_ids": f.vuln_ids[:4], "cvss": f.cvss, "fixed_version": f.fixed_version,
        "evidence": [f"[{e.source}] {e.detail}" for e in f.evidence],
    }


def _fallback(f: Finding) -> dict:
    path = " > ".join(f.dependency_paths[0]) if f.dependency_paths else f.location
    where = {"runtime": "is shipped in the production image", "dev": "is only used for development/testing",
             "build": "affects how the container image is built", "ci": "runs inside the CI pipeline"}
    step = {
        "vulnerability": f"Upgrade to a fixed version ({f.fixed_version})" if f.fixed_version
        else "No fix published: evaluate replacing or removing the dependency",
        "malicious-package": "Remove the package immediately, rotate any secrets on machines that installed it",
        "suspicious-change": "Revert the change to the trusted baseline and require security review",
        "container": "Pin a supported base image by digest and remove remote script execution",
        "ci-cd": "Pin the action to a full commit SHA and restrict workflow permissions",
        "manifest-hygiene": "Pin exact versions from the npm registry and regenerate the lockfile",
    }.get(f.category, "Review manually")
    return {
        "explanation": f"{f.title}. Evidence: {f.evidence[0].detail if f.evidence else 'n/a'}",
        "why_it_matters": f"The affected component {where.get(f.scope, 'is part of the supply chain')} "
                          f"(path: {path}).",
        "likely_attack_scenario": "See advisory references." if f.vuln_ids else "not assessed (template)",
        "risk_reasoning": "; ".join(f.risk_rationale),
        "evidence_used": [e.source for e in f.evidence],
        "suggested_next_step": step,
        "ai_confidence": "n/a",
    }


def explain(findings: list[Finding], context: dict, llm: LLM, top_n: int = 8) -> dict:
    top = select_top(findings, top_n)
    payload = PROMPT.format(context=json.dumps(context, indent=1),
                            findings=json.dumps([_compact(f) for f in top], indent=1))
    resp = llm.generate_json(payload)
    status = {"mode": "llm" if resp else "fallback", "model": llm.model, "sent_findings": len(top),
              "calls": llm.calls, "error": "" if resp else llm.last_error}

    by_id = {}
    if resp and isinstance(resp.get("findings"), list):
        by_id = {x.get("id"): x for x in resp["findings"] if isinstance(x, dict)}

    for f in top:
        ai = by_id.get(f.id)
        if ai:
            allowed = set(f.vuln_ids)
            text = json.dumps(ai)
            invented = sorted({m for m in ID_RE.findall(text) if m not in allowed})
            for bad in invented:  # hallucination guard
                for k, v in ai.items():
                    if isinstance(v, str):
                        ai[k] = v.replace(bad, "[unverified ID removed]")
            ai.pop("id", None)
            # guardrail 2: evidence the model claims to use must exist on this finding
            real_sources = {e.source for e in f.evidence}
            used = ai.get("evidence_used") if isinstance(ai.get("evidence_used"), list) else []
            ai["evidence_used"] = [u for u in used if any(u in s or s in u for s in real_sources)]
            ai["evidence_claims_rejected"] = [u for u in used if u not in ai["evidence_used"]]
            ai["source"] = f"AI inference ({llm.model})"
            ai["unverified_ids_removed"] = invented
            f.ai = ai
        else:
            fb = _fallback(f)
            fb["source"] = "Deterministic template (LLM unavailable)"
            f.ai = fb

    summary = (resp or {}).get("executive_summary") if resp else None
    if summary:
        invented = sorted({m for m in ID_RE.findall(summary)
                           if m not in {i for f in findings for i in f.vuln_ids}})
        for bad in invented:
            summary = summary.replace(bad, "[unverified ID removed]")
    status["executive_summary"] = summary
    status["prioritisation_rationale"] = (resp or {}).get("prioritisation_rationale") if resp else None
    status["model"] = llm.model
    status["model_attempts"] = llm.attempts
    return status
