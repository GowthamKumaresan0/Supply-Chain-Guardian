"""[5] AI explanation agent.

Only the top-ranked findings are sent (free-tier budget), in ONE structured LangChain call.
The LLM sees verified evidence only and must not add facts. Its output is stored under
`finding.ai` and always labelled as AI inference in the report.

Prompting & token-efficiency design (v2):
- Role-separated SystemMessage (static rules + compact category rubric, cacheable) and
  HumanMessage (compact key-value records, omitting empty/default fields).
- Native Pydantic structured output (`GuardianExplanation`) so the API enforces exact JSON
  shape without pasting a bulky schema template into the prompt text.
- Evidence source indexing (`[0]`, `[1]`, ...) so the model returns integer indices instead
  of repeating long source names, mapped back deterministically with zero false rejections.
- Rich deterministic grounding: includes risk_rationale, CISA KEV / FIRST EPSS, confidence,
  and directness so the LLM explains real risk signals instead of guessing.
- Guardrails strip invented advisory IDs across findings, executive_summary, AND
  prioritisation_rationale, and reject unsupported evidence references.
"""
from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field

from .llm import LLM, estimate_tokens
from .models import Finding

PROMPT_VERSION = "explain-v2-compact-structured"
ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+)\b")
MAX_EVIDENCE_CHARS = 220

try:
    from langchain_core.prompts import ChatPromptTemplate
    HAVE_PROMPT_TEMPLATE = True
except ImportError:  # pragma: no cover
    HAVE_PROMPT_TEMPLATE = False


class FindingExplanation(BaseModel):
    id: str = Field(description="Exact finding id copied from input.")
    explanation: str = Field(description="1 sentence: what verified evidence shows, plain English.")
    why_it_matters: str = Field(description="1-2 sentences: impact in THIS app (scope, path, directness); do not repeat explanation.")
    likely_attack_scenario: str = Field(description="1-2 sentences: concrete exploit path, or 'Not applicable'.")
    risk_reasoning: str = Field(description="1-2 sentences: evaluate deterministic score & rationale (KEV/EPSS, corroboration, scope, baseline change, fix).")
    evidence_indices: list[int] = Field(default_factory=list, description="0-based [i] indices of this finding's ev lines relied on.")
    suggested_next_step: str = Field(description="1 concrete imperative remediation action for human review.")
    ai_confidence: Literal["High", "Medium", "Low"] = Field(description="Confidence based strictly on provided evidence.")


class GuardianExplanation(BaseModel):
    executive_summary: str = Field(description="3-4 sentences: app inventory, key baseline changes, and top risks.")
    findings: list[FindingExplanation] = Field(description="One entry per input finding, in input order.")
    prioritisation_rationale: str = Field(description="2 sentences: which findings to fix first and why.")


SYSTEM_PROMPT = """Role: Software Supply Chain Guardian analyst explaining VERIFIED scanner findings to developers.
Rules:
- Ground every claim strictly in the input; never invent CVE/GHSA/MAL IDs, versions, exploits, or fixes. State uncertainty explicitly.
- Day 1 detection only: remediation steps are advisory and require human approval.
- Keep fields tight and non-overlapping (never repeat facts across explanation, why_it_matters, and risk_reasoning); cite evidence via 0-based `evidence_indices` from each finding's `ev` list.
Category focus:
- malicious-package: assume active compromise; advise immediate removal & credential rotation.
- suspicious-change: name the tampering signal (typosquat/hash mismatch/install script/non-registry URL); advise baseline revert & audit.
- vulnerability: cite exact ID, KEV/EPSS urgency, and fix (direct bump vs transitive override) or mitigation if unfixed.
- container: tie EOL/root/remote-script to image build or runtime; advise digest pinning & non-root USER.
- ci-cd: explain workflow token/secret exposure; advise 40-char SHA pinning & least-privilege permissions."""

USER_PROMPT_TEMPLATE = """Context:
{context}

Findings (top {count}, ranked):
{findings}"""

# Legacy template kept ONLY so scripts/benchmark_prompting.py can compare v1 vs v2.
LEGACY_PROMPT = """You are the analysis component of a software supply-chain security tool.
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
    """Top-n by risk, ensuring each category's strongest finding is represented."""
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


def _trim(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    t = " ".join((text or "").split())
    return t if len(t) <= limit else t[: limit - 1].rstrip() + "…"


def _is_direct(f: Finding) -> bool:
    return any(bool(e.data.get("direct")) for e in f.evidence if isinstance(e.data, dict))


def _exploit_signal(f: Finding) -> str:
    parts: list[str] = []
    if f.kev:
        parts.append("CISA KEV")
    if f.epss is not None:
        pct = f" p{round(f.epss_percentile * 100)}" if f.epss_percentile is not None else ""
        parts.append(f"EPSS {f.epss:.1%}{pct}")
    return ", ".join(parts)


def _compact(f: Finding) -> dict:
    """Compact, high-signal dict omitting empty/default values and adding deterministic rationale."""
    d: dict = {
        "id": f.id,
        "cat": f.category,
        "title": f.title,
        "comp": f.component,
        "scope": f.scope,
        "loc": f.location,
        "sev": f.severity,
        "risk": f"{f.risk_score} ({f.risk_level})",
    }
    if f.confidence:
        d["conf"] = f.confidence
    if _is_direct(f):
        d["direct"] = True
    if f.changed:
        d["new_vs_baseline"] = True
    if f.dependency_paths:
        d["path"] = " > ".join(f.dependency_paths[0])
    if f.vuln_ids:
        d["ids"] = f.vuln_ids[:4]
    if f.cvss is not None:
        d["cvss"] = f.cvss
    exploit = _exploit_signal(f)
    if exploit:
        d["exploit"] = exploit
    if f.fixed_version:
        d["fix"] = f.fixed_version
    if f.risk_rationale:
        d["rationale"] = "; ".join(f.risk_rationale)
    if f.evidence:
        d["ev"] = [f"[{i}|{e.source}] {_trim(e.detail)}" for i, e in enumerate(f.evidence)]
    return d


def _format_finding_block(f: Finding) -> str:
    """Token-efficient structured text block for one finding (far fewer tokens than indented JSON)."""
    d = _compact(f)
    header_parts = [f"id={d['id']}", f"cat={d['cat']}", f"risk={d['risk']}", f"sev={d['sev']}", f"scope={d['scope']}"]
    if d.get("conf"):
        header_parts.append(f"conf={d['conf']}")
    if d.get("direct"):
        header_parts.append("direct=yes")
    if d.get("new_vs_baseline"):
        header_parts.append("new=yes")
    lines = [" | ".join(header_parts), f"  title: {d['title']} | comp: {d['comp']} ({d['loc']})"]
    meta: list[str] = []
    if d.get("ids"):
        meta.append(f"ids={','.join(d['ids'])}")
    if "cvss" in d:
        meta.append(f"cvss={d['cvss']}")
    if d.get("exploit"):
        meta.append(f"exploit={d['exploit']}")
    if d.get("fix"):
        meta.append(f"fix={d['fix']}")
    if meta:
        lines.append("  " + " | ".join(meta))
    if d.get("path"):
        lines.append(f"  path: {d['path']}")
    if d.get("rationale"):
        lines.append(f"  score_why: {d['rationale']}")
    if d.get("ev"):
        lines.append("  ev: " + " ; ".join(d["ev"]))
    return "\n".join(lines)


def _summarize_changes(changes: dict) -> str:
    """Cap baseline diff lists so large diffs never blow up prompt tokens."""
    if not changes:
        return "none (no baseline)"
    parts: list[str] = []
    if changes.get("new_findings") is not None:
        parts.append(f"new_findings={changes['new_findings']}")
    for key in ("added", "removed", "version_changed", "integrity_changed",
                "source_changed", "scripts_changed", "new_images", "new_workflows"):
        vals = changes.get(key)
        if isinstance(vals, list) and vals:
            sample = ", ".join(str(v) for v in vals[:5])
            more = f" (+{len(vals) - 5} more)" if len(vals) > 5 else ""
            parts.append(f"{key}({len(vals)}): {sample}{more}")
    return "; ".join(parts) if parts else "no changes detected"


def _format_context(context: dict) -> str:
    inv = context.get("inventory") or {}
    lines = [f"app: {context.get('app', 'unknown')} | ecosystem: {context.get('ecosystem', 'npm')}"]
    if context.get("deployment"):
        lines.append(f"deployment: {context['deployment']}")
    if inv:
        inv_parts = [
            f"total={inv.get('total_components', 0)}",
            f"direct={inv.get('direct', 0)}",
            f"transitive={inv.get('transitive', 0)}",
            f"runtime={inv.get('runtime', 0)}",
            f"dev={inv.get('dev_only', 0)}",
            f"max_depth={inv.get('max_depth', 0)}",
        ]
        if inv.get("with_install_scripts"):
            inv_parts.append(f"install_scripts={inv['with_install_scripts']}")
        lines.append("inventory: " + ", ".join(inv_parts))
    lines.append(f"baseline_diff: {_summarize_changes(context.get('changes_vs_baseline') or {})}")
    return "\n".join(lines)


def build_prompt_messages(top: list[Finding], context: dict) -> tuple[str, str]:
    """Render (system_prompt, user_prompt) using LangChain ChatPromptTemplate when available."""
    ctx_text = _format_context(context)
    findings_text = "\n".join(_format_finding_block(f) for f in top)
    if HAVE_PROMPT_TEMPLATE:
        tmpl = ChatPromptTemplate.from_messages([
            ("system", "{sys}"),
            ("human", USER_PROMPT_TEMPLATE),
        ])
        msgs = tmpl.format_messages(sys=SYSTEM_PROMPT, context=ctx_text, count=len(top), findings=findings_text)
        return str(msgs[0].content), str(msgs[1].content)
    return SYSTEM_PROMPT, USER_PROMPT_TEMPLATE.format(context=ctx_text, count=len(top), findings=findings_text)


def _strip_unverified_ids(text: str, allowed: set[str]) -> tuple[str, list[str]]:
    invented = sorted({m for m in ID_RE.findall(text or "") if m not in allowed})
    cleaned = text
    for bad in invented:
        cleaned = cleaned.replace(bad, "[unverified ID removed]")
    return cleaned, invented


def _resolve_evidence_used(ai: dict, f: Finding) -> tuple[list[str], list[str]]:
    """Map evidence_indices (preferred) or legacy evidence_used strings against real finding sources."""
    sources = [e.source for e in f.evidence]
    real_set = set(sources)

    indices = ai.pop("evidence_indices", None)
    if isinstance(indices, list) and (indices or not ai.get("evidence_used")):
        used: list[str] = []
        rejected: list[str] = []
        for idx in indices:
            if isinstance(idx, int) and 0 <= idx < len(sources):
                if sources[idx] not in used:
                    used.append(sources[idx])
            else:
                rejected.append(f"ev[{idx}]")
        return used, rejected

    raw = ai.get("evidence_used") if isinstance(ai.get("evidence_used"), list) else []
    used = [u for u in raw if isinstance(u, str) and any(u in s or s in u for s in real_set)]
    rejected = [str(u) for u in raw if u not in used]
    return used, rejected


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
    if not top:
        return {
            "mode": "skipped", "model": llm.model, "sent_findings": 0, "calls": llm.calls,
            "error": "", "executive_summary": "No security or supply-chain findings were detected.",
            "prioritisation_rationale": None, "model_attempts": list(llm.attempts),
            "token_usage": dict(llm.usage), "prompt_version": PROMPT_VERSION,
        }

    system_msg, user_msg = build_prompt_messages(top, context)
    max_out = min(4096, 450 + len(top) * 260)
    resp = llm.generate_json(
        user_msg,
        system=system_msg,
        schema=GuardianExplanation,
        max_output_tokens=max_out,
        cache_version=PROMPT_VERSION,
    )
    status: dict = {
        "mode": "llm" if resp else "fallback",
        "model": llm.model,
        "sent_findings": len(top),
        "calls": llm.calls,
        "error": "" if resp else llm.last_error,
        "prompt_version": PROMPT_VERSION,
        "prompt_tokens_est": estimate_tokens(system_msg) + estimate_tokens(user_msg),
        "token_usage": dict(llm.usage),
    }

    by_id: dict[str, dict] = {}
    if resp and isinstance(resp.get("findings"), list):
        by_id = {x.get("id"): dict(x) for x in resp["findings"] if isinstance(x, dict) and x.get("id")}

    for f in top:
        ai = by_id.get(f.id)
        if ai:
            allowed = set(f.vuln_ids)
            text = json.dumps(ai)
            invented = sorted({m for m in ID_RE.findall(text) if m not in allowed})
            for bad in invented:  # guardrail 1: hallucinated advisory IDs
                for k, v in ai.items():
                    if isinstance(v, str):
                        ai[k] = v.replace(bad, "[unverified ID removed]")
            ai.pop("id", None)
            # guardrail 2: evidence the model claims to use must exist on this finding
            used, rejected = _resolve_evidence_used(ai, f)
            ai["evidence_used"] = used
            ai["evidence_claims_rejected"] = rejected
            ai["source"] = f"AI inference ({llm.model})"
            ai["unverified_ids_removed"] = invented
            f.ai = ai
        else:
            fb = _fallback(f)
            fb["source"] = "Deterministic template (LLM unavailable)"
            f.ai = fb

    all_allowed_ids = {i for f in findings for i in f.vuln_ids}
    summary = (resp or {}).get("executive_summary") if resp else None
    if isinstance(summary, str) and summary:
        summary, _ = _strip_unverified_ids(summary, all_allowed_ids)
    rationale = (resp or {}).get("prioritisation_rationale") if resp else None
    if isinstance(rationale, str) and rationale:
        rationale, _ = _strip_unverified_ids(rationale, all_allowed_ids)

    status["executive_summary"] = summary
    status["prioritisation_rationale"] = rationale
    status["model"] = llm.model
    status["model_attempts"] = list(llm.attempts)
    return status
