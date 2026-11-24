"""Gemini client (LangChain transport), the Flask API, and the end-to-end pipeline."""
from __future__ import annotations

import json

import pytest

from guardian import llm as llm_mod
from guardian.agents.base import AgentFailed


class FakeMsg:
    def __init__(self, text):
        self.text = text


def fake_chat(script):
    """script: model -> list of outcomes (str reply or Exception), consumed in order."""
    class Chat:
        def __init__(self, model, **kw):
            self.model = model
            assert kw["google_api_key"] == "test-key-123"

        def invoke(self, messages):
            out = script[self.model].pop(0)
            if isinstance(out, Exception):
                raise out
            return FakeMsg(out)
    return Chat


@pytest.fixture
def gemini(monkeypatch, tmp_path):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-old")
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "gemini-new")
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    return lambda script: (monkeypatch.setattr(llm_mod, "ChatGoogleGenerativeAI", fake_chat(script)), llm_mod.LLM(tmp_path))[1]


def test_llm_falls_back_to_next_model_and_strips_fences(gemini):
    llm = gemini({"gemini-old": [Exception("404 NOT_FOUND models/gemini-old")],
                  "gemini-new": ['```json\n{"ok": true}\n```']})
    assert llm.backend.startswith("LangChain")
    assert llm.generate_json("hi") == {"ok": True}
    assert llm.model == "gemini-new" and llm.attempts == ["gemini-old: not available (404)", "gemini-new: ok"]
    # second identical prompt is served from the cache
    assert llm.generate_json("hi") == {"ok": True} and llm.calls["cache_hits"] == 1


def test_llm_bad_key_stops_and_never_leaks_key(gemini):
    llm = gemini({"gemini-old": [Exception("401 API key test-key-123 invalid")], "gemini-new": []})
    assert llm.generate_json("x") is None
    assert "test-key-123" not in llm.last_error and "***" in llm.last_error
    assert llm.attempts == ["gemini-old: HTTP 401"]


def test_llm_retries_invalid_json(gemini):
    llm = gemini({"gemini-old": ["not json", '{"a": 1}'], "gemini-new": []})
    assert llm.generate_json("y") == {"a": 1}


def test_llm_tracks_usage_and_supports_system_and_structured_output(monkeypatch, tmp_path):
    from guardian.explain import GuardianExplanation
    seen_calls = []

    class FakeStructured:
        def invoke(self, messages):
            seen_calls.append(("structured", [type(m).__name__ for m in messages]))
            parsed = GuardianExplanation(
                executive_summary="Summary text.",
                findings=[],
                prioritisation_rationale="Fix critical first.",
            )
            raw = type("Raw", (), {"usage_metadata": {
                "input_tokens": 310, "output_tokens": 95, "total_tokens": 405,
                "output_token_details": {"reasoning": 0},
            }})()
            return {"raw": raw, "parsed": parsed, "parsing_error": None}

    class StructuredChat:
        def __init__(self, model, **kw):
            self.model = model
            self.kw = kw

        def with_structured_output(self, schema, method="json_schema", include_raw=False):
            assert schema is GuardianExplanation and method == "json_schema" and include_raw is True
            return FakeStructured()

    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
    monkeypatch.setattr(llm_mod, "ChatGoogleGenerativeAI", StructuredChat)

    llm = llm_mod.LLM(tmp_path)
    out = llm.generate_json("user body", system="sys rules", schema=GuardianExplanation, max_output_tokens=800)
    assert out["executive_summary"] == "Summary text."
    assert seen_calls == [("structured", ["SystemMessage", "HumanMessage"])]
    assert llm.usage["input_tokens"] == 310 and llm.usage["output_tokens"] == 95 and llm.usage["total_tokens"] == 405

    # Cache hit preserves usage telemetry without a second API call
    llm2 = llm_mod.LLM(tmp_path)
    out2 = llm2.generate_json("user body", system="sys rules", schema=GuardianExplanation, max_output_tokens=800)
    assert out2 == out and llm2.calls == {"api": 0, "cache_hits": 1, "failures": 0}
    assert llm2.usage["total_tokens"] == 405


def test_explain_compact_prompt_grounding_and_guardrails(monkeypatch, tmp_path):
    from guardian.explain import (
        LEGACY_PROMPT,
        build_prompt_messages,
        explain,
    )
    from guardian.llm import estimate_tokens
    from guardian.models import Evidence, Finding

    f1 = Finding(
        id="VULN-lodash@4.17.20-GHSA-35jh-r3h4-6jhm",
        category="vulnerability",
        title="Command Injection in lodash",
        severity="HIGH",
        component="lodash@4.17.20",
        scope="runtime",
        location="package-lock.json",
        dependency_paths=[["demo@1.0.0", "lodash@4.17.20"]],
        vuln_ids=["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"],
        cvss=7.2,
        fixed_version="4.17.21",
        changed=True,
        kev=True,
        epss=0.2,
        epss_percentile=0.97,
        risk_score=100,
        risk_level="Critical",
        confidence="High (2 sources)",
        risk_rationale=["base 72 from CVSS 7.2", "+10 runtime", "+15 CISA KEV"],
        evidence=[
            Evidence("OSV.dev", "lodash@4.17.20 affected by GHSA-35jh-r3h4-6jhm", {"direct": True}),
            Evidence("CISA KEV", "CVE-2021-23337 is actively exploited"),
        ],
    )
    ctx = {
        "app": "demo@1.0.0",
        "ecosystem": "npm (Node.js)",
        "deployment": "Node.js application (no Dockerfile detected)",
        "inventory": {"total_components": 50, "direct": 5, "transitive": 45, "runtime": 30, "dev_only": 20, "max_depth": 4},
        "changes_vs_baseline": {"added": [f"pkg-{i}@1.0.0" for i in range(40)], "new_findings": 1},
    }

    sys_msg, user_msg = build_prompt_messages([f1], ctx)
    # New prompt includes deterministic grounding signals that v1 omitted
    assert "CISA KEV" in user_msg and "EPSS 20.0%" in user_msg
    assert "score_why:" in user_msg and "direct=yes" in user_msg and "conf=High (2 sources)" in user_msg
    # Large baseline diff is capped instead of dumping all 40 packages
    assert "(+35 more)" in user_msg and "pkg-39@1.0.0" not in user_msg

    # Verify token reduction against legacy verbose JSON prompt
    legacy_payload = LEGACY_PROMPT.format(
        context=json.dumps(ctx, indent=1),
        findings=json.dumps([{
            "id": f1.id, "category": f1.category, "title": f1.title, "component": f1.component,
            "scope": f1.scope, "location": f1.location, "severity": f1.severity,
            "risk_score": f1.risk_score, "risk_level": f1.risk_level, "changed_vs_baseline": f1.changed,
            "dependency_path": " > ".join(f1.dependency_paths[0]), "advisory_ids": f1.vuln_ids,
            "cvss": f1.cvss, "fixed_version": f1.fixed_version,
            "evidence": [f"[{e.source}] {e.detail}" for e in f1.evidence],
        }], indent=1),
    )
    assert estimate_tokens(sys_msg + user_msg) < estimate_tokens(legacy_payload)

    # Guardrails: evidence_indices mapping, out-of-range rejection, and invented IDs stripped everywhere
    fake_resp = {
        "executive_summary": "App has CVE-2021-23337 and fake CVE-2099-99999.",
        "prioritisation_rationale": "Fix CVE-2021-23337 before fake GHSA-aaaa-bbbb-cccc.",
        "findings": [{
            "id": f1.id,
            "explanation": "lodash has CVE-2021-23337 (also fake MAL-2099-123).",
            "why_it_matters": "Direct runtime dependency.",
            "likely_attack_scenario": "Command injection via template.",
            "risk_reasoning": "KEV + runtime justifies Critical.",
            "evidence_indices": [0, 1, 99],
            "suggested_next_step": "Upgrade lodash to 4.17.21.",
            "ai_confidence": "High",
        }],
    }
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    llm = llm_mod.LLM(tmp_path)
    monkeypatch.setattr(llm, "generate_json", lambda *a, **k: fake_resp)

    st = explain([f1], ctx, llm, top_n=8)
    assert st["mode"] == "llm"
    assert "[unverified ID removed]" in st["executive_summary"] and "CVE-2099-99999" not in st["executive_summary"]
    assert "[unverified ID removed]" in st["prioritisation_rationale"] and "GHSA-aaaa-bbbb-cccc" not in st["prioritisation_rationale"]
    assert f1.ai["evidence_used"] == ["OSV.dev", "CISA KEV"]
    assert f1.ai["evidence_claims_rejected"] == ["ev[99]"]
    assert f1.ai["unverified_ids_removed"] == ["MAL-2099-123"]
    assert f1.ai["source"].startswith("AI inference")

    # Empty findings short-circuits with zero LLM calls
    llm_empty = llm_mod.LLM(tmp_path)
    called = {"n": 0}
    monkeypatch.setattr(llm_empty, "generate_json", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    st_empty = explain([], ctx, llm_empty)
    assert st_empty["mode"] == "skipped" and called["n"] == 0


# ------------------------------------------------------------------ Flask API

@pytest.fixture
def client(monkeypatch, tmp_path):
    from guardian import server
    monkeypatch.setattr(server, "OUTPUT", tmp_path / "output")
    (tmp_path / "output").mkdir()
    server.app.config["TESTING"] = True
    return server.app.test_client()


def test_api_basics(client):
    assert client.get("/").status_code == 200
    steps = [s[0] for s in client.get("/api/presets").get_json()["steps"]]
    assert steps.index("vulns") < steps.index("intel") < steps.index("tamper")
    assert client.post("/api/scan", json={"url": "ftp://nope"}).status_code == 400
    assert client.post("/api/scan", json={"preset": "nope"}).status_code == 400
    assert client.get("/api/report/../etc").status_code in (400, 404)
    assert client.get("/api/report/missing").status_code == 404
    assert client.get("/api/jobs/unknown").status_code == 404


def test_job_error_reports_failed_step(monkeypatch):
    from guardian import server

    def boom(*a, **k):
        raise AgentFailed("Discovery agent", "discover", "Required file not found: package-lock.json.")
    monkeypatch.setattr(server, "clone", lambda url, emit: (server.TARGETS / "x", "abc"))
    monkeypatch.setattr(server, "ensure_lockfile", lambda t, e: "found")
    monkeypatch.setattr(server, "snapshot_dir", lambda slug: server.TARGETS / "no-such-snapshot")
    monkeypatch.setattr(server, "run_scan", boom)
    job = {"events": [], "started": 0}
    server._run_job(job, None, "https://github.com/o/r")
    assert job["status"] == "error" and job["failed_step"] == "discover"
    assert job["error"] == "Required file not found: package-lock.json."


# ------------------------------------------------------------------ end to end

def test_run_scan_end_to_end(app_dir, fake_services, tmp_path):
    from guardian.pipeline import run_scan
    out = tmp_path / "report"
    events = []
    r = run_scan(app_dir, out, None, emit=lambda *a: events.append(a), use_llm=False, use_trivy=False,
                 use_syft=False, meta={"slug": "demo"})
    assert r["agents"]["framework"].startswith("LangGraph") and len(r["agents"]["agents"]) == 6
    assert r["full_graph"]["nodes"] >= 4 and (out / "deptree_graph.json").exists()
    assert r["vulnerability_scan"]["source"] == "OSV.dev + GitHub Advisory DB + deps.dev"
    assert "deptree_graph.json" in {f["name"] for f in r["files"]["outputs"]}
    saved = json.loads((out / "guardian_report.json").read_text())
    top = next(f for f in saved["findings"] if f["id"].endswith("GHSA-35jh-r3h4-6jhm"))
    assert top["kev"] is True and top["epss"] == 0.2
    assert any("CISA" in x for x in top["risk_rationale"])
    assert events[-1][:2] == ("report", "done")
    fixes = {f["package"]: f for f in r["remediation"]["fixes"]}
    assert fixes["lodash"]["kind"] == "direct" and fixes["lodash"]["to_version"] == "4.17.21"
    assert fixes["minimist"]["kind"] == "override" and fixes["minimist"]["to_version"] == "1.2.6"
