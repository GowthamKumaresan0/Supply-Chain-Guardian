"""Single entry point for every LLM call (Gemini, free tier).

- key + model read from .env (never logged, never written to reports)
- on-disk response cache keyed by sha256(version + params + system + prompt)
- retry with exponential backoff on 429 / 5xx / timeouts / malformed JSON
- model fallback chain: GEMINI_MODEL first, then GEMINI_FALLBACK_MODELS
  (handles retired models (404), overloaded models (503) and per-model rate limits (429))
- hard time budget: every call is cut off at GEMINI_CALL_TIMEOUT (default 45 s) and the whole
  request at GEMINI_TOTAL_TIMEOUT (default 60 s), so a slow or overloaded model can never stall a scan
- returns None on total failure so callers can use their deterministic fallback
- transport: LangChain (langchain-google-genai ChatGoogleGenerativeAI) with SystemMessage,
  native Pydantic structured output (json_schema), thinking-budget control, and token
  usage telemetry; plain REST stays as a fallback transport.
"""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import os
import random
import re
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

DEFAULT_MODEL = "gemini-3.5-flash"
DEFAULT_FALLBACKS = "gemini-3.5-flash,gemini-3.1-flash-lite,gemini-flash-lite-latest"
CALL_TIMEOUT = float(os.getenv("GEMINI_CALL_TIMEOUT", "45"))
TOTAL_TIMEOUT = float(os.getenv("GEMINI_TOTAL_TIMEOUT", "60"))
_POOL = cf.ThreadPoolExecutor(max_workers=4, thread_name_prefix="gemini")
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

try:  # LangChain is the preferred client; REST stays as a fallback transport
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_google_genai import ChatGoogleGenerativeAI
    HAVE_LANGCHAIN = True
except ImportError:  # pragma: no cover
    HAVE_LANGCHAIN = False


def estimate_tokens(text: str) -> int:
    """Fast, offline token estimate (~4 chars/token for English/JSON/structured text)."""
    return max(1, (len(text) + 3) // 4) if text else 0


def _status_code(text: str) -> int | None:
    m = re.search(r"\b(400|401|403|404|429|500|502|503|504)\b", text)
    return int(m.group(1)) if m else None


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        t = t.rsplit("```", 1)[0]
    return t.strip()


def _extract_lc_usage(msg: Any) -> dict[str, int]:
    """Extract token counts from a LangChain AIMessage when available."""
    meta = getattr(msg, "usage_metadata", None)
    if not isinstance(meta, dict):
        return {}
    out_details = meta.get("output_token_details") or {}
    in_tok = int(meta.get("input_tokens") or 0)
    out_tok = int(meta.get("output_tokens") or 0)
    reason_tok = int(out_details.get("reasoning") or 0)
    total_tok = int(meta.get("total_tokens") or (in_tok + out_tok))
    if not (in_tok or out_tok or total_tok):
        return {}
    return {"input_tokens": in_tok, "output_tokens": out_tok,
            "reasoning_tokens": reason_tok, "total_tokens": total_tok}


def _extract_rest_usage(payload: dict) -> dict[str, int]:
    """Extract token counts from a Gemini REST generateContent response."""
    meta = payload.get("usageMetadata") or {}
    if not isinstance(meta, dict) or not meta:
        return {}
    in_tok = int(meta.get("promptTokenCount") or 0)
    out_tok = int(meta.get("candidatesTokenCount") or 0)
    reason_tok = int(meta.get("thoughtsTokenCount") or 0)
    total_tok = int(meta.get("totalTokenCount") or (in_tok + out_tok + reason_tok))
    return {"input_tokens": in_tok, "output_tokens": out_tok,
            "reasoning_tokens": reason_tok, "total_tokens": total_tok}


def _to_dict(obj: Any) -> dict | None:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    return None


def _schema_name(schema: Any) -> str:
    if schema is None:
        return ""
    return getattr(schema, "__name__", type(schema).__name__)


def _schema_json(schema: Any) -> dict | None:
    if schema is None:
        return None
    if isinstance(schema, dict):
        return schema
    if hasattr(schema, "model_json_schema"):
        return schema.model_json_schema()
    return None


class LLM:
    def __init__(self, cache_dir: Path, max_retries: int = 3):
        self.key = os.getenv("GEMINI_API_KEY", "").strip()
        primary = os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_MODEL
        fallbacks = os.getenv("GEMINI_FALLBACK_MODELS", DEFAULT_FALLBACKS).split(",")
        self.models = list(dict.fromkeys([primary] + [m.strip() for m in fallbacks if m.strip()]))
        self.model = primary          # model that actually answered (updated on success)
        self.cache = cache_dir / "llm"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.max_retries = max_retries
        self.call_timeout = CALL_TIMEOUT
        self.total_timeout = TOTAL_TIMEOUT
        self._deadline = float("inf")
        self.calls = {"api": 0, "cache_hits": 0, "failures": 0}
        self.usage = {"input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0,
                      "total_tokens": 0, "estimated_input_tokens": 0}
        self.attempts: list[str] = []  # audit trail: model -> outcome
        self.last_error = ""
        self.backend = "LangChain (langchain-google-genai)" if HAVE_LANGCHAIN else "REST (generativelanguage.googleapis.com)"

    def _redact(self, text: str) -> str:
        return text.replace(self.key, "***") if self.key else text

    def _record_usage(self, usage: dict[str, int]) -> None:
        for k in ("input_tokens", "output_tokens", "reasoning_tokens", "total_tokens"):
            self.usage[k] += int(usage.get(k) or 0)

    def _remaining(self) -> float:
        return self._deadline - time.monotonic()

    def _timed(self, fn, *args):
        """Run one API call with a hard cut-off (the client libraries' own timeouts are not reliable)."""
        limit = min(self.call_timeout, self._remaining())
        if limit <= 1:
            raise TimeoutError("AI time budget used up")
        try:
            return _POOL.submit(fn, *args).result(timeout=limit)
        except cf.TimeoutError:
            raise TimeoutError(f"no answer within {limit:.0f} s") from None

    def _sleep(self, seconds: float) -> bool:
        """Back off before a retry; False when there is no time left for another attempt."""
        if self._remaining() < seconds + 5:
            return False
        time.sleep(seconds)
        return True

    def _thinking_kwargs(self, model: str) -> dict[str, Any]:
        """Minimise hidden reasoning tokens on extractive explanation tasks."""
        raw = os.getenv("GEMINI_THINKING_BUDGET", "").strip()
        if raw:
            try:
                return {"thinking_budget": int(raw)}
            except ValueError:
                pass
        # Explaining already-verified evidence needs minimal internal reasoning; capping it
        # avoids spending 500-2000 invisible thinking tokens per call on Flash models.
        if "gemini-2.5" in model or "gemini-3" in model:
            return {"thinking_budget": 0}
        return {}

    def _build_chat(self, model: str, temperature: float, max_output_tokens: int | None):
        base: dict[str, Any] = dict(
            model=model, google_api_key=self.key, temperature=temperature,
            response_mime_type="application/json", max_retries=0, timeout=self.call_timeout,
        )
        if max_output_tokens:
            base["max_output_tokens"] = max_output_tokens
        extra = self._thinking_kwargs(model)
        if extra:
            try:
                return ChatGoogleGenerativeAI(**base, **extra)
            except Exception:
                pass
        return ChatGoogleGenerativeAI(**base)

    def _build_messages(self, prompt: str, system: str) -> list:
        msgs: list = []
        if system:
            msgs.append(SystemMessage(content=system))
        msgs.append(HumanMessage(content=prompt))
        return msgs

    def _call_langchain(
        self,
        model: str,
        prompt: str,
        temperature: float,
        *,
        system: str = "",
        schema: Any = None,
        max_output_tokens: int | None = None,
    ) -> tuple[dict | None, bool, dict[str, int]]:
        """-> (parsed json | None, try_next_model, usage_dict)"""
        chat = self._build_chat(model, temperature, max_output_tokens)
        structured = None
        if schema is not None and hasattr(chat, "with_structured_output"):
            try:
                structured = chat.with_structured_output(schema, method="json_schema", include_raw=True)
            except Exception:
                structured = None

        messages = self._build_messages(prompt, system)
        delay = 2.0
        for attempt in range(1, self.max_retries + 1):
            try:
                self.calls["api"] += 1
                if structured is not None:
                    res = self._timed(structured.invoke, messages)
                    raw_msg = res.get("raw") if isinstance(res, dict) else None
                    usage = _extract_lc_usage(raw_msg)
                    if isinstance(res, dict) and res.get("parsing_error"):
                        raise ValueError(str(res["parsing_error"]))
                    parsed = res.get("parsed") if isinstance(res, dict) else res
                    data = _to_dict(parsed)
                    if data is None:
                        raise ValueError("structured output returned empty response")
                else:
                    msg = self._timed(chat.invoke, messages)
                    usage = _extract_lc_usage(msg)
                    text = msg.text if isinstance(msg.text, str) else msg.text()
                    data = json.loads(_strip_fences(text))
                    if schema is not None and hasattr(schema, "model_validate"):
                        data = schema.model_validate(data).model_dump()
                self._record_usage(usage)
                self.attempts.append(f"{model}: ok")
                return data, False, usage
            except TimeoutError as e:  # slow or overloaded model: move on, don't wait again
                self.last_error = f"{model}: {e}"
                self.attempts.append(f"{model}: timed out ({e})")
                return None, True, {}
            except ValueError as e:  # malformed JSON or schema validation failure: retry
                self.last_error = f"{model} invalid JSON: {str(e)[:120]}"
            except Exception as e:  # API errors surface as exceptions carrying the HTTP status
                msg_text = self._redact(str(e))
                code = _status_code(msg_text)
                self.last_error = f"{model} {type(e).__name__}: {msg_text[:160]}"
                if code == 404 or "not found" in msg_text.lower():
                    self.attempts.append(f"{model}: not available (404)")
                    return None, True, {}
                if code in (400, 401, 403):
                    self.attempts.append(f"{model}: HTTP {code}")
                    return None, False, {}
                if code == 503:  # overloaded: a lighter fallback model answers sooner than a retry
                    self.attempts.append(f"{model}: overloaded (503)")
                    return None, True, {}
            if attempt < self.max_retries:
                if not self._sleep(delay + random.uniform(0, 1)):
                    break
                delay *= 2
        self.attempts.append(f"{model}: failed after {attempt} attempts")
        return None, True, {}

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    def _call(self, model: str, body: dict) -> tuple[dict | None, bool, dict[str, int]]:
        """-> (parsed json | None, try_next_model, usage_dict)"""
        delay = 2.0
        for attempt in range(1, self.max_retries + 1):
            try:
                self.calls["api"] += 1
                r = self._timed(lambda: requests.post(ENDPOINT.format(model=model), json=body,
                                                      timeout=self.call_timeout, headers={"x-goog-api-key": self.key}))
                if r.status_code == 200:
                    payload = r.json()
                    usage = _extract_rest_usage(payload)
                    parts = payload["candidates"][0]["content"]["parts"]
                    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
                    data = json.loads(_strip_fences(text))
                    self._record_usage(usage)
                    self.attempts.append(f"{model}: ok")
                    return data, False, usage
                self.last_error = f"{model} HTTP {r.status_code}: {r.text[:160]}"
                if r.status_code == 404:
                    self.attempts.append(f"{model}: not available (404)")
                    return None, True, {}
                if r.status_code in (400, 401, 403):
                    self.attempts.append(f"{model}: HTTP {r.status_code}")
                    return None, False, {}  # bad key / request: other models won't help
                if r.status_code == 503:
                    self.attempts.append(f"{model}: overloaded (503)")
                    return None, True, {}
            except TimeoutError as e:
                self.last_error = f"{model}: {e}"
                self.attempts.append(f"{model}: timed out ({e})")
                return None, True, {}
            except (requests.RequestException, KeyError, IndexError, ValueError) as e:
                self.last_error = f"{model} {type(e).__name__}: {str(e)[:160]}"
            if attempt < self.max_retries:
                if not self._sleep(delay + random.uniform(0, 1)):
                    break
                delay *= 2
        self.attempts.append(f"{model}: failed after {attempt} attempts")
        return None, True, {}

    def _cache_key(self, prompt: str, system: str, temperature: float,
                   schema: Any, max_output_tokens: int | None, cache_version: str) -> str:
        # Keep simple plain-prompt calls hashed identically when optional params are unused
        if not (system or schema or max_output_tokens or cache_version) and temperature == 0.2:
            raw = prompt
        else:
            raw = json.dumps({
                "v": cache_version, "t": temperature, "max_out": max_output_tokens,
                "schema": _schema_name(schema), "sys": system, "prompt": prompt,
            }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def generate_json(
        self,
        prompt: str,
        temperature: float = 0.2,
        *,
        system: str = "",
        schema: Any = None,
        max_output_tokens: int | None = None,
        cache_version: str = "",
    ) -> dict | None:
        self.usage["estimated_input_tokens"] += estimate_tokens(system) + estimate_tokens(prompt)
        digest = self._cache_key(prompt, system, temperature, schema, max_output_tokens, cache_version)
        cached = self.cache / f"{digest}.json"
        if cached.exists():
            self.calls["cache_hits"] += 1
            entry = json.loads(cached.read_text(encoding="utf-8"))
            self.model = entry.get("_model", self.model)
            if isinstance(entry.get("_usage"), dict):
                self._record_usage(entry["_usage"])
            self.attempts.append(f"{self.model}: cache hit")
            return entry["response"] if "response" in entry else entry
        if not self.enabled:
            self.last_error = "GEMINI_API_KEY not set"
            return None

        gen_cfg: dict[str, Any] = {"temperature": temperature, "responseMimeType": "application/json"}
        if max_output_tokens:
            gen_cfg["maxOutputTokens"] = max_output_tokens
        js_schema = _schema_json(schema)
        if js_schema:
            gen_cfg["responseJsonSchema"] = js_schema
        body: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": gen_cfg,
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}

        self._deadline = time.monotonic() + self.total_timeout
        for model in self.models:
            if self._remaining() <= 1:
                self.attempts.append(f"{model}: skipped (AI time budget of {self.total_timeout:.0f} s used up)")
                self.last_error = f"no answer within the {self.total_timeout:.0f} s AI time budget"
                break
            if HAVE_LANGCHAIN:
                data, next_model, usage = self._call_langchain(
                    model, prompt, temperature,
                    system=system, schema=schema, max_output_tokens=max_output_tokens,
                )
            else:
                data, next_model, usage = self._call(model, body)
            if data is not None:
                self.model = model
                self.last_error = ""
                cached.write_text(
                    json.dumps({"_model": model, "_usage": usage, "response": data}, indent=2),
                    encoding="utf-8",
                )
                return data
            if not next_model:
                break
        self.calls["failures"] += 1
        return None
