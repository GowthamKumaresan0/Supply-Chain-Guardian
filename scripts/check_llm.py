"""Quick health check for the Gemini configuration in .env (never prints the key)."""
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
key = (os.getenv("GEMINI_API_KEY") or "").strip()
model = (os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip()
if not key:
    sys.exit("GEMINI_API_KEY is not set in .env")
print(f"model={model} key_length={len(key)} key_has_spaces_or_quotes={any(c in key for c in ' \"' + chr(39))}")

r = requests.post(
    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    headers={"x-goog-api-key": key},
    json={"contents": [{"parts": [{"text": "Reply with the single word OK"}]}]},
    timeout=60,
)
print("HTTP", r.status_code)
if r.status_code == 200:
    print("reply:", r.json()["candidates"][0]["content"]["parts"][0]["text"].strip())
else:
    print(r.text[:600])
