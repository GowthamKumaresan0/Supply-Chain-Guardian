"""List Gemini models available to the key in .env that support generateContent."""
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")
key = os.getenv("GEMINI_API_KEY", "").strip()
url, token = "https://generativelanguage.googleapis.com/v1beta/models", ""
while True:
    r = requests.get(url, headers={"x-goog-api-key": key}, params={"pageSize": 100, "pageToken": token}, timeout=30)
    r.raise_for_status()
    data = r.json()
    for m in data.get("models", []):
        if "generateContent" in m.get("supportedGenerationMethods", []) and "flash" in m["name"]:
            print(m["name"].removeprefix("models/"), "|", m.get("displayName", ""))
    token = data.get("nextPageToken")
    if not token:
        break
