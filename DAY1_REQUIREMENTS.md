# Day 1 – What I Need From You Before We Start

Fill in each **Your answer** line (or tick the box), save the file, and tell me "done".

---

## 1. Target application
We need a free, open-source app from a public repo with a realistic dependency tree,
ideally containing `package-lock.json`, a `Dockerfile`, and `.github/workflows/`.

- [ ] **OWASP NodeGoat** (recommended – Node.js, old deps with real CVEs, Dockerfile, small & fast)
- [ ] **OWASP Juice Shop** (bigger, more impressive, slower to work with)
- [ ] Other (give GitHub URL): ______________________

**Your answer:**

---

## 2. LLM for the AI explanation layer
Which provider will we use?

- [ ] Claude (Anthropic)
- [ ] OpenAI
- [ ] Gemini
- [ ] Local (Ollama) – model name: __________
- [ ] No key yet – build with a fallback, plug the key in later

> ⚠️ **Do NOT paste the API key into this file or the chat.**
> Create a file `d:\Hackhaton\.env` yourself with a line like:
> `ANTHROPIC_API_KEY=your-key-here` (or `OPENAI_API_KEY=...` / `GEMINI_API_KEY=...`)

**Your answer:**

---

## 3. Permission to install tools
Currently installed: Python 3.14, Node 24. **Missing:** git, Docker, Syft/Trivy.

| Tool | Purpose | Allow install? (yes/no) |
|---|---|---|
| git | Clone the target repo, diff baseline vs modified | |
| Trivy *(optional)* | Cross-check SBOM & vulnerabilities, scan Dockerfile | |
| Syft *(optional)* | Alternative SBOM generator | |
| Python packages: `requests`, `networkx`, `cyclonedx-python-lib`, `python-dotenv`, LLM SDK | Core of the Guardian | |

If git is not allowed, I will download the repo as a ZIP instead.

---

## 4. Docker
Docker is **not installed**. For Day 1 my plan is to **statically analyse the Dockerfile and CI workflows**
(this meets "inspect at least one container image or CI/CD workflow").
Day 2 (build & test the fix) will most likely need Docker.

- [ ] Static Dockerfile analysis is fine for Day 1
- [ ] I will install Docker Desktop now

**Your answer:**

---

## 5. Report / dashboard format

- [ ] Static HTML report (fastest, recommended for the 4-hour window)
- [ ] Streamlit interactive dashboard (~20 min extra)

**Your answer:**

---

## 6. Team / submission details (optional, for README)

- Team name: ______________________
- Project folder: `d:\Hackhaton` (change? ______________)
- Any rules from organisers not in the PDF (e.g. required language, submission format)?
  ______________________

---

## 7. Plan approval

- [ ] I have read the Day 1 plan (Discover → SBOM/Graph → Vulnerabilities → Suspicious changes → AI explanation → Report) and the 4-hour timeline, and I approve it.

**Changes you want to the plan (if any):**
