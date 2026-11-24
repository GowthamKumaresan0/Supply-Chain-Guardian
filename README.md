# Software Supply Chain Guardian (Team 17)

> **Know what you build. Trust what you ship.**  
> *Autonomous Software Supply Chain Security & Remediation Platform*  
> Developed for the **Amrita × Bosch BGSW Hackathon**.

**Team 17:**  
Avinash Pala (BL.EN.U4AIE23062) · Nandana Thachilath M (CB.SC.U4AIE23151) · SriSomesh (CB.AI.U4AID23141) · Gowtham Kumaresan (CB.AI.U4AID23009) · Vijay Srinivas P (CB.SC.U4AIE23263)

---

## 🌟 Executive Summary

Software Supply Chain Guardian is an intelligent, multi-agent security platform that inspects software dependencies, identifies malicious tampering and known vulnerabilities, plans non-breaking code remediations, and verifies them inside isolated Docker containers.

The platform executes across two foundational stages:
* **Day 1: "Build the Guardian's Eyes"** — Comprehensive inventory discovery, multi-source vulnerability enrichment, baseline anomaly detection, deterministic risk scoring, and explainable AI insights.
* **Day 2: "Build the Guardian's Brain & Shield"** — Intelligent two-tier remediation (safe auto-fixes vs. human approval for major breaking changes), live disk synchronization for VS Code, branch isolation (protecting `main`), and full containerized verification.

---

## 🏗️ System Architecture

```
                          ┌───────────────────────────┐
                          │  Repository / Application │
                          │ (Baseline vs. Target Copy)│
                          └─────────────┬─────────────┘
                                        │
┌───────────────────────────────────────┴───────────────────────────────────────┐
│                           DAY 1: DETECTION & INTEL                            │
├───────────────────────────────────────────────────────────────────────────────┤
│ [1] Discovery Agent        package.json + lockfile -> CycloneDX 1.5 SBOM      │
│ [2] Vulnerability Agent    OSV.dev + GitHub Advisory DB + deps.dev            │
│ [3] Threat Intel Agent     CISA KEV + FIRST EPSS + OpenSSF Scorecards         │
│ [4] Supply-Chain Anomaly   Typosquatting, lifecycle scripts, integrity diffs  │
│ [5] Change Detection       Deep comparison with trusted baseline              │
│ [6] Deterministic Scorer   0-100 Mathematical Risk Score + Rationale          │
│ [7] Responsible LLM        Gemini Flash: Explainable narrative & next steps   │
└───────────────────────────────────────┬───────────────────────────────────────┘
                                        │
┌───────────────────────────────────────┴───────────────────────────────────────┐
│                          DAY 2: REMEDIATION & VERIFY                          │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│               ┌───────────────────┴───────────────────┐                       │
│               ▼                                       ▼                       │
│    [Tier 1: Safe Auto-Fixes]              [Tier 2: Major Breaking Upgrades]   │
│    • Patch & Minor SemVer bumps           • Major SemVer jumps (0.x -> 2.x)   │
│    • Guaranteed backward-compatible       • Potential API deprecation/breaks  │
│    • 85 fixes auto-staged in code         • 40 fixes behind Human Sign-off    │
│    • VS Code White-Themed Diff IDE        • Reviewer Name & Comment audit     │
│               │                                       │                       │
│               └───────────────────┬───────────────────┘                       │
│                                   ▼                                           │
│  [Live Disk Sync]       Real-time manifest sync for original VS Code          │
│  [Branch Protection]    Commit to remediation branch (main strictly safe)     │
│  [Docker Verification]  Isolated build, npm ci (--ignore-scripts),            │
│                         offline runtime require, unit tests, full re-scan     │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Day 1 Scope: "Build the Guardian's Eyes"

| Requirement | Implementation | Output Artifact |
| :--- | :--- | :--- |
| **Manifest & Lockfile Analysis** | Traverses direct and transitive packages with full depth | `guardian/discover.py` |
| **SBOM Generation** | CycloneDX 1.5 JSON spec, cross-checked with Anchore **Syft** | `output/nodegoat/sbom.cdx.json` |
| **Dependency Graph** | NetworkX dependency graph with shortest-path reachability | Interactive Radial & Network View |
| **Container & CI/CD Inspection** | Dockerfile analysis, GitHub Actions audit, and **Trivy** scan of base image | `guardian/container_ci.py` |
| **Known Vulnerabilities** | Batch querying OSV.dev, GitHub Advisory DB, and deps.dev | `guardian/vulns.py` |
| **Supply-Chain Anomalies** | Typosquatting (Levenshtein distance), `postinstall` scripts, checksum shifts | `guardian/anomalies.py` |
| **Deterministic Risk Scoring** | Explainable 0–100 score based on CVSS + context modifiers | `guardian/risk.py` |
| **Responsible AI Insights** | Explains top findings using Gemini Flash without hallucinated IDs | `output/nodegoat/guardian_report.json` |

### 🧮 How Risk Scoring (0–100) Works
Risk scores are **strictly deterministic** (not generated by AI):
$$\text{Risk Score} = \text{Base}(\text{CVSS or Severity}) + \sum(\text{Context Modifiers}) \quad [0 \dots 100]$$

* **Base Score:** CVSS $\times$ 10 (or CRITICAL: 85, HIGH: 65, MEDIUM: 40, LOW: 20).
* **Malicious Package:** Immediate floor of **95** (OpenSSF / OSV malware feeds).
* **Production Scope (`runtime`):** **$+10$** (directly exposed in production container).
* **Dev/Test-Only Scope (`dev`):** **$-25$** (never ships in production image).
* **Active In-The-Wild Exploit (CISA KEV):** **$+15$**.
* **Exploitation Likelihood (EPSS):** **$+10$** for $\ge 50\%$, **$+5$** for $\ge 10\%$, **$-5$** for $<1\%$.
* **Direct Dependency:** **$+5$**.
* **Newly Introduced vs Baseline:** **$+10$**.

---

## 🛡️ Day 2 Scope: "Build the Guardian's Brain & Shield"

### 1. Two-Tier Remediation Policy
Guardian categorizes all 125 proposed fixes using **Semantic Versioning (`MAJOR.MINOR.PATCH`)**:

```
Version:  MAJOR . MINOR . PATCH
           (X)     (Y)     (Z)
```

* **Tier 1: Safe Auto-Remediation (85 Fixes = 29 Patch + 56 Minor)**
  * **Patch (`Z` changes):** Small bug fixes. Zero API changes. (e.g., `minimist: 1.2.0 → 1.2.6`).
  * **Minor (`Y` changes):** Backward-compatible features. (e.g., `bson: 1.0.9 → 1.1.4`).
  * **Behavior:** Auto-applied into code by default. Guaranteed zero breaking changes.
* **Tier 2: Major Human Approval Gate (40 Fixes)**
  * **Major (`X` changes):** Breaking changes, removed methods, altered signatures. (e.g., `set-value: 0.4.3 → 2.0.1`, `mongodb: 2.2.33 → 3.7.4`).
  * **Behavior:** Locked behind human approval. Requires explicit sign-off from an authorized developer or reviewer before entering sandbox or verification builds.

---

### 2. White-Themed VS Code Auto-Remediation IDE
Embedded directly in the web UI (`/#/r/nodegoat/fixes`):
* **Source Control Explorer (Left Sidebar):** Displays `package.json [M]`, lists all 85 safe auto-applied packages, search filter, and individual `[ ⎌ Undo ]` / `[ ↺ Re-apply ]` buttons per package.
* **Split Diff Editor (Right Pane):** VS Code light theme with sticky column headers (`Current Vulnerable Code (HEAD)` vs `Guardian Auto-Fix (Working Tree)`), line numbers, and soft red/green diff highlights.
* **Status Bar:** Displays active branch, status (`85 active / 0 reverted`), `UTF-8`, `JSON`, and `Spaces: 2`.
* **Scroll Preservation:** Retains exact sidebar scroll offset across re-renders and item toggles.

---

### 3. Live Disk Synchronization for Original VS Code
* Unlike tools that only keep changes in memory or a hidden database, Guardian's backend automatically synchronizes active fixes to `targets/nodegoat-modified/package.json` on disk:
  * When safe fixes are loaded, they are written to disk.
  * When a reviewer clicks **Approve** on a major fix, that package is instantly injected into `package.json`.
  * When a reviewer clicks **Undo** or **Reject**, it is instantly removed.
* **Result:** Opening the project in your real VS Code desktop editor immediately displays the updated dependencies and `overrides` block live!

---

### 4. Branch Protection & Safe Git Export
* **Main Branch Protection:** Committing directly to `main` or `master` is blocked by policy.
* **One-Click Export:** The **"🌿 Commit Fixes to Separate Branch"** feature writes changes to disk, creates an isolated branch (e.g., `remediation/nodegoat-safe-fixes`), and commits the changes cleanly.
* **Instant Revert:** A `[ ↩️ Switch back ]` button allows developers to toggle between branches directly from the web interface.

---

### 5. Multi-Stage Docker Verification Engine
Accessible from the **Verify** tab, Guardian tests approved fixes in a clean Docker container:

| Verification Stage | What it Validates |
| :--- | :--- |
| **1. Apply** | Overrides injected into `package.json`, stale lockfile entries pruned. |
| **2. Lockfile Check** | Validates `package-lock.json` via `npm ls` (up to 3 re-resolution rounds). |
| **3. Clean Install** | Runs `npm ci --ignore-scripts` inside an isolated container (no host mount). |
| **4. Offline Runtime Check** | Every production dependency is `require()`'d with **zero network access**. |
| **5. Test Execution** | Executes project test suite (`npm test`) with **zero network access**. |
| **6. Full Re-Scan** | Re-runs the entire agent pipeline to confirm CVEs are eliminated and no regressions introduced. |
| **7. Verdict** | Issues final verdict: **`verified`**, **`partly fixed`**, **`new risk`**, or **`regression`**. |

---

## 🚀 Quickstart & Installation

### Prerequisites
* Python 3.10 or 3.11+
* Git
* Node.js & npm (v18+)
* *(Optional)* Docker Desktop (for containerized verification)
* *(Optional)* Trivy & Syft (`winget install AquaSecurity.Trivy Anchore.Syft` or brew)

### 1. Clone & Install Dependencies
```powershell
git clone https://github.com/GowthamKumaresan0/Supply-Chain-Guardian.git
cd Supply-Chain-Guardian
python -m pip install -r requirements.txt
```

### 2. Configure Environment (Optional Gemini LLM)
Create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

### 3. Launch the Web Application
```powershell
python -m guardian.cli serve --port 8765
```
Open **`http://127.0.0.1:8765`** in your browser.

* Pick **`NodeGoat`** or enter any GitHub repository URL.
* Navigate across tabs: **Journey**, **Vulnerabilities**, **Suspicious Changes**, **Fixes**, and **Verify**.

---

## 🧪 Testing

The repository contains offline unit and integration tests (faking external network calls):
```powershell
python -m unittest discover tests
```
Tests cover:
* SemVer version selection and tie-breaking algorithms
* Multi-source vulnerability enrichment and KEV/EPSS modifiers
* Manifest `overrides` injection and unified diff generation
* Safe auto-remediation filtering and human approval gates
* Docker verification pipeline runner

---

## 📁 Repository Structure

```
Supply-Chain-Guardian/
├── guardian/
│   ├── agents/              # LangGraph multi-agent definitions
│   ├── deptree/             # Multi-ecosystem radial dependency graph
│   ├── web/
│   │   └── app.html         # Single-page web dashboard (Vanilla JS + CSS)
│   ├── anomalies.py         # Typosquatting, checksum, and malicious script detection
│   ├── container_ci.py      # Dockerfile & GitHub Actions security analyzer
│   ├── discover.py          # Lockfile & manifest dependency parser
│   ├── llm.py               # Gemini client with fallback & hallucination guardrails
│   ├── models.py            # Pydantic data models (Finding, Component, SBOM)
│   ├── remediation.py       # Fix planner, SemVer chooser, sandbox patcher
│   ├── risk.py              # Deterministic 0-100 contextual risk scorer
│   ├── server.py            # Flask API backend & live file sync engine
│   ├── verify.py            # Docker build, test, and re-scan orchestrator
│   └── vulns.py             # OSV.dev & GitHub Advisory database query engine
├── output/
│   └── nodegoat/            # Generated reports, SBOMs, sandbox & patches
├── targets/
│   ├── nodegoat-baseline/   # Untouched trusted copy
│   └── nodegoat-modified/   # Application under security review
├── tests/                   # Automated test suite
├── run_app.ps1              # One-click startup script for Windows
├── requirements.txt         # Python package dependencies
└── README.md                # Project documentation
```

---

## 🔒 Responsible AI & Security Principles

1. **Deterministic Ground Truth:** The LLM *never* assigns risk scores or generates code fixes. All scores are mathematically calculated, and all version bumps follow strict SemVer algorithms.
2. **Read-Only Inspection:** Scanning never executes target code or lifecycle scripts (`--ignore-scripts`).
3. **Sandbox Isolation:** All code changes are generated and verified in an isolated sandbox or unprivileged Docker container.
4. **Privacy First:** Only metadata (package names and versions) is analyzed. Proprietary business logic and secrets are never transmitted.

---

*Supply Chain Guardian — Built with pride for Amrita × Bosch BGSW Hackathon.*
