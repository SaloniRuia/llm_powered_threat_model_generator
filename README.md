# 🔐 LLM-Powered Threat Model Auto-Generator

> **Paste a GitHub URL. Get a professional, code-grounded threat model in under 60 seconds.**

A fully automated application security pipeline that reads your actual codebase, applies STRIDE methodology per component, scores every threat with a CVSS-inspired formula, and generates actionable mitigations mapped to OWASP and NIST controls — all driven by GPT-4o and Claude Sonnet.

---

## Why This Exists

Threat modeling is one of the highest-value practices in AppSec — and one of the most consistently skipped.

A proper threat model for a mid-complexity system costs a senior AppSec engineer **2–3 days**. Most engineering teams ship without one. Existing tools like Microsoft Threat Modeling Tool and IriusRisk require manual diagram input and produce generic, templated outputs. They don't read your actual code, so their output rarely reflects reality.

**This pipeline fixes that.** It reads your code, reasons over it, and produces a threat model that cites the actual files, functions, and behaviors that create each risk.

---

## Demo

```
Input  → github.com/tiangolo/fastapi
Output → 34 threats identified
         CRITICAL: 3  HIGH: 11  MEDIUM: 14  LOW: 6
         22 mitigations generated (OWASP + NIST mapped)
         Time: 47.3 seconds
```

---

## Notebooks

The project is structured as 7 modular Kaggle/Jupyter notebooks. Each notebook handles one stage of the pipeline and can be run independently or chained end-to-end.

```
NB01_Ingestion.ipynb              ← Fetch repo from GitHub API
NB02_Component_Extraction.ipynb   ← Extract architecture (GPT-4o)
NB03_STRIDE_Analysis.ipynb        ← Per-component STRIDE (Claude Sonnet)
NB04_Scoring.ipynb                ← CVSS-like threat scoring
NB05_Mitigation_Report.ipynb      ← OWASP/NIST mitigations + Markdown report
NB06_E2E_Runner.ipynb             ← Full pipeline in one notebook (demo-ready)
NB07_Ablation_Experiments.ipynb   ← 4 experiments measuring component contribution
```

---

## Pipeline Architecture

```
GitHub Repo URL
      │
      ▼
┌─────────────────────────────────────────────────┐
│  NB-01  INGESTION                               │
│  • GitHub Trees API → priority file scoring     │
│  • Fetch file contents (capped per extension)   │
│  • OpenAPI / Swagger spec detection & parsing   │
│  • Output: repo_surface.json                    │
└──────────────────────────┬──────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────┐
│  NB-02  COMPONENT EXTRACTION  [GPT-4o]          │
│  • Token-budgeted code context packing          │
│  • Extract: components, data flows,             │
│    trust boundaries, external actors            │
│  • Validation: all components cite source files │
│  • Output: components.json                      │
└──────────────────────────┬──────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────┐
│  NB-03  STRIDE ANALYSIS  [Claude Sonnet]        │
│  • One LLM call per component (no context       │
│    collapse; deep per-component reasoning)      │
│  • 6 STRIDE categories × N components          │
│  • Every threat must cite file/function         │
│  • Hallucination rate measured at output        │
│  • Output: threats.json                         │
└──────────────────────────┬──────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────┐
│  NB-04  CVSS-LIKE SCORING  [deterministic]      │
│  • Attack Vector inference (Network/Local)      │
│  • Attack Complexity inference                  │
│  • Impact scores per STRIDE category            │
│  • Severity: CRITICAL / HIGH / MEDIUM / LOW     │
│  • Output: scored_threats.json                  │
└──────────────────────────┬──────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────┐
│  NB-05  MITIGATION + REPORT  [Claude Sonnet]    │
│  • Batched mitigation generation (5 per call)   │
│  • OWASP Top 10 + NIST SP 800-53 mapping        │
│  • Markdown report assembly                     │
│  • Output: threat_model_report.md               │
└─────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **LLM — Extraction** | GPT-4o | Structured JSON component extraction from code |
| **LLM — Security** | Claude claude-sonnet-4-6 | STRIDE analysis + mitigation generation |
| **Repo Ingestion** | GitHub REST API | Tree fetch + priority file retrieval |
| **Spec Parsing** | PyYAML / json | OpenAPI / Swagger spec parsing |
| **Token Management** | tiktoken | Context window budgeting |
| **Scoring** | Pure Python | Deterministic CVSS-inspired formula |
| **Output** | Markdown | Professional threat model report |
| **Environment** | Kaggle / Jupyter | `.ipynb` notebooks, Python 3.10+ |

**Why two LLMs?** GPT-4o is used for component extraction because its structured JSON output mode is reliable for schema-constrained tasks. Claude Sonnet is used for STRIDE and mitigations because it produces more nuanced, evidence-grounded security reasoning. Each model does what it does best.

---

## STRIDE Framework

Every threat is categorized using STRIDE — the industry-standard Microsoft threat modeling methodology:

| Category | What It Catches |
|----------|----------------|
| **S** — Spoofing | Attackers impersonating users, services, or components |
| **T** — Tampering | Unauthorized modification of data in transit or at rest |
| **R** — Repudiation | Malicious actions that can be denied or go unlogged |
| **I** — Information Disclosure | Sensitive data exposure to unauthorized parties |
| **D** — Denial of Service | Availability disruption of components or services |
| **E** — Elevation of Privilege | Gaining permissions beyond what is authorized |

---

## Scoring Model

Threats are scored using a simplified CVSS-inspired formula with four inferred axes:

```
Score = min( (6.42 × ISS) + (8.22 × AV × AC × E), 10.0 )

where:
  ISS = 1 - (1 - Confidentiality)(1 - Integrity)(1 - Availability)
  AV  = Attack Vector     [Network=0.85, Adjacent=0.62, Local=0.55]
  AC  = Attack Complexity [Low=0.77, High=0.44]
  E   = Exploitability    [Functional=0.97, PoC=0.94, Theoretical=0.91]
```

Impact sub-scores (C/I/A) are assigned per STRIDE category based on the standard CVSS STRIDE mapping. All axes are inferred from the threat description — no manual input required.

| Score | Severity |
|-------|----------|
| 9.0 – 10.0 | 🔴 CRITICAL |
| 7.0 – 8.9 | 🟠 HIGH |
| 4.0 – 6.9 | 🟡 MEDIUM |
| 0.0 – 3.9 | 🟢 LOW |

---

## Ablation Experiments (NB-07)

NB-07 measures the contribution of each pipeline component through four controlled experiments:

### Exp A — No Code Context (Baseline)
Runs STRIDE with only a natural language description of the repo. No source files, no OpenAPI spec.

**Hypothesis:** Hallucination rate spikes. Threats become generic ("SQL injection is possible") with no file citations.

### Exp B — OpenAPI Ablation
Compares full context (code + OpenAPI spec) vs code-only.

**Hypothesis:** Removing the spec reduces API-surface threat coverage — endpoint-specific threats like missing auth on specific routes won't appear.

### Exp C — Single-Step vs Multi-Step Chain
Single mega-prompt ("analyze this codebase and list all threats") vs the two-step chain (extract components → per-component STRIDE).

**Hypothesis:** Chaining significantly reduces hallucination rate. When the model focuses on one component at a time, it produces more specific, evidence-backed threats.

### Exp D — GPT-4o vs Claude Sonnet
Identical prompt, same code context, both models run independently.

**Hypothesis:** Different STRIDE category distributions — models have different blind spots. Claude tends toward thorough I (Information Disclosure) coverage; GPT-4o catches more E (Elevation of Privilege) patterns.

**Primary metric across all experiments:** `Hallucination Rate = threats without a valid file citation / total threats`

---

## Setup

### Kaggle (recommended)

1. Upload all `.ipynb` files to a new Kaggle notebook session
2. Add secrets in **Add-ons → Secrets**:
   - `OPENAI_API_KEY`
   - `ANTHROPIC_API_KEY`
   - `GITHUB_TOKEN` *(optional but recommended — avoids rate limits)*
3. Run notebooks in order: NB-01 → NB-02 → ... → NB-05
4. Or run NB-06 alone for the full end-to-end demo

### Local

```bash
pip install openai anthropic tiktoken requests PyYAML nbformat

export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GITHUB_TOKEN="ghp_..."   # optional

jupyter notebook
```

Run notebooks in sequence. Each one reads the output JSON of the previous step.

---

## Output Format

The final report (`threat_model_report.md`) is structured as:

```markdown
# Threat Model Report
> Generated: 2025-03-29 | STRIDE | CVSS-inspired scoring

## Executive Summary
| Severity | Count |
...

## Findings

### 1. 🔴 [CRITICAL] Unauthenticated Admin Endpoint Exposure
**Component:** API Router | **STRIDE:** E | **Score:** 9.2/10

**Description:** The /admin/users endpoint in routers/admin.py accepts
requests without validating the Authorization header...

**Evidence:** `routers/admin.py:47`

**Mitigations:**
- Add OAuth2 bearer token validation middleware to all /admin/* routes
- Implement role-based access control (RBAC) using FastAPI's Depends()
- Add request logging and alerting for all admin endpoint access

**Controls:** A01:2021, A07:2021, AC-2, AC-3
```

Every finding includes: severity score, STRIDE category, the specific file/function that creates the risk, and concrete mitigations with OWASP + NIST references.

---

## Key Design Decisions

**One LLM call per component (NB-03)**
Running STRIDE analysis for all components in a single prompt causes context collapse — the model loses track of component-specific details and produces generic threats. Splitting into one call per component is slower but dramatically improves grounding and specificity.

**No LangChain dependency**
The multi-step chain is implemented directly via sequential API calls. This keeps the Kaggle environment lightweight, eliminates version conflicts, and makes the pipeline easier to debug step by step.

**Hallucination guard**
Every STRIDE prompt instructs the model that threats without a specific file or function citation will be considered hallucinated. NB-03 measures the hallucination rate at output so you can see how well the model stayed grounded.

**Token budgeting before LLM calls**
NB-02 uses tiktoken to pack as many priority files as possible within a fixed token budget before sending to GPT-4o. This prevents context window errors on large repos and ensures the most security-relevant files are always included.

---

## Limitations

- **Private repos** require a GitHub token with appropriate scopes
- **Very large repos** (>500 files) will only analyze the top priority files — full coverage requires chunking across multiple calls
- **Compiled / binary-heavy repos** (e.g. C++ without headers) will produce lower quality output as source context is limited
- **CVSS scores are approximate** — they're inferred from threat descriptions, not from a full manual CVSS assessment
- **Latency scales with component count** — NB-03 makes one API call per component; repos with 15+ identified components may exceed 60s

---

## Roadmap

- [ ] IDE Plugin — VS Code extension that runs on every PR
- [ ] CI/CD Integration — GitHub Action that blocks merges on new CRITICAL threats
- [ ] PASTA & DREAD methodology support
- [ ] Auto-update — re-run when architecture-affecting files change
- [ ] Compliance mapping — SOC 2, ISO 27001, PCI-DSS control auto-mapping
- [ ] Team collaboration — assign mitigations to engineers, track remediation

---

## References

- [STRIDE Threat Modeling — Microsoft](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OpenAPI Specification](https://swagger.io/specification/)

---

*Built for HackBricks Round 1 — AppSec track.*
