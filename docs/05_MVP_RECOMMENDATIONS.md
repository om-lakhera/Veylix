# MVP Recommendations & Phased Roadmap

To validate market demand without unnecessary technical overhead, we define the **Smallest Useful MVP** and clearly designate features to postpone.

---

## 1. The Smallest Useful MVP (Phase 1)

The objective of the MVP is to provide **immediate, differentiated insight** upon connecting a repository in under 60 seconds, answering:
*"What are my dependencies, how healthy are they, and what single item requires attention first?"*

### MVP Core Features:
1. **GitHub App Authentication & Onboarding:**
   - Sign in with GitHub (OAuth).
   - Install GitHub App on selected repositories.
2. **Two Primary Manifest Ecosystems:**
   - **npm / Node.js:** Support `package.json` + `package-lock.json` (or `pnpm-lock.yaml`).
   - **Python / PyPI:** Support `requirements.txt` / `Pipfile.lock` / `poetry.lock`.
   *(Node.js and Python represent >60% of open-source and early-stage startup projects).*
3. **Automated Vulnerability Scan (OSV):**
   - Query OSV API for all detected package versions.
   - Display CVE/GHSA ID, severity rating (Critical/High/Medium/Low), and fixed version.
4. **Maintenance Health Signal (deps.dev / OpenSSF):**
   - Fetch project scorecard: Maintained score, days since last release, commit frequency indicator.
   - Flag packages with no updates in >18 months or marked deprecated.
5. **Veylix Prioritization Engine (Triage Score):**
   - Calculate a deterministic **Repository Health Score (0–100)**.
   - Present a ranked "Triage Queue" sorting items by risk severity:
     - 🔴 **Immediate:** Active vulnerability + Unmaintained or high exploitability.
     - 🟡 **Caution:** Known vulnerability with clear upgrade path, or Abandoned core dependency.
     - 🟢 **Healthy:** Actively maintained, no advisories.
6. **Web Dashboard:**
   - Clean, high-signal single-page dashboard for each repository.
   - Search/filter dependencies by status (Vulnerable, Outdated, Abandoned).

---

## 2. Features to Postpone (Post-MVP)

Postponing these items prevents premature optimization and high maintenance costs:

| Postponed Feature | Rationale for Postponement | Revisit In |
| :--- | :--- | :--- |
| **Automated PR Generation / Bot Commits** | Dependabot and Renovate already do this. Building PR generation early introduces git conflict handling, automerge rules, and high maintenance. First validate if maintainers value the triage score. | Phase 2 |
| **Reachability / AST Call-Graph Analysis** | High complexity. Requires deep language AST parsers and significant compute. Snyk charges enterprise prices specifically because this is costly to build and run. | Phase 3 |
| **Support for 10+ Package Managers** | Parsing Rust Cargo, Go mod, Maven, Gradle, Composer, RubyGems adds parsing edge cases. Start with npm & PyPI first. | Phase 2 |
| **CI/CD Integration CLI (CLI Tool)** | A web dashboard provides better initial engagement and faster feedback loops than a headless CLI. | Phase 2 |
| **Custom Policy & SLA Rules Engine** | Complex enterprise configuration creates onboarding friction. Stick to sensible, opinionated defaults first. | Phase 3 |
| **License Compliance Scanning** | Secondary value compared to security and maintenance risk. Can be added via `deps.dev` license field later. | Phase 2 |
