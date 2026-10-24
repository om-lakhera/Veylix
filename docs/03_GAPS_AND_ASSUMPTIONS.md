# Market Gaps & Evidence vs. Assumptions

To build a viable SaaS product, we must clearly separate empirically verified market realities from unvalidated assumptions.

---

## 1. Identified Market Gaps

1. **The "Pre-CVE" Maintenance Blindspot:**
   - Most tools react only *after* a vulnerability is published in NVD/GHSA.
   - There is no mainstream, lightweight tool continuously telling repo owners: *"This dependency has had no commits in 2 years, has only 1 active maintainer, and has 45 open issues—consider evaluating an alternative before a critical issue strikes."*

2. **Action Prioritization vs. Notification Spun:**
   - Tools either flood the repository with individual PRs (Dependabot) or give an unranked list of 100+ package bumps (Renovate).
   - Developers need a simple ranking:
     - **Tier 1 (Urgent):** Exploitable CVE or Critical vulnerability in an unmaintained package.
     - **Tier 2 (High):** Known vulnerability with a non-breaking safe patch available.
     - **Tier 3 (Maintenance Risk):** Abandoned or deprecated package without active maintainers.
     - **Tier 4 (Routine):** Minor/patch version updates with high test pass rates and active maintainers.

3. **Accessibility & Pricing Transparency:**
   - Snyk is priced out of reach for independent developers and startups.
   - OSV-Scanner has zero UI or SaaS workflow.
   - An intuitive, developer-focused dashboard with generous free/freemium access fills this void.

---

## 2. Verified Evidence vs. Unvalidated Assumptions

| Category | Item | Classification | Evidence / Basis | Validation Next Step |
| :--- | :--- | :--- | :--- | :--- |
| **User Pain** | Developers suffer from PR noise and alert fatigue from automated dependency bots. | **Verified Evidence** | Documented across developer surveys, Renovate's core rationale for the Dependency Dashboard, and community articles on bot fatigue. | N/A (Confirmed) |
| **Data Availability** | Open-source vulnerabilities can be queried freely via open REST APIs without paid licensing. | **Verified Evidence** | Google OSV API (`api.osv.dev`) and deps.dev API provide open, public REST endpoints for querying advisory databases (GHSA, PyPI, RustSec, Go, etc.). | N/A (Confirmed) |
| **Maintenance Signals** | Package maintenance metrics (commits, releases, OpenSSF Scorecard) are programmatically accessible. | **Verified Evidence** | `deps.dev` v3 API maps package versions (`purl`) directly to repository OpenSSF Scorecard evaluations (`Maintained`, `Code-Review`, `Branch-Protection`). | Verified via public API schema. |
| **GitHub Permissions** | We can inspect manifests without reading proprietary source code. | **Verified Evidence** | GitHub App permissions allow `Contents: read-only` targeting only manifest filenames (`package.json`, `requirements.txt`, etc.) via the Trees/Contents API. | Verified against GitHub Apps API documentation. |
| **Product Value** | Developers will prefer an external SaaS dashboard over in-repo PRs for triaging. | **Assumption** | Some developers strongly prefer staying entirely inside GitHub PRs/Issues and dislike leaving the GitHub UI. | Interview 5-10 maintainers on whether they want a Web Dashboard, a single GitHub Issue (like Renovate), or both. |
| **Score Trust** | Maintainers will trust a composite "Veylix Health Score" (0–100). | **Assumption** | If the scoring algorithm is opaque ("black box"), developers will mistrust it. | Ensure the score calculation is transparent, deterministic, and displays itemized reasons. |
| **Willingness to Pay** | Teams will pay $15–$30/repo/month for maintenance intelligence if PR automation is omitted. | **Assumption** | Teams might consider intelligence without automated PR fixing incomplete. | Validate willingness to pay during closed beta testing. |
