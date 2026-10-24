# Market Gaps, Evidence & Hypothesis Validation

This document establishes the empirical foundation for Veylix, separating verified operational facts from unvalidated market hypotheses.

---

## 1. The "Pre-CVE Maintenance Gap" as an Unvalidated Hypothesis

### The Hypothesis
> **Hypothesis:** Developers and repository maintainers care enough about upstream package abandonment and maintenance velocity that they will actively prioritize and act on "maintenance vitality" alerts *before* an official CVE is published.

### Adjacent Competitors & Existing Tooling
While standard tools focus on CVEs, several solutions already address parts of this problem:
* **Socket.dev:** Proactively monitors npm and PyPI for supply chain anomalies, unmaintained packages, install scripts, and author churn.
* **Endor Labs:** Evaluates dependency lifecycle risk, maintenance cadence, and whether vulnerable methods are reachable.
* **OpenSSF Scorecard:** Automated security and maintenance checks (`Maintained`, `Code-Review`, `Branch-Protection`).
* **Debricked:** Incorporates community health metrics directly into its SCA dashboard.
* **Ecosystem-Native Signals:** `npm audit` warns about deprecated packages directly in the terminal; `pip` warns on unsupported runtime configurations.

### Supporting Evidence
1. **Supply Chain Risks in Neglected Projects:** High-profile security incidents (such as `event-stream` or the `xz-utils` backdoor) showed that unmaintained or under-maintained libraries with burned-out maintainers are vulnerable to social engineering and ownership hijacking.
2. **Technical Debt Accumulation:** Stale libraries hold back major runtime upgrades (e.g., Python 3.8 EOL, Node ESM migration), eventually forcing high-stress emergency rewrites.

### Counterarguments & Industry Skepticism
1. **"Mature & Stable" vs. "Abandoned":** Many single-purpose libraries (e.g., `is-number`, `mime-types`) are feature-complete and require zero commits for years. Flagging them as "high risk" creates developer irritation and false alarms.
2. **High Migration Friction:** Upgrading a patched library is a one-line semver bump. In contrast, replacing an unmaintained library requires architectural refactoring, testing, and migration cost. Without a direct drop-in replacement, developers will defer the task.
3. **"If It's Not Broken, Don't Touch It":** In commercial environments under sprint deadlines, engineering managers rarely approve replacing a working library solely based on a low commit frequency.

### User-Validation Experiments

| Experiment | Target Group | Methodology | Success Metric |
| :--- | :--- | :--- | :--- |
| **Exp 1: Triage Survey** | 10 active GitHub maintainers | Present a real audit of their repository with two lists: (A) CVEs vs. (B) Abandoned packages. Ask which ones they would schedule in their next sprint. | $\ge 60\%$ express willingness to act on non-CVE maintenance risks within a quarter. |
| **Exp 2: False-Positive Calibration** | 50 top open-source repos | Run vitality scoring on mature repositories (e.g., Express, FastAPI, Redux). Count how many feature-complete, zero-defect libraries are falsely tagged as "Critical Risk". | False-positive rate on stable utility libraries is under $10\%$. |
| **Exp 3: Actionability Test** | Beta users | Provide maintenance warning cards with vs. without suggested migration alternatives (e.g., "Consider migrating from `request` to `undici` or `axios`"). | Measurable click-through or action rate $> 25\%$ higher when replacement options are surfaced. |

---

## 2. Verified Evidence vs. Unvalidated Assumptions

| Category | Item | Classification | Evidence / Basis | Next Validation Step |
| :--- | :--- | :--- | :--- | :--- |
| **User Pain** | Developers experience alert fatigue from noisy, un-grouped dependency bots. | **Verified Evidence** | Documented across developer surveys, Renovate's core rationale for the Dependency Dashboard, and community feedback. | N/A (Confirmed) |
| **Data Access** | Vulnerabilities can be queried freely via open REST APIs with zero licensing costs. | **Verified Evidence** | Google OSV API (`api.osv.dev`) provides public REST endpoints supporting batch queries up to 1,000 packages. | Verified via official documentation. |
| **Health Signals** | OpenSSF Scorecard metrics can be fetched freely for public packages. | **Verified Evidence** | Google `deps.dev` v3 API provides package metadata and OpenSSF Scorecard checks under CC-BY 4.0 terms. | Verified via official API endpoints. |
| **GitHub Permissions** | Manifests can be inspected without cloning or storing proprietary code. | **Verified Evidence** | GitHub App permissions allow `Contents: read-only` targeting only manifest filenames via the Git Trees/Blobs API. | Verified against GitHub Apps API documentation. |
| **UI Delivery** | Developers want a standalone web dashboard rather than an in-repo issue. | **Assumption** | Some developers strongly prefer staying entirely inside GitHub PRs/Issues (like Renovate's Dependency Dashboard). | Validate through initial beta user feedback. |
| **Pre-CVE Action** | Developers will allocate sprint cycles to replace unmaintained libraries before a CVE hits. | **Unvalidated Hypothesis** | Many teams defer refactors until forced by a security incident or runtime breakage. | Execute Validation Experiments 1 & 3. |
| **Stateless UX** | A stateless, on-demand scan is sufficient for early maintainer value. | **Assumption** | Users might expect historical diffs and scheduled notifications immediately. | Confirm with prototype user testing. |
