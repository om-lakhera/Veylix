# MVP Recommendations & Incremental Proof of Concept

This document defines the architecture of the **Smallest Useful MVP**, details why a database is omitted from the initial prototype, and outlines an incremental 3-milestone Proof of Concept (PoC).

---

## 1. Database Review: Why the Prototype is Stateless

We evaluated whether persistent database storage (e.g., Cloudflare D1) is necessary for the first working prototype:

### Decision: **Omit Persistent Database from Prototype (Stateless On-Demand Architecture)**

* **Simplest Working Design:** An on-demand scan workflow takes a repository manifest or lockfile, parses it in Worker memory, enriches it via OSV and deps.dev APIs, and streams the ranked JSON payload directly to the React frontend.
* **No Quota Consumption:** Zero D1 row reads and zero D1 row writes are consumed, completely eliminating the risk of exceeding Cloudflare D1's 100k daily write limit.
* **Zero Infrastructure Overhead:** No SQL schema migrations, no ORM layer (Drizzle deferred to Phase 2), and zero risk of orphaned or stale scan records.
* **Client-Side Session Cache:** The React dashboard caches scan results in the user's browser `sessionStorage` or `localStorage`, allowing instant navigation without re-triggering backend compute.

> [!NOTE]
> Cloudflare D1 and Drizzle ORM will be considered only in **Phase 2** if we need asynchronous webhook ingestion, historical trend graphs across weeks, or multi-user preferences.

---

## 2. Incremental Proof of Concept (PoC) Plan

The PoC will be executed in three strictly isolated, incremental milestones:

```
┌────────────────────────────────────────────────────────┐
│ Milestone 1: npm Lockfile Parser & OSV Batch Engine    │
│ (Validate lockfile parsing + OSV batch query)          │
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│ Milestone 2: Python Engine & deps.dev Health Signals   │
│ (Validate requirements.txt + OpenSSF Scorecard metrics)│
└──────────────────────────┬─────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│ Milestone 3: React Web UI & Read-Only GitHub Connect   │
│ (Deploy dashboard to Cloudflare Pages & scan live repo)│
└────────────────────────────────────────────────────────┘
```

### Milestone 1: npm Analysis Engine
* **Goal:** Parse an npm lockfile and identify known vulnerabilities.
* **Input:** Valid `package.json` and `package-lock.json` containing known test dependencies (including an intentionally outdated/vulnerable version such as `lodash@4.17.15`).
* **Process:** Extract package names and resolved versions into a JSON array; issue a single batch query to `POST https://api.osv.dev/v1/querybatch`.
* **Deliverable & Acceptance Criteria:**
  - Extracts 100% of direct and resolved transitive packages.
  - Returns OSV CVE/GHSA matches in a single batch HTTP request.
  - Completes in under 2 seconds.

### Milestone 2: Python Analysis Engine & Vitality Enrichment
* **Goal:** Parse Python dependencies and enrich findings with OpenSSF Scorecard signals.
* **Input:** Pinned `requirements.txt` (e.g., `requests==2.20.0`, `flask==1.0.2`, `urllib3==1.24.1`).
* **Process:** Parse package specifiers; query OSV for the PyPI ecosystem; query `deps.dev` for OpenSSF Scorecard `Maintained` subscore and release staleness.
* **Deliverable & Acceptance Criteria:**
  - Accurately identifies vulnerable Python packages.
  - Correctly extracts Scorecard `Maintained` rating and release dates via deps.dev.
  - Implements subrequest throttling ($\le 30$ subrequests per run).

### Milestone 3: React Dashboard & GitHub API Integration
* **Goal:** Deliver an interactive, zero-cost web interface hosted on Cloudflare Pages.
* **Input:** Public GitHub repository URL or pasted lockfile.
* **Process:** Cloudflare Worker fetches manifest from GitHub public API (`Contents: read-only`), runs the enrichment pipeline, and returns the prioritized triage queue to the React frontend.
* **Deliverable & Acceptance Criteria:**
  - Hosted live on `veylix.pages.dev` with custom Vanilla CSS styling.
  - Renders a clean Repository Health Score (0–100) and categorized triage cards (Immediate, Caution, Maintenance Warning, Healthy).
  - Handles API failures with graceful degradation (no paywalls or broken screens).

---

## 3. Postponed Features Matrix

| Postponed Feature | Reason for Deferral | Phase |
| :--- | :--- | :--- |
| **Persistent Database (D1)** | Unnecessary for on-demand inspection; adds complexity and write quota overhead. | Phase 2 |
| **Automated PR Creation** | High git conflict maintenance; does not test core prioritization hypothesis. | Phase 2 |
| **Additional Ecosystems (Go, Rust)** | Focus validation on the two largest ecosystems (npm & PyPI) first. | Phase 2 |
| **AST / Reachability Analysis** | Requires language-specific runtimes and heavy compute incompatible with 10 ms CPU limits. | Phase 3 |
| **Paid Upgrade / Billing System** | Strictly prohibited by ₹0 budget constraint. | Never |
