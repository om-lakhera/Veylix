# Technical Feasibility, Privacy, Security & Strict ₹0 Budget Plan

This document establishes the verified technical feasibility, security architecture, and strict ₹0 operating model for Veylix.

---

## 1. Strict ₹0 Budget Reconciliation

All prior designs mentioning paid compute, managed Postgres databases, Redis queues, or custom domains have been **completely eliminated**. Veylix is engineered to operate perpetually on verified free tiers with hard caps that prevent accidental billing.

### Verified Free Tier Quotas & Boundaries

| Component | Provider & Tier | Quota & Technical Limits | Accidental Billing Protection |
| :--- | :--- | :--- | :--- |
| **Backend Compute** | **Cloudflare Workers (Free Plan)** | • **100,000 requests/day** (resets 00:00 UTC)<br>• **10 ms CPU time** per invocation (I/O wait is free)<br>• **128 MB RAM** per isolate<br>• **50 subrequests** per invocation<br>• Free `*.workers.dev` domain | **Hard Stop Policy:** Requests fail with HTTP 1015/1027 when limit is hit. Overages cannot occur unless the account is explicitly upgraded to the $5/mo Paid plan. |
| **Frontend Hosting** | **Cloudflare Pages (Free Plan)** | • **Unlimited requests & bandwidth**<br>• **500 builds/month** (1 concurrent build)<br>• 20,000 files/deployment (25 MiB max file)<br>• Free `*.pages.dev` domain + Universal SSL | **100% Free Forever:** No billing details required for static hosting. |
| **Database (Prototype)** | **None (Stateless Architecture)** | • In-memory parsing & client session storage<br>• Zero storage quotas, zero database maintenance | **Zero Risk:** Eliminates database operational concerns entirely for Phase 1. |
| **Database (Future / Phase 2)** | **Cloudflare D1 (Free Tier)** | • **5,000,000 rows read/day**<br>• **100,000 rows written/day**<br>• **5 GB total storage** (max 500 MB per DB)<br>• Max 10 databases per account | **Hard Stop:** D1 queries return errors upon exceeding daily read/write allowances. No automatic billing. |
| **Domain & DNS** | **Cloudflare Subdomains** | • Subdomains: `veylix.pages.dev` & `api.veylix.workers.dev`<br>• Unlimited free SSL/TLS certificates | **Cost: ₹0 ($0.00).** No domain purchase or annual renewal needed. |
| **Threat Intelligence** | **Google OSV API** | • Batch endpoint `/v1/querybatch` (up to 1,000 packages/request)<br>• Public, unauthenticated open REST API | **Cost: ₹0 ($0.00).** Open public service. |
| **Maintenance Signals** | **Google deps.dev API** | • Open Source Insights REST API<br>• CC-BY 4.0 license; caching explicitly allowed | **Cost: ₹0 ($0.00).** Open public service. |

**Total Operating Cost: Exactly ₹0 / month.**

---

## 2. Threat Intelligence & External API Verification

### Google OSV API (`https://api.osv.dev`)
* **Usage Policy:** Public open-source vulnerability database aggregating GHSA, PyPI, RustSec, Go, etc. No API key required.
* **Batch Endpoint:** `POST /v1/querybatch` accepts up to **1,000 queries per single HTTP request**.
* **Cloudflare Workers Optimization:** Scanning a repository with 250 dependencies requires only **1 subrequest** out of the 50 allowed on the Workers Free tier.
* **Rate Limits & Resilience:** No static published quota. Clients are expected to implement exponential backoff on HTTP 5xx/429.

### Google deps.dev API (`https://api.deps.dev/v3alpha`)
* **Usage Policy:** Governed by Google API Terms of Service. Data licensed under CC-BY 4.0.
* **Caching Policy:** Terms explicitly encourage client-side and edge caching to reduce server load.
* **Quota & Throttling:** No fixed numerical rate limit, but responds with `HTTP 429 (Too Many Requests)` under sudden bursts.
* **Workers Strategy:** Because deps.dev requires individual package URL (`purl`) lookups, the worker will only fetch health scores for direct dependencies (capping lookups to $\le 30$ subrequests per scan).

---

## 3. GitHub App Integration, Auth & Security

### Minimum Permissions Required
To guarantee developer trust and adhere to the principle of least privilege:
* `Metadata: read-only` (Mandatory: repository names, branches, and account metadata).
* `Contents: read-only` (Restricted: used strictly to fetch manifest and lockfile trees).
* *No write permissions, no repository administration, no source code access.*

### Authentication & Token Generation Flow
1. **GitHub App Private Key Storage:** Stored securely as an encrypted secret in Cloudflare Workers (`wrangler secret put GITHUB_PRIVATE_KEY`).
2. **RS256 JWT Generation in Worker:**
   - Generated using the native Web Crypto API (`crypto.subtle`).
   - Header: `{"alg": "RS256", "typ": "JWT"}`.
   - Payload: `{"iss": GITHUB_APP_ID, "iat": now - 60, "exp": now + 600}` (maximum 10-minute lifetime).
3. **Installation Access Token Exchange:**
   - Worker makes an outbound call: `POST https://api.github.com/app/installations/{installation_id}/access_tokens`.
   - Bearer: The RS256 JWT.
   - Response: An ephemeral installation token valid for **1 hour**.
   - The token is used in-memory for the duration of the scan and never written to persistent disk.

### Webhook Verification & Replay Protection
* GitHub signs webhook deliveries via HMAC SHA-256 in the `X-Hub-Signature-256` header.
* The Cloudflare Worker verifies this signature using `crypto.subtle.verify` against the raw payload bytes and the pre-configured `GITHUB_WEBHOOK_SECRET`.
* Unsigned or invalid requests are terminated immediately with `HTTP 401 Unauthorized`.

### Private Repository Handling & Privacy Guarantees
* **Zero Source Code Ingestion:** Veylix uses GitHub's Git Trees and Blobs API to retrieve only targeted filenames (`package.json`, `package-lock.json`, `requirements.txt`, `poetry.lock`).
* **In-Memory Lifespan:** File contents are parsed in Worker memory into package tuples `(name, version)` and discarded. No customer application code is ever persisted or logged.

---

## 4. Graceful Degradation Protocols (Zero-Upgrade Policy)

Under no circumstance will Veylix present a paywall or paid upgrade prompt. The system will degrade gracefully as follows:

| Constraint / Trigger | Fallback Behavior |
| :--- | :--- |
| **Workers 100k daily requests exhausted** | Edge caches serve cached scan results. If an uncached request fails with HTTP 1015/1027, the UI displays a clean status notice: *"Daily community scan quota reached. Quota resets at 00:00 UTC."* |
| **Workers 50 subrequests limit** | All vulnerability checks are batched into a single `POST /v1/querybatch` call (1 subrequest). If a project has $>30$ direct dependencies, deps.dev vitality lookups are paginated or deferred to client-side on-demand inspection. |
| **deps.dev returns HTTP 429** | The scanner degrades to **Vulnerability-Only Mode**. OSV advisory results are displayed immediately, while maintenance indicators show *"Vitality score temporarily unavailable."* |
| **GitHub App Rate Limits reached** | The web UI provides an instant fallback: **"Direct Lockfile Upload / Paste"**, allowing developers to drop a `package-lock.json` directly into the dashboard for client/worker processing without consuming GitHub API quota. |
