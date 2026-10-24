# Technical Feasibility, Privacy, Security & Cost Assessment

This assessment reviews the architectural and operational realities of building Veylix without paid APIs or heavy infrastructure.

---

## 1. GitHub Integration Feasibility

### Architecture
- **Model:** Native **GitHub App** (installed by user/org at account or repo level).
- **Permissions Required:**
  - `Metadata: read-only` (Default mandatory permission for repo list, branch names).
  - `Contents: read-only` (Required solely to fetch manifest and lockfile trees).
  - `Pull requests: read-only` *(Optional future)*: To detect open dependency PRs.
- **Webhook Ingestion:**
  - `push` event: Check if modified files include registered manifest paths (`package.json`, `package-lock.json`, `requirements.txt`, etc.).
  - `installation` & `installation_repositories`: Setup or tear down scanned repo records.
- **Rate Limit Budget:**
  - Authenticated GitHub Apps receive **15,000 requests per hour** per installation.
  - Manifest fetching uses the Git Trees API or single file Content API (1 to 3 requests per commit affecting manifest files).
  - Webhook-driven delta scans easily fit within GitHub App quotas even for active repositories.

---

## 2. Technical Feasibility & External Data Sources

All required threat intelligence and maintenance metrics can be gathered using open, zero-cost APIs:

1. **Google OSV API (`https://api.osv.dev/v1/query`):**
   - **Cost:** Free, public REST API with high rate tolerances.
   - **Data:** Queries packages by name, ecosystem, and version. Returns standardized OSV JSON containing CVE IDs, GHSA IDs, severity CVSS scores, affected version ranges, and fixed versions.
2. **Google deps.dev API (`https://api.deps.dev/v3alpha/`):**
   - **Cost:** Free, public REST/gRPC API.
   - **Data:** Transitive dependency graphs, package licenses, project links, and aggregated **OpenSSF Scorecard** metrics (e.g. `Maintained`, `Code-Review`, `Branch-Protection`, `Dangerous-Workflow`).
3. **OpenSSF Scorecard Data:**
   - Pre-computed scores for hundreds of thousands of top open-source repositories; accessible directly via `deps.dev` or the OpenSSF Scorecard public API (`https://api.scorecard.dev/v2/`).

---

## 3. Privacy & Security Assessment

To gain developer and enterprise trust, Veylix will adopt a **"Zero-Code Ingestion"** architecture:

* **No Source Code Cloning:** Veylix will never execute `git clone`. The backend fetches only specific manifest and lockfile content via GitHub API blobs.
* **Ephemeral In-Memory Parsing:** Manifest files are parsed in memory, extracted into package tuples `(ecosystem, name, version)`, and the raw manifest text is immediately discarded or securely hashed.
* **Encrypted Secrets:**
  - GitHub App private keys and webhook secrets stored via environment secrets manager (e.g., AWS Secrets Manager, Doppler, or Fly secrets).
  - GitHub App installation tokens are temporary and expire automatically after 1 hour.
* **Data Retention:**
  - Retain only: repository metadata (ID, full name), dependency graph records `(package, current_version, resolved_version)`, computed risk score, and timestamped audit logs.
  - No customer proprietary intellectual property is ever written to disk or database.

---

## 4. Recurring Operational Costs (Zero Paid APIs)

| Component | Technology / Service Provider | Development / Free Tier | Production Scale (1,000 Repos) |
| :--- | :--- | :--- | :--- |
| **Vulnerability Data** | Google OSV API | $0.00 / mo (Free) | $0.00 / mo (Free open service) |
| **Maintenance & Health** | Google deps.dev / OpenSSF API | $0.00 / mo (Free) | $0.00 / mo (Free open service) |
| **Compute / API Server** | Node.js / Go backend on Fly.io, Render, or AWS ECS | $0.00 - $7.00 / mo | $25.00 - $50.00 / mo |
| **Database** | Managed PostgreSQL (Neon, Supabase, or AWS RDS) | $0.00 / mo (Free tier) | $15.00 - $35.00 / mo |
| **Cache & Job Queue** | Redis (Upstash Serverless or Redis Cloud) | $0.00 / mo (Free tier) | $10.00 - $20.00 / mo |
| **Domain & DNS** | Cloudflare DNS + Standard Registrar | ~$12.00 / year (~$1/mo) | ~$12.00 / year |
| **Total Estimated Run Cost** | | **~$0 - $10 / month** | **~$50 - $115 / month** |

**Conclusion:** The project is exceptionally capital-efficient. Core intelligence requires zero paid data subscriptions.
