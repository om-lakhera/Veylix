# Verified Sources, Uncertainties & Next Phase Recommendations

This document maintains the official bibliography of verified documentation, records unresolved strategic questions, and recommends immediate next steps.

---

## 1. Verified Official Sources & Limits

### Cloudflare Infrastructure (Zero Budget Foundation)
1. **Cloudflare Workers Free Tier Documentation & Limits:**
   - [Cloudflare Workers Limits & Pricing](https://developers.cloudflare.com/workers/platform/pricing/)
   - Verified Limits: 100,000 requests/day (resets 00:00 UTC), 10 ms CPU execution time per invocation (I/O wait is free), 128 MB RAM per isolate, 50 subrequests per invocation.
   - Enforcement: Hard stop policy (HTTP 1015/1027). Accidental overages are strictly impossible on the Free plan.
2. **Cloudflare Pages Free Tier Documentation:**
   - [Cloudflare Pages Limits & Pricing](https://developers.cloudflare.com/pages/platform/limits/)
   - Verified Limits: Unlimited requests and bandwidth for static assets, 500 builds/month, 1 concurrent build, 20,000 files/deployment (max 25 MiB/file), free `*.pages.dev` subdomain with automatic Universal SSL.
3. **Cloudflare D1 Free Tier Documentation:**
   - [Cloudflare D1 Pricing & Limits](https://developers.cloudflare.com/d1/platform/pricing/)
   - Verified Limits: 5,000,000 rows read/day, 100,000 rows written/day, 5 GB total storage (500 MB max per DB). Daily quotas enforce hard stops with zero automatic overage fees.

### Threat Intelligence & Ecosystem APIs
4. **Google OSV API (`api.osv.dev`):**
   - [OSV API Documentation & Batch Endpoint](https://google.github.io/osv.dev/post-v1-querybatch/)
   - Verified Limits: `POST /v1/querybatch` accepts up to **1,000 package queries in a single HTTP request**; response size capped at 32 MiB on HTTP/1.1 (unlimited on HTTP/2). Public and unauthenticated.
5. **Google deps.dev API (`api.deps.dev`):**
   - [Open Source Insights API Terms & Schema](https://deps.dev/api)
   - Verified Policies: Governed by Google API Terms of Service; data licensed under CC-BY 4.0; client caching is explicitly permitted; returns HTTP 429 under overload (requires exponential backoff).
6. **OpenSSF Scorecard:**
   - [Scorecard Checks Specification](https://scorecard.dev/)
   - Verified Signals: `Maintained`, `Code-Review`, `Branch-Protection`, and dependency pinning metrics.

### GitHub Integration & Authentication
7. **GitHub Apps Authentication & Webhooks:**
   - [GitHub REST API - Authenticating as a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app)
   - Verified Specs: RS256 JWT signed via App Private Key; 10-minute maximum expiration; exchanged for 1-hour installation token; HMAC SHA-256 (`X-Hub-Signature-256`) webhook signing.
8. **Web Crypto API in Cloudflare Workers:**
   - [Cloudflare Workers Web Crypto API](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
   - Verified Capabilities: Native support for `RSASSA-PKCS1-v1_5` / `RS256` key import (PKCS#8) and `HMAC-SHA256` signing via `crypto.subtle`.

---

## 2. Cost Risks & Safety Evaluation

| Risk Category | Identified Hazard | Risk Mitigation / Defense |
| :--- | :--- | :--- |
| **Accidental Billing Risk** | Cloudflare charging overage fees if traffic spikes. | **Eliminated:** Cloudflare Free accounts do not have credit card details required and enforce hard stops (error responses) rather than billing overages. |
| **Worker Subrequest Cap (50)** | Scanning a repository with 200 dependencies could trigger 200 outbound subrequests. | **Eliminated:** OSV calls are consolidated into 1 single batch subrequest (`/v1/querybatch`). Deps.dev calls are capped to $\le 30$ top dependencies per invocation. |
| **Database Quota Burn** | Running automated scans could exhaust D1 daily write limits (100k rows/day). | **Eliminated:** Persistent database omitted from prototype. Scanning is completely stateless. |
| **API Blacklisting (deps.dev)** | High-frequency polling triggering IP bans. | **Mitigated:** All requests implement exponential backoff; client-side browser caching prevents duplicate requests for the same repo. |

---

## 3. Remaining Uncertainties & Strategic Questions

1. **GitHub Auth Strategy for Milestone 3:**
   - *Option A:* Standard **GitHub OAuth App (User Token)**. Allows reading the user's public and private repos on demand with simpler user onboarding.
   - *Option B:* Full **GitHub App Installation**. Required if we want automated repository webhooks later.
   - *Recommendation for Prototype:* Start with unauthenticated public repo URLs or direct file paste first, then evaluate whether GitHub OAuth or GitHub App is best suited for user testing.
2. **Missing OpenSSF Scorecards for Long-Tail Packages:**
   - Many smaller npm packages do not have an OpenSSF Scorecard in `deps.dev`. How should Veylix score them?
   - *Proposed Rule:* If no Scorecard exists, default the `Maintained` score to neutral (5/10) and rely on the release staleness (days since last npm/PyPI publish) to avoid unfair penalties.
3. **Local Tooling Selection:**
   - Verify that all local development can be run using standard Node.js tools (`wrangler dev`, `vite`) with zero external service accounts.

---

## 4. Recommended Next Phase: Approval Gate

We recommend obtaining stakeholder approval for **Milestone 1 of the Proof of Concept**:
* Build a local, zero-cost npm lockfile parser in TypeScript.
* Connect it to the Google OSV batch endpoint (`POST /v1/querybatch`).
* Validate vulnerability detection against a test repository without setting up any cloud hosting or external accounts.
