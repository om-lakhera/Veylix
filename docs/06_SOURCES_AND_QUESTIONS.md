# Research Sources & Unresolved Decisions

This document records the specific verified sources consulted during research and outlines open strategic decisions for the founder/lead.

---

## 1. Verified Sources Checked

### Competitive Intelligence
1. **Renovate Documentation & Noise Controls:**
   - [Renovate Docs - Dependency Dashboard](https://docs.renovatebot.com/key-concepts/dashboard/)
   - Focus: Alert fatigue management, grouping presets, throttle limits, multi-host support.
2. **Dependabot Architecture & Best Practices:**
   - [GitHub Docs - About Dependabot version updates](https://docs.github.com/en/code-security/dependabot)
   - Focus: Native GitHub integration, YAML configuration, lack of multi-platform support, grouping syntax.
3. **Snyk Open Source Capabilities & Pricing:**
   - [Snyk Documentation - Open Source Vulnerability Management](https://docs.snyk.io/scan-using-snyk/snyk-open-source)
   - Focus: Reachability analysis, proprietary vulnerability database, per-developer pricing model, test limitations.
4. **OSV-Scanner by Google:**
   - [Google Open Source Vulnerabilities (OSV) Database & Scanner](https://osv.dev/ and https://github.com/google/osv-scanner)
   - Focus: Open-source CLI, OSV schema, zero-cost access to GHSA, PyPI, RustSec, Go advisory feeds.

### Data APIs & Infrastructure
5. **deps.dev API (Open Source Insights):**
   - [Google Open Source Insights API Documentation](https://deps.dev/api)
   - Focus: Version metadata, transitive dependency graph, license info, and OpenSSF Scorecard aggregation.
6. **OpenSSF Scorecard:**
   - [Scorecard Security Health Metrics](https://scorecard.dev/)
   - Focus: `Maintained`, `Code-Review`, `Branch-Protection`, automated checks for open-source repositories.
7. **GitHub App Permissions & Rate Limits:**
   - [GitHub REST API Documentation - Rate Limits & Apps](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting)
   - Focus: 15,000 req/hr allocation for GitHub Apps, granular `contents:read` permissions without cloning repo source.

---

## 2. Unresolved Strategic Decisions (For User Review)

Before entering the implementation phase, the following decisions must be made:

1. **Initial Tech Stack Selection:**
   - **Backend:** Node.js (TypeScript with Fastify or Express) vs. Go (high concurrency, low memory footprint).
   - **Frontend:** Next.js (React) vs. Vite + Vanilla CSS/Tailwind (fast SPA, low server complexity).
   - **Database:** PostgreSQL (with Prisma or Drizzle ORM).

2. **Delivery Mechanism:**
   - **Option A:** Hosted Web Application (User logs in via GitHub, sees dashboard).
   - **Option B:** Single GitHub Issue / PR Summary Comment (In-repo summary, similar to Renovate's Dependency Dashboard).
   - *Recommendation:* Start with Option A (Web Application) for rich visualization, with optional GitHub Issue sync in a later phase.

3. **Ecosystem Prioritization:**
   - Confirm launch ecosystems: **npm (JavaScript/TypeScript)** and **PyPI (Python)**, or should we include **Go** / **Rust** in the MVP?

4. **Monetization & Free Tier Structure:**
   - E.g., 100% Free for all Public/Open-Source Repositories; Free tier for up to 3 Private Repositories; Paid tier ($19/mo) for unlimited private repos and team members.
