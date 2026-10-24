# Veylix: Project Brief

## Executive Summary
**Veylix** is a developer-centric dependency health and prioritization platform for GitHub repositories. Rather than bombarding engineering teams with dozens of disconnected pull requests and low-signal vulnerability alerts, Veylix analyzes dependency health holistically—evaluating known security advisories (CVEs/GHSA), package maintenance vitality, and release cadence to deliver a single, prioritized triage stream.

The project is governed by a **strict total budget of ₹0 ($0.00)**. All components must operate entirely on verified free tiers with hard caps (no accidental overages, no paid subscriptions, and no paid APIs).

---

## 1. Problem Statement & Hypothesis
Modern software engineering teams face severe **alert fatigue** and **maintenance blindspots**:
- **Notification Overload:** Standard dependency bots (like unconfigured Dependabot) open fragmented PRs for every routine version bump, leading maintainers to ignore alerts.
- **CVE Bias & Maintenance Blindspot:** Traditional vulnerability scanners (like OSV-Scanner) trigger only on registered CVEs. They do not proactively flag dependencies on an abandonment trajectory until a vulnerability or supply chain compromise occurs.
- **Action Prioritization:** Developers lack contextual prioritization: *Which dependency update actually requires immediate intervention today versus which can safely wait for a scheduled sprint?*

> [!NOTE]
> The hypothesis that developers will actively prioritize and act on "pre-CVE" maintenance vitality metrics is currently treated as an **unvalidated hypothesis** and will be tested through targeted maintainer experiments before heavy feature commitment.

---

## 2. Target Audience
1. **GitHub Repository Maintainers & Tech Leads:** Need a consolidated view of dependency risks without drowning in bot PRs.
2. **Small Engineering Teams & Startups:** Operating with zero security budget, needing automated hygiene without enterprise platform fees.
3. **Open-Source Maintainers:** Seeking quick insight into whether their upstream dependencies are actively maintained or silently abandoned.

---

## 3. Core Value Proposition & Architectural Constraints
* **Holistic Risk Prioritization:** Combines open vulnerability advisories (OSV) with package vitality indicators (OpenSSF Scorecard via deps.dev).
* **Strict ₹0 Operating Budget:** Deployed on Cloudflare Workers and Cloudflare Pages with zero paid compute, zero paid databases, and zero domain expenses (using `*.workers.dev` and `*.pages.dev`).
* **Simplest Working Architecture:** A stateless, on-demand scanning engine for the initial proof-of-concept—eliminating database complexity and database costs completely in the first prototype.
* **Zero Source Code Ingestion:** Analyzes only dependency manifests and lockfiles (`package.json`, `requirements.txt`, etc.) via read-only GitHub API tokens. Never clones or stores proprietary application source code.
