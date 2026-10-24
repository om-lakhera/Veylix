# Veylix: Project Brief

## Executive Summary
**Veylix** is a developer-centric dependency health and prioritization SaaS for GitHub repositories. Rather than bombarding engineering teams with dozens of disconnected pull requests and low-signal vulnerability alerts, Veylix analyzes dependency health holistically—synthesizing known security vulnerabilities (CVEs/GHSA), project maintenance vitality (commit velocity, bus factor, release cadence), and supply chain hygiene into a single actionable triage stream.

---

## 1. Problem Statement
Modern software engineering teams face severe **alert fatigue** and **maintenance blindspots**:
- **Notification Overload:** Standard dependency bots (like unconfigured Dependabot) open fragmented PRs for every patch, resulting in maintainers ignoring or deferring updates.
- **CVE Bias:** Traditional vulnerability scanners (like OSV-Scanner or basic SCA tools) only trigger on existing, registered CVEs. They miss unmaintained, abandoned, or single-maintainer dependencies until a vulnerability or supply chain compromise has already occurred.
- **Lack of Actionable Prioritization:** Developers lack contextual prioritization: *Which dependency update actually requires immediate intervention today versus which can safely wait for the next scheduled sprint?*

---

## 2. Target Audience
1. **GitHub Repository Maintainers & Tech Leads:** Need a clear picture of project dependencies without drowning in bot PRs.
2. **Small-to-Mid Sized Engineering Teams:** Cannot afford six-figure enterprise AppSec suites (e.g., Snyk Enterprise) but require intelligent security and dependency risk governance.
3. **Open-Source Maintainers:** Want automated visibility into whether the libraries they rely on are being actively maintained or silently abandoned.

---

## 3. Core Value Proposition
* **Holistic Health Scoring:** Merges security advisories (OSV/GHSA) with real-world maintenance signals (OpenSSF Scorecard via deps.dev).
* **Prioritized Triage Queue:** Answers "What should I fix first?" using risk-weighted scoring (e.g., Critical CVE in an Abandoned Library > High CVE in an Actively Maintained Library with Safe Patch > Stale Dependency with No Known CVE).
* **Zero Source Code Ingestion:** Analyzes only dependency manifests and lockfiles, ensuring strict code privacy and swift onboarding via a standard GitHub App.
