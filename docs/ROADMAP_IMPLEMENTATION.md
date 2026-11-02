# Product roadmap implementation plan

This plan reflects the current repository and its Node.js/Vite architecture. Existing scan APIs and CLI behavior remain the compatibility boundary. Capabilities are shipped only when the data source and behavior can be tested; unsupported coverage is called out rather than inferred.

## Repository baseline

Already implemented before this expansion:

- npm `package-lock.json` v1-v3 and Python `requirements.txt` / Poetry lock parsing.
- OSV batch vulnerability matching and advisory-derived fixed versions.
- Optional deps.dev/OpenSSF maintenance signals and deterministic aggregate risk scoring.
- Local browser scan history, finding comparison, safe remediation commands, and bounded dependency graph reconstruction.
- JSON and browser print/PDF flows, a text/JSON CLI, and an example GitHub Actions workflow.

## Milestones and current disposition

### 1. Vulnerability intelligence — partial

- Implement optional FIRST.org EPSS lookup by CVE and CISA KEV catalog matching. Provider failures produce explicit warnings and do not suppress OSV findings.
- Preserve OSV `published` and `modified` dates for per-advisory timelines.
- Reuse existing deps.dev publication/deprecation and OpenSSF Scorecard signals.
- Still deferred: current-version-to-latest release comparison, exploit reachability, historical advisory snapshots, package provenance, ownership-change evidence, and verified malicious-package classification. Current metadata does not reliably establish those claims.

### 2. Additional scanners — partial

- Implement a modular, local-only secret-pattern scanner in the CLI with bounded file/byte/entry/finding counts, ignored build/vendor directories, line-numbered evidence, and redacted values.
- Still deferred: Docker image/Dockerfile, GitHub Actions, Terraform, Kubernetes, general configuration, license-policy, and typosquatting scanners. Each requires format-specific rules and fixtures before it can be advertised as supported.

### 3. Scan management — partial

- Existing browser-local history, two-scan comparisons, stable advisory identifiers, and uncertainty labeling remain available.
- Still deferred: persistent annotations and expiring ignore rules, explicit baseline files, guaranteed incremental scans, and a first-class multi-project workspace. No server-side history is introduced.

### 4. Reports and integrations — partial

- Add SARIF 2.1.0, CycloneDX 1.5, SPDX 2.3, Markdown, and self-contained HTML generation, alongside existing JSON/text output and browser print-to-PDF.
- Preserve severity threshold exit behavior and schedule the repository's example scan weekly.
- Still deferred: generated-format validation against official schemas in CI, reusable CLI profile/config files, SARIF upload to Code Scanning, security badges, and a stable public API compatibility/versioning policy.

### 5. Platform capabilities — deferred

- The existing scanner continues to require live OSV access for vulnerability matching; optional intelligence remains independently disableable.
- Still deferred: a persistent/offline advisory cache, watch mode, custom rule authoring, plugin loading, and guarantees for reproducible outputs. No plugins are loaded, so extensions cannot bypass scanning.
- Existing request size/rate/concurrency controls and bounded local scanner are retained. More caching/performance work requires a specific stale-data and invalidation design.

### 6. Repository and documentation — in progress

- Maintain accurate README, FAQ/user guide, privacy copy, architecture, API, detection methodology, contribution/security guidance, changelog, issue templates, pull request template, and a draft-release workflow.
- Do not add fake badges, unsupported integrations, paid services, analytics, or fabricated coverage claims.

## Verification gates

For each implementation tranche:

1. Add focused tests for normal, malformed, adversarial, unavailable-provider, and resource-limit cases.
2. Keep the existing web, CLI, and API entry points backward-compatible unless a behavior change is explicit and tested.
3. Run `npm test -- --run`, `npm run build`, CLI help and relevant CLI command tests.
4. Inspect the final diff and `git diff --check`. Validate external output formats with a consumer/schema validator before claiming full standards conformance.

