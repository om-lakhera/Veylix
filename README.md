# Veylix

Veylix analyzes supported npm and Python dependency manifests, queries OSV for known vulnerability advisories, and can optionally enrich results with deps.dev/OpenSSF maintenance signals and FIRST.org EPSS plus CISA KEV data. It also provides JSON, SARIF, CycloneDX, SPDX, Markdown, and HTML reports, local scan history/comparison, and a local-only pattern-based secret scanner. Reports are informational and depend on the files parsed and upstream data available at scan time.

## Requirements

- Node.js 20 or newer.
- npm 9 or newer.
- A network connection for vulnerability lookup; optional maintenance checks also require deps.dev access.

No API keys, user account, database, or external paid service is configured by this repository. Hosting and upstream usage are subject to provider terms, limits, and possible costs; the project does not guarantee $0 hosting.

## Install and develop

```powershell
npm ci
npm run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`). The Vite development server includes the API middleware. `npm run preview` also includes this middleware, but is a local preview tool and not a production hosting service.

## Build, start, and test

```powershell
npm run build
npm test
npm start
```

`npm run build` type-checks and builds the web app into `dist/`, compiles the Node production server into `server-dist/`, and generates SEO files. `npm start` runs the compiled Node server and requires a completed build. The server exposes the web app and `/api/health`, `/api/scan`, and `/api/scan-github` on the same origin.

`npm test` runs deterministic unit and integration tests. `npm run test:live` contacts real upstream services and is intentionally separate; it may fail due to network availability, provider rate limits, or changed upstream data.

There is no configured lint or formatting script.

## CLI usage

Veylix exposes a command-line interface that reuses the same TypeScript scanning engine as the web app. The CLI reads a supported manifest or project directory, emits text, JSON, SARIF 2.1.0, CycloneDX 1.5, SPDX 2.3, Markdown, or self-contained HTML, and exits with a deterministic status code for automation.

```bash
# Scan a package-lock.json with a strict high-severity threshold
node ./bin/veylix.js scan --file ./package-lock.json --ecosystem npm --threshold high --format json

# Scan a Python requirements.txt project and fail only on low-or-worse advisories
node ./bin/veylix.js scan --file ./requirements.txt --ecosystem pypi --threshold low

# Export a GitHub Code Scanning-compatible SARIF report
node ./bin/veylix.js scan --file ./package-lock.json --format sarif > veylix.sarif

# Optional EPSS and CISA KEV enrichment for matching CVE identifiers
node ./bin/veylix.js scan --file ./package-lock.json --exploit-intel --format json

# Run the local-only secret pattern scanner; matched values are never printed
node ./bin/veylix.js secrets --path . --format json

# Discover and scan a local repository and its nested npm/Python projects
node ./bin/veylix.js repository scan --path . --format json
```

The repository command respects `.gitignore`, skips common generated directories and symbolic links, and accepts explicit exclusions and resource limits. It reports detected projects, languages, scan targets, normalized findings, and scanner diagnostics. Dependency vulnerability lookup uses the existing OSV integration; dependency identifiers and versions may be sent to OSV, but repository source files and secrets are not uploaded to Render. The repository foundation currently performs dependency vulnerability analysis for npm lockfiles and Python requirements/Poetry lockfiles; other detected ecosystems are reported as unsupported rather than treated as scanned. Dockerfiles may be discovered as configuration targets but are not scanned by this repository command. This is static local analysis, not DAST or live network probing.

Exit codes:

- `0`: scan succeeded and the configured threshold was not exceeded.
- `1`: scan succeeded, but a vulnerability met or exceeded the configured threshold.
- `2`: invalid arguments, missing input, or scanner execution failure.

Supported dependency inputs include a direct path to `package-lock.json`, `package.json` with a sibling lockfile, `requirements.txt`, `poetry.lock`, or a project directory containing one of those supported files. The secrets command scans regular local files with bounded file/byte/entry/finding limits and skips common generated and vendor directories. It reports paths, line numbers, rule IDs, and remediation guidance without including detected values; pattern matching can miss secrets and produce false positives. Dependency scanning does not execute repository code or shell commands: it parses static dependency files and sends package identifiers/versions to OSV, plus optional package-health and exploitation lookups only when enabled.

## GitHub Actions example

The repository includes a sample workflow in [`.github/workflows/veylix.yml`](./.github/workflows/veylix.yml). It checks out a project, installs dependencies, runs the local Veylix CLI on pushes, pull requests, and a weekly schedule, and fails the workflow when the configured vulnerability threshold is reached. It uses public OSV data and does not require a Veylix account. GitHub-hosted runner quotas and upstream rate limits still apply.

## Environment configuration

| Variable | Required | Purpose |
|---|---|---|
| `VITE_SITE_URL` | For production SEO URLs | Verified HTTPS origin, with no path, query, or fragment. Set at build time. It is used for canonical/Open Graph URLs and to generate `dist/sitemap.xml` and the sitemap line in `dist/robots.txt`. If unset, no canonical URLs or sitemap are generated. |
| `PORT` | Hosting-dependent | HTTP listen port; defaults to `3000`. |
| `HOST` | Hosting-dependent | Bind address; defaults to `127.0.0.1`. Container hosts generally require `0.0.0.0`. |

There are no configured secrets. Do not put credentials in `VITE_*` variables: Vite exposes these values to the browser bundle. `VITE_SITE_URL` is public metadata, not a secret.

## Production deployment

The production backend is a long-running Node.js HTTP server, not a static-only site or a preconfigured Cloudflare Worker/Pages function. It requires a Node-compatible host that can run the build output, keep the server process available, provide outbound HTTPS access, and route public HTTPS traffic to the process. The current audit target supplied by the operator is `https://veylix-0dzz.onrender.com/`; Render service settings are not stored in this repository.

1. Select a Node.js 20+ hosting environment and verify its current price, quotas, request duration, and outbound-network rules. Do not assume a free plan or unlimited usage.
2. Configure Render's build command as `npm ci && npm run build`. The packages required to compile and bundle the app are declared in `dependencies`, so this works even when Render sets `NODE_ENV=production` and omits `devDependencies`. Set `VITE_SITE_URL` to the actual verified HTTPS origin during this build if canonical URLs and a sitemap are desired.
3. Configure the start command as `npm start`; supply the platform's `PORT`. Set `HOST=0.0.0.0` when the host requires a container-wide bind. Terminate TLS at the host or its trusted reverse proxy and forward requests for both SPA paths and `/api/*` to this same process.
4. Verify `GET /api/health`, `GET /`, a direct deep link such as `/privacy`, `GET /robots.txt`, and `GET /sitemap.xml` when a production origin is configured. Submit a file scan only when approved for an external upstream lookup.
5. Retain the last known-good build/release according to the chosen provider and roll back by restoring that release if verification fails. Provider-specific release, backup, and retention controls must be configured by the operator.

The server limits JSON request bodies, supported manifest size, request receive time, headers, and active scans per process. Production scan POST requests are limited to 20 per minute per socket peer using an in-memory fixed window; the table is bounded and resets on restart. This is not an account system or a durable, distributed per-user limiter. The server intentionally does not trust forwarded client-IP headers; behind a proxy, multiple users may share the proxy's rate-limit bucket. Configure suitable edge limits for a multi-instance deployment and monitor upstream usage. The process-level concurrency and rate limits are not shared across instances.

Static assets receive cache headers; API responses are `no-store`. Scan API calls and external OSV, deps.dev, and GitHub requests require outbound connectivity. GitHub scanning only fetches supported dependency manifests from `raw.githubusercontent.com`, rejects redirects, and does not clone or execute repository code.

## Optional Render MCP

The workspace includes a VS Code MCP server entry for Render's hosted server in [`.vscode/mcp.json`](./.vscode/mcp.json). When prompted, authorize the Render account through VS Code's OAuth flow; no API key is stored in this repository. The server can perform actions such as changing service environment variables and triggering deploys, so review tool requests before approving them. See [Render's MCP documentation](https://render.com/docs/mcp-server) for details.

## Scanning, storage, and limitations

- Supported files: npm `package-lock.json` versions 1-3 (optional `package.json`); Python `requirements.txt`; Poetry `poetry.lock` (optional `pyproject.toml`).
- Upload limits: 5 MiB per manifest and 10 MiB total. Unsupported file combinations and malformed manifests are rejected.
- A failed required OSV lookup fails the scan; it is not represented as zero vulnerabilities. Optional maintenance signals may be unavailable and are reported separately.
- EPSS/KEV enrichment is opt-in. It sends CVE IDs to FIRST.org in bounded batches and downloads the CISA KEV catalog for local comparison; provider failures add warnings without suppressing OSV findings. The source dates/retrieval timestamps are provided where available. It is not a reachability analysis.
- OSV published and modified timestamps and scan-to-scan comparisons do not constitute a historical advisory archive. Veylix does not currently have complete advisory change tracking, package provenance, ownership-change, or malicious-package verification.
- The standalone secret scanner uses bounded local patterns. It is not a certified or exhaustive secrets scanner and currently does not scan Docker, Terraform, Kubernetes, license policy, or workflow security configuration.
- CLI output formats are generated without a schema-validator dependency. Check the generated output with the consuming platform’s current validator before relying on it in production pipelines.
- Scan history and reports are held in browser `localStorage` (up to 25 entries). They do not sync between devices and are not backed up server-side; clearing or eviction of browser data removes them. A completed report may be unavailable after reload if browser storage failed.
- No analytics or advertising cookies are configured. The cookie/storage dialog describes essential local report storage; it does not save fictitious optional-consent choices.
- The API does not intentionally persist manifests or scan history. Hosting providers and external upstream services may process request metadata or retain operational logs under their own policies. The browser dispatches minimal scan lifecycle custom events within the current page only; no analytics provider, listener, persistence, or event network destination is configured.
- No operator identity, private support/privacy contact, legal jurisdiction, Render service configuration, custom domain, backup policy, or legal approval is configured in this repository. Privacy/Terms are drafts and require owner confirmation and qualified legal review before public launch.
- Veylix does not guarantee complete advisory coverage, exploitability assessment, safe dependencies, or compatibility of suggested upgrades.

## Project documentation

- [Architecture](./docs/ARCHITECTURE.md), [HTTP API](./docs/API.md), and [detection methodology and limitations](./docs/DETECTION-METHODOLOGY.md).
- [Roadmap implementation plan](./docs/ROADMAP_IMPLEMENTATION.md) distinguishes shipped capabilities from deferred work.
- [Contributing](./CONTRIBUTING.md), [security reporting](./SECURITY.md), and [changelog](./CHANGELOG.md).
- [Deployment checklist](./docs/DEPLOYMENT_CHECKLIST.md) lists operator setup and outstanding configuration.

Other documents in [`docs/`](./docs/) may contain early research and architecture proposals. They are not active deployment configuration; references to Cloudflare quotas, future integrations, cost guarantees, or planned services should not be treated as capabilities of the current application.
