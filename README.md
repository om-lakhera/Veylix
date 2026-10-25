# Veylix

Veylix analyzes supported npm and Python dependency manifests, queries OSV for known vulnerability advisories, and can optionally request maintenance signals from deps.dev. Reports are informational and depend on the files parsed and upstream data available at scan time.

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

## Environment configuration

| Variable | Required | Purpose |
|---|---|---|
| `VITE_SITE_URL` | For production SEO URLs | Verified HTTPS origin, with no path, query, or fragment. Set at build time. It is used for canonical/Open Graph URLs and to generate `dist/sitemap.xml` and the sitemap line in `dist/robots.txt`. If unset, no canonical URLs or sitemap are generated. |
| `PORT` | Hosting-dependent | HTTP listen port; defaults to `3000`. |
| `HOST` | Hosting-dependent | Bind address; defaults to `127.0.0.1`. Container hosts generally require `0.0.0.0`. |

There are no configured secrets. Do not put credentials in `VITE_*` variables: Vite exposes these values to the browser bundle. `VITE_SITE_URL` is public metadata, not a secret.

## Production deployment

The production backend is a long-running Node.js HTTP server, not a static-only site or a preconfigured Cloudflare Worker/Pages function. Select a Node-compatible host that can run the build output, keep the server process available, provide outbound HTTPS access, and route public HTTPS traffic to the process. No hosting provider or domain is selected/configured here, and no deployment has been performed.

1. Select a Node.js 20+ hosting environment and verify its current price, quotas, request duration, and outbound-network rules. Do not assume a free plan or unlimited usage.
2. Configure Render's build command as `npm install && npm run build`. The packages required to compile and bundle the app are declared in `dependencies`, so this works even when Render sets `NODE_ENV=production` and omits `devDependencies`. Set `VITE_SITE_URL` to the actual verified HTTPS origin during this build if canonical URLs and a sitemap are desired.
3. Configure the start command as `npm start`; supply the platform's `PORT`. Set `HOST=0.0.0.0` when the host requires a container-wide bind. Terminate TLS at the host or its trusted reverse proxy and forward requests for both SPA paths and `/api/*` to this same process.
4. Verify `GET /api/health`, `GET /`, a direct deep link such as `/privacy`, `GET /robots.txt`, and `GET /sitemap.xml` when a production origin is configured. Submit a file scan only when approved for an external upstream lookup.
5. Retain the last known-good build/release according to the chosen provider and roll back by restoring that release if verification fails. Provider-specific release, backup, and retention controls must be configured by the operator.

The server limits JSON request bodies, supported manifest size, request receive time, headers, and active scans per process. It is not an account system and has no durable, distributed per-user rate limiter. If exposing the API publicly, configure suitable request/rate limits at a trusted hosting edge or reverse proxy and monitor upstream usage. The process-level concurrency limit does not protect multiple server instances as one shared quota.

Static assets receive cache headers; API responses are `no-store`. Scan API calls and external OSV, deps.dev, and GitHub requests require outbound connectivity. GitHub scanning only fetches supported dependency manifests from `raw.githubusercontent.com`, rejects redirects, and does not clone or execute repository code.

## Optional Render MCP

The workspace includes a VS Code MCP server entry for Render's hosted server in [`.vscode/mcp.json`](./.vscode/mcp.json). When prompted, authorize the Render account through VS Code's OAuth flow; no API key is stored in this repository. The server can perform actions such as changing service environment variables and triggering deploys, so review tool requests before approving them. See [Render's MCP documentation](https://render.com/docs/mcp-server) for details.

## Scanning, storage, and limitations

- Supported files: npm `package-lock.json` versions 1-3 (optional `package.json`); Python `requirements.txt`; Poetry `poetry.lock` (optional `pyproject.toml`).
- Upload limits: 5 MiB per manifest and 10 MiB total. Unsupported file combinations and malformed manifests are rejected.
- A failed required OSV lookup fails the scan; it is not represented as zero vulnerabilities. Optional maintenance signals may be unavailable and are reported separately.
- Scan history and reports are held in browser `localStorage` (up to 25 entries). They do not sync between devices and are not backed up server-side; clearing or eviction of browser data removes them. A completed report may be unavailable after reload if browser storage failed.
- No analytics or advertising cookies are configured. The cookie/storage dialog describes essential local report storage; it does not save fictitious optional-consent choices.
- The API does not intentionally persist manifests or scan history. Hosting providers and external upstream services may process request metadata or retain operational logs under their own policies.
- No operator identity, support email, legal jurisdiction, hosting provider, production domain, backup policy, or legal approval is configured. Privacy/Terms are drafts and require owner confirmation and qualified legal review before public launch.
- Veylix does not guarantee complete advisory coverage, exploitability assessment, safe dependencies, or compatibility of suggested upgrades.

## Project documentation

The files in [`docs/`](./docs/) include early research and architecture proposals. They are not active deployment configuration; in particular, references to Cloudflare quotas, future integrations, cost guarantees, or planned services should not be treated as capabilities of the current application.

See [`docs/DEPLOYMENT_CHECKLIST.md`](./docs/DEPLOYMENT_CHECKLIST.md) for the pre-deployment steps and outstanding configuration.
