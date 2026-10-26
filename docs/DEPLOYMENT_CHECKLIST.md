# Veylix Deployment Checklist

Do not deploy until the blockers below are resolved. This checklist describes the current Node server; it does not select a host or create infrastructure.

## Hosting options and required decisions

This application is not a static-only front end. It requires a long-lived Node.js 20+ process to serve the built `dist/` assets and the production API (`/api/*`). A static host with no server runtime cannot support GitHub repository scanning or dependency file submission as implemented.

The most suitable production options are:

- [ ] Render: strong Node service support, easy `npm start` deployment, container or web service model, but free-tier availability and longevity vary by plan and region. Good fit when you want a straightforward Node service with explicit start commands.
- [ ] Google Cloud Run: good for long-lived containerized services, autoscaling, and production logging; requires a Google Cloud project and billing configuration. Best fit when you need stronger infrastructure controls and can accept more setup work.
- [ ] Railway: straightforward deployment and Node runtime support, but free/trial limits and quota terms must be checked before launch. Good fit for prototyping and smaller production workloads when the provider's limits are acceptable.
- [ ] A provider with an explicit custom Node runtime and outbound HTTPS access: acceptable if it supports process persistence, TLS termination, and the existing server contract. Do not use a static-only host for production API scanning.

The current audit target supplied by the operator is `https://veylix-0dzz.onrender.com/`. This repository does not contain Render service or DNS configuration, so verify the service settings in Render before the next deployment.

## Required before the first public release

- [ ] Select a Node.js 20+ host that runs a long-lived HTTP process, supports the required request duration, and permits outbound HTTPS to public GitHub manifests, OSV, and deps.dev.
- [ ] Verify the host's current price, quotas, API/request limits, logging, TLS, release rollback, and availability terms. $0 hosting is not guaranteed.
- [ ] Configure the verified production HTTPS origin as build-time `VITE_SITE_URL`. If the domain is not known, canonical URLs and a sitemap remain intentionally absent.
- [ ] Configure runtime `PORT`. With `NODE_ENV=production` or a platform-provided `PORT`, the server defaults to `HOST=0.0.0.0`; set `HOST` explicitly if the host requires another bind address. Ensure HTTPS terminates at the host or trusted proxy and forwards SPA and `/api/*` requests to the same Node process.
- [ ] Configure an edge/reverse-proxy request rate limit for the public scan API. The app also limits scan POSTs to 20/minute per socket peer in an in-memory, bounded per-process table; it resets on restart, is not distributed, and may group users behind the same proxy because forwarded IP headers are not trusted.
- [ ] Provide the operator identity, support contact, jurisdiction, effective dates, retention/logging details, and have Privacy/Terms reviewed by qualified counsel. Do not invent these values.
- [ ] Decide operational recovery expectations. Scan history is only in each user's browser `localStorage`; the service has no server-side report backup or restore mechanism.

## Build and test before release

From the repository root, in PowerShell:

```powershell
npm ci
$env:VITE_SITE_URL = 'https://<verified-production-origin>'
npm run build
npm test
npm audit
```

Replace the example with the actual verified origin; do not publish the placeholder. `npm run build` emits `dist/`, `server-dist/`, `dist/robots.txt`, and a domain-specific `dist/sitemap.xml`. `npm test` is deterministic; `npm run test:live` uses external services and is optional, not a substitute for deterministic tests.

There is no configured lint or formatting command. The build includes TypeScript checks for the client and production server.

## Configure and launch

1. For Render, use `npm ci && npm run build` as the build command. Packages required to compile and bundle the app are declared in `dependencies`, so they remain installed when `NODE_ENV=production` omits `devDependencies`. Set the production `VITE_SITE_URL` during the build; it is public metadata and must not contain secrets.
2. Start with `npm start` and pass the platform `PORT`. The server defaults to `0.0.0.0` when `NODE_ENV=production` or `PORT` is supplied, and remains on loopback for local development. No other application credentials or environment variables are currently required.
3. Route TLS-protected public requests to this process. Do not deploy only `dist/` to a static host if GitHub scans are required; this app needs the Node API server.
4. Check `GET /api/health` and `GET /` after process startup. The health response confirms the API process responds, not the availability of upstream scan providers.
5. Check direct navigation/refresh for `/new-scan`, `/privacy`, `/terms`, `/cookies`, `/support`, and a valid-format `/scans/<id>` route.
6. Check `robots.txt`, parse `sitemap.xml`, confirm sitemap URLs use only the actual origin, and confirm scan history/results/settings are `noindex`.
7. Review host logs and test a bounded file scan with an approved manifest. Confirm upstream failure is surfaced as a failed scan, not a clean result.
8. If any check fails, stop promotion and restore the previous known-good release using the selected provider's rollback mechanism. Keep provider-specific rollback commands with the operator runbook.

## Known constraints

- No hosting platform, production domain, deployment credentials, TLS configuration, or automated deployment pipeline is configured in this repository.
- The production server is a single-process Node HTTP server. Host scaling, durable distributed rate limiting, platform health-check policy, and process supervision must be configured by the operator.
- Scan reports are stored in browser storage only and cannot be recovered by the service if cleared or evicted.
- Public API usage can consume upstream quotas. Monitor the chosen provider and configure edge-level request limits before exposing scan endpoints.
- The legal pages are drafts, not evidence of legal compliance. Public launch requires owner and counsel review.
