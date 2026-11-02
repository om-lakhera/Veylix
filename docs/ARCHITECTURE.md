# Architecture

## Runtime shape

Veylix is a TypeScript application with a React/Vite browser client and a Node.js HTTP production server. The server serves the built SPA and same-origin `/api/*` endpoints. The Vite development server exposes the same API handler through middleware. The browser has an existing file-scan fallback when the same-origin scan API is unavailable; public GitHub scans require the server API.

## Dependency scan flow

1. The browser uploads supported lock/manifests or submits a public GitHub reference.
2. The server validates allowed payload keys and enforces serialized-request and per-manifest size bounds.
3. Parsers resolve supported npm/Python package names, versions, direct/development status, and any reliable dependency paths.
4. The engine submits package/version batches to OSV. A failed required OSV request fails the scan; it is not represented as a clean result.
5. Optional deps.dev/OpenSSF maintenance data and optional FIRST.org EPSS/CISA KEV data are joined to findings as distinct signals.
6. Results are returned to the browser and optionally saved in browser `localStorage`; no server-side report database exists.

## Main modules

- `src/parser.ts`, `src/python-parser.ts`: bounded npm lockfile, requirements, and Poetry parsing.
- `src/osv-client.ts`: OSV batch matching and advisory transformation.
- `src/deps-client.ts`: optional package-health and Scorecard signals.
- `src/exploit-intel-client.ts`: optional EPSS and KEV lookups, with bounded response sizes and per-scan CVE limits.
- `src/engine.ts`: shared analysis pipeline and report assembly.
- `src/server/`: API validation, GitHub manifest fetch, rate limiting, Vite integration, and production HTTP host.
- `src/web/`: SPA routes, scan UI, local history/comparison, remediation, dependency paths, and exports.
- `src/cli.ts`: command parsing, deterministic vulnerability thresholds, local manifest reads, export formats, and the standalone secret scanner command.

## Data retention and outbound calls

Manifest contents are processed by the same-origin API or browser fallback to extract package identifiers. OSV receives package names/ecosystems/versions. deps.dev receives package identifiers only when maintenance enrichment is enabled. FIRST.org receives only matching CVE identifiers when exploitability enrichment is enabled; the CISA KEV catalog is downloaded and filtered locally. Public GitHub scans retrieve only supported manifest files from raw-content hosting. See [API documentation](./API.md), [detection methodology](./DETECTION-METHODOLOGY.md), and the in-app privacy policy for details and limitations.

## Explicit non-goals for current implementation

There is no account system, cloud scan-history service, plugin loader, offline advisory database, recursive source-code execution, or private repository token integration. Dependency edges are displayed only when exact package/version relationships are available from parser paths. Unsupported scanners must not be inferred from inventory data.

