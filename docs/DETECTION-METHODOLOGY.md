# Detection methodology and data limitations

Veylix separates confirmed advisory matches from maintenance signals and local secret-pattern heuristics.

## Dependency vulnerabilities

The parsers extract package names, ecosystems, and resolved or parser-derived versions from npm `package-lock.json` v1-v3, Python `requirements.txt`, or Poetry `poetry.lock`. OSV batch results are matched to those package versions. Severity, aliases, affected ranges, and fixed versions are taken from advisory data when present. A suggested fixed version is not a compatibility guarantee.

Python range requirements can be queried using a base version and produce parser warnings. Missing advisory data is not proof of safety. Required OSV request failures fail the scan.

## Exploitation intelligence (optional)

- FIRST.org EPSS is requested only for CVE identifiers present in advisory IDs or aliases. EPSS scores are probabilities and percentiles from the returned dataset; they are not a direct measure of exploitability in the scanned project.
- CISA KEV data is downloaded as a public catalog and compared locally by CVE ID. A match means that CISA lists the CVE as known exploited; absence from the catalog is not proof that no exploit exists.
- Results include upstream data dates and retrieval timestamps where available. Provider errors and response bounds are surfaced as warnings.
- The feature is disableable. It does not perform code reachability or exploit testing.

## Maintenance and package-health indicators

Optional deps.dev/OpenSSF data can include release dates, deprecation information, and Scorecard metrics. These are maintenance/supply-chain risk indicators, not vulnerabilities. A long release interval or missing Scorecard does not prove abandonment or malicious behavior. The aggregate Veylix risk score is a deterministic prioritization heuristic, not a probability.

## Dependency relationships

The explorer reconstructs relationships only from exact package-name/version paths supplied by the existing parsers. Ambiguous, unsupported, or missing path data is not inferred. Cycle detection and graph traversal are bounded.

## Local secret-pattern scanner

`veylix secrets` runs locally and makes no network requests. It looks for a small set of private-key markers and common credential patterns. It scans regular files under bounded file, depth, entry, byte, and finding limits; skips common generated/vendor directories and symbolic links; and reports only rule, path, line, severity, and remediation. Matched values are never included in findings or logs.

This scanner can miss credentials and can flag examples or non-secret strings. It is not a substitute for provider-specific scanners or a manual review. No Docker image/Dockerfile, workflow, Terraform, Kubernetes, configuration, license policy, typosquatting, provenance, maintainer-history, or malicious-package scanner is currently claimed.

## History

Scan history and comparisons remain local to the browser. Comparison uses advisory aliases and package identity and marks ambiguous or missing identifiers as uncertain. OSV `published`/`modified` timestamps are metadata supplied by the current response; Veylix does not keep a historical advisory archive or claim to detect every advisory change.

