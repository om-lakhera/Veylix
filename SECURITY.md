# Security policy

## Scope

Veylix is an informational dependency scanner. Its web server accepts supported npm and Python manifests and can fetch supported manifests from public GitHub repositories. The local CLI also includes a pattern-based secret scanner. No scanner should be treated as exhaustive.

## Reporting a vulnerability

Please do not report an unpatched vulnerability, credential, private manifest, or exploit details in a public issue. Use GitHub's private vulnerability reporting feature for this repository if it is available. If private reporting is unavailable, contact the repository maintainers through GitHub and request a private reporting channel before sharing technical details.

Include only the minimum information needed to reproduce the issue. Redact credentials, personal information, and private repository names. Do not test against systems you do not own or have permission to assess.

## Security design notes

- The server bounds request and manifest sizes, scan concurrency, and scan request rates per process.
- GitHub scanning is restricted to public manifest files and does not clone or execute repository code.
- The dependency scanner sends package identifiers and versions to OSV; optional integrations have separate data flows described in the Privacy Policy and detection methodology.
- Scan reports/history are browser-local. The server does not intentionally persist reports.
- Secret-scanner evidence never contains the matched credential value. Its pattern coverage is incomplete and may produce false positives.
- There is no configured private contact address or guaranteed response-time commitment. Hosting logs and retention are controlled by the operator/provider.

