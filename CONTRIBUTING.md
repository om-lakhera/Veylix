# Contributing to Veylix

## Development setup

- Use Node.js 20 or newer and npm.
- Run `npm ci`, then `npm run dev` for local development.
- Run `npm test -- --run` and `npm run build` before submitting changes.
- `npm run test:live` contacts public upstream APIs and is not required for deterministic local tests.

## Change expectations

- Preserve the existing public scan API, npm/Python scanning behavior, and CLI commands.
- Add focused tests for new behavior, including malformed input, resource bounds, and upstream failures where relevant.
- Keep vulnerability findings separate from maintenance heuristics and other risk indicators.
- Do not claim a format or scanner is supported until it has working implementation and tests.
- Never include real credentials, private manifests, or sensitive repository data in issues, fixtures, logs, or test output.
- Do not add paid services, analytics, accounts, databases, or runtime dependencies without a clear need and review.
- Update README, methodology, privacy, and user-facing documentation when behavior or data flows change.

## Security-sensitive contributions

Do not post exploit details, credentials, private dependency files, or personal data in a public issue. Follow [SECURITY.md](./SECURITY.md) for reporting guidance.

