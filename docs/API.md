# HTTP API

The production server and Vite development middleware expose the same-origin JSON endpoints.

## `GET /api/health`

Returns basic process status, version, and supported dependency ecosystems. It does not check whether OSV, deps.dev, FIRST.org, CISA, or GitHub are available.

## `POST /api/scan`

Submit one supported manifest combination:

```json
{
  "packageLockJson": "{\"lockfileVersion\":3,\"packages\":{}}",
  "packageJson": "{\"name\":\"sample\",\"dependencies\":{}}",
  "fetchMaintenanceHealth": false,
  "fetchExploitIntelligence": false
}
```

Supported input fields are `packageJson`, `packageLockJson`, `requirementsTxt`, `poetryLock`, `pyprojectToml`, and the two optional boolean enrichment flags. npm requires `package-lock.json`; Python accepts `requirements.txt` or `poetry.lock`. Current limits are 5 MiB per manifest, 10 MiB combined manifest contents, and 21 MiB serialized request size.

## `POST /api/scan-github`

```json
{
  "repoUrl": "owner/repository",
  "fetchMaintenanceHealth": false,
  "fetchExploitIntelligence": false
}
```

Only public GitHub repositories and supported manifest files are retrieved. The scanner does not clone or execute repository code.

## Responses and failure behavior

Successful scan responses contain `success`, `target`, and `report`. Rejected inputs and upstream OSV failures return a non-success response with a safe error message. Optional enrichment failures are represented as `report.warnings`; they do not convert required OSV failures into success or hide OSV findings. API responses use `Cache-Control: no-store`.

The endpoints are same-origin and do not provide authentication, a versioned external API contract, persistent project storage, or a stability guarantee. Rate limits and proxy considerations are described in the deployment checklist.

