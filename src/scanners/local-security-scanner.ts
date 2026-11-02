import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseNpmManifests } from '../parser.js';
import { parsePoetryLock, parseRequirementsTxt, canonicalizePythonPackageName } from '../python-parser.js';
import { scanSecretContent } from './secret-scanner.js';

export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type SecurityConfidence = 'confirmed' | 'heuristic';

export interface SecurityFinding {
  id: string;
  ruleId: string;
  scanner: 'secrets' | 'dockerfile' | 'docker-image' | 'github-actions' | 'configuration' | 'terraform' | 'kubernetes' | 'license' | 'typosquatting' | 'custom';
  title: string;
  severity: SecuritySeverity;
  confidence: SecurityConfidence;
  filePath?: string;
  lineNumber?: number;
  packageName?: string;
  evidence: string;
  remediation: string;
}

export interface SecurityScanResult {
  target: string;
  findings: SecurityFinding[];
  warnings: string[];
  filesScanned: number;
  bytesScanned: number;
}

export interface DeclarativeRule {
  id: string;
  title: string;
  severity: SecuritySeverity;
  contains: string;
  extensions?: string[];
  remediation: string;
}

export interface LocalSecurityScanOptions {
  maxFiles?: number;
  maxDepth?: number;
  maxFileSizeBytes?: number;
  maxTotalBytes?: number;
  maxEntries?: number;
  maxFindings?: number;
  allowedLicenses?: string[];
  customRules?: DeclarativeRule[];
  discoveredFiles?: string[];
  signal?: AbortSignal;
}

export interface DockerImageInspection {
  image: string;
  user?: string;
  healthcheck?: unknown;
  exposedPorts?: string[];
  envNames?: string[];
}

const DEFAULT_MAX_FILES = 20_000;
const DEFAULT_MAX_DEPTH = 24;
const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 100 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_MAX_FINDINGS = 20_000;
const MAX_RULE_FILE_BYTES = 256 * 1024;
const EXCLUDED_DIRS = new Set([
  '.git', '.hg', '.svn', '.next', '.cache', 'node_modules', 'vendor', 'venv', '.venv',
  '__pycache__', 'dist', 'build', 'coverage', '.terraform'
]);
const TEXT_EXTENSIONS = new Set([
  '.json', '.yaml', '.yml', '.toml', '.tf', '.tfvars', '.hcl', '.conf', '.ini', '.env',
  '.properties', '.xml', '.cfg', '.config', '.dockerfile', '.txt'
]);
const WORKFLOW_PATH = /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i;
const DOCKERFILE_NAME = /^(?:dockerfile(?:\..*)?|containerfile)$/i;
const KNOWN_PACKAGES = [
  'react', 'react-dom', 'lodash', 'express', 'axios', 'request', 'webpack', 'vite',
  'typescript', 'next', 'chalk', 'debug', 'minimist', 'commander', 'urllib3', 'requests',
  'django', 'flask', 'numpy', 'pandas', 'pytest', 'fastapi', 'pydantic', 'cryptography'
];
const findingIds = new WeakMap<SecurityFinding[], Set<string>>();

function stableId(parts: string[]): string {
  return parts.map((part) => part.trim().toLowerCase()).join('|');
}

function normalizeExtension(extension: string): string {
  return extension.startsWith('.') ? extension.toLowerCase() : `.${extension.toLowerCase()}`;
}

export function validateDeclarativeRules(value: unknown): DeclarativeRule[] {
  if (!Array.isArray(value) || value.length > 200) {
    throw new Error('Custom rules must be a JSON array containing no more than 200 rules.');
  }
  const ids = new Set<string>();
  return value.map((rule, index) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      throw new Error(`Custom rule ${index + 1} must be an object.`);
    }
    const candidate = rule as Record<string, unknown>;
    const { id, title, severity, contains, extensions, remediation } = candidate;
    if (typeof id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/.test(id) || ids.has(id)) {
      throw new Error(`Custom rule ${index + 1} has an invalid or duplicate id.`);
    }
    if (typeof title !== 'string' || title.trim().length === 0 || title.length > 160) {
      throw new Error(`Custom rule ${index + 1} must include a title of 1 to 160 characters.`);
    }
    if (!['critical', 'high', 'medium', 'low', 'info'].includes(String(severity))) {
      throw new Error(`Custom rule ${index + 1} has an unsupported severity.`);
    }
    if (typeof contains !== 'string' || contains.trim().length < 3 || contains.length > 256) {
      throw new Error(`Custom rule ${index + 1} must use a literal contains value of 3 to 256 characters.`);
    }
    if (typeof remediation !== 'string' || remediation.trim().length === 0 || remediation.length > 500) {
      throw new Error(`Custom rule ${index + 1} must include remediation of 1 to 500 characters.`);
    }
    if (extensions !== undefined && (
      !Array.isArray(extensions) ||
      extensions.length > 20 ||
      !extensions.every((extension) => typeof extension === 'string' && /^\.[a-zA-Z0-9]{1,12}$/.test(extension))
    )) {
      throw new Error(`Custom rule ${index + 1} contains invalid file extensions.`);
    }
    ids.add(id);
    return {
      id,
      title: title.trim(),
      severity: severity as SecuritySeverity,
      contains,
      ...(Array.isArray(extensions) ? { extensions: extensions.map((extension) => normalizeExtension(extension as string)) } : {}),
      remediation: remediation.trim()
    };
  });
}

export function loadDeclarativeRules(filePath: string): DeclarativeRule[] {
  const resolvedPath = path.resolve(filePath);
  const stats = fs.statSync(resolvedPath);
  if (!stats.isFile() || stats.size > MAX_RULE_FILE_BYTES) {
    throw new Error('Custom rules file must be a regular file no larger than 256 KiB.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'));
  } catch {
    throw new Error('Custom rules file must contain valid JSON.');
  }
  return validateDeclarativeRules(parsed);
}

function classify(relativePath: string): SecurityFinding['scanner'] {
  if (WORKFLOW_PATH.test(relativePath)) return 'github-actions';
  if (DOCKERFILE_NAME.test(path.basename(relativePath))) return 'dockerfile';
  if (/\.(?:tf|tfvars?)$/i.test(relativePath) || /\.hcl$/i.test(relativePath)) return 'terraform';
  if (/k8s|kube|kubernetes/i.test(relativePath) && /\.(?:yaml|yml|json)$/i.test(relativePath)) return 'kubernetes';
  return 'configuration';
}

function addFinding(
  findings: SecurityFinding[],
  scanner: SecurityFinding['scanner'],
  ruleId: string,
  title: string,
  severity: SecuritySeverity,
  confidence: SecurityConfidence,
  filePath: string | undefined,
  lineNumber: number | undefined,
  evidence: string,
  remediation: string,
  packageName?: string,
  maxFindings = DEFAULT_MAX_FINDINGS
): void {
  if (findings.length >= maxFindings) return;
  const id = stableId([scanner, ruleId, filePath ?? '', packageName ?? '', evidence]);
  let seen = findingIds.get(findings);
  if (!seen) {
    seen = new Set<string>();
    findingIds.set(findings, seen);
  }
  if (seen.has(id)) return;
  seen.add(id);
  findings.push({
    id,
    ruleId,
    scanner,
    title,
    severity,
    confidence,
    ...(filePath ? { filePath } : {}),
    ...(lineNumber !== undefined ? { lineNumber } : {}),
    ...(packageName ? { packageName } : {}),
    evidence,
    remediation
  });
}

function scanDockerfile(
  relativePath: string,
  lines: string[],
  findings: SecurityFinding[],
  maxFindings: number
): void {
  const fromLines: number[] = [];
  let hasUser = false;
  let hasHealthcheck = false;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!.trim();
    if (!line || line.startsWith('#')) continue;
    const from = line.match(/^FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+\S+)?/i);
    if (from) {
      fromLines.push(index + 1);
      if (from[1]!.toLowerCase() !== 'scratch' &&
        (from[1]!.split('@')[0]!.split(':').at(-1)?.toLowerCase() === 'latest' || !from[1]!.includes(':'))) {
        addFinding(findings, 'dockerfile', 'docker.base-floating-tag', 'Base image uses a floating tag', 'medium', 'heuristic', relativePath, index + 1, 'Base image tag is latest or omitted', 'Pin the base image to a reviewed immutable digest or specific version tag.', undefined, maxFindings);
      }
    }
    if (/^USER\s+\S+/i.test(line)) {
      hasUser = true;
      if (/^USER\s+(?:0|root)(?:\s|$)/i.test(line)) {
        addFinding(findings, 'dockerfile', 'docker.root-user', 'Container explicitly runs as root', 'high', 'confirmed', relativePath, index + 1, 'USER selects root', 'Create and select a dedicated non-root user for the workload.', undefined, maxFindings);
      }
    }
    if (/^HEALTHCHECK\b/i.test(line)) hasHealthcheck = true;
    if (/^ADD\s+https?:\/\//i.test(line)) {
      addFinding(findings, 'dockerfile', 'docker.add-remote', 'Remote content is added during image build', 'medium', 'confirmed', relativePath, index + 1, 'ADD references a remote URL', 'Fetch and verify remote artifacts explicitly, including checksums/signatures, before copying them into the image.', undefined, maxFindings);
    }
    if (/^RUN\b.*\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b/i.test(line)) {
      addFinding(findings, 'dockerfile', 'docker.pipe-to-shell', 'Downloaded content is piped directly to a shell', 'high', 'confirmed', relativePath, index + 1, 'RUN pipes a network downloader into a shell', 'Pin and verify downloaded installer content before executing it.', undefined, maxFindings);
    }
  }
  if (fromLines.length === 0) {
    addFinding(findings, 'dockerfile', 'docker.no-base-image', 'No FROM instruction found', 'medium', 'heuristic', relativePath, 1, 'No FROM instruction found', 'Confirm this is an intentional scratch or generated Dockerfile.', undefined, maxFindings);
  }
  if (!hasUser && fromLines.length > 0) {
    addFinding(findings, 'dockerfile', 'docker.user-unspecified', 'Container user is not specified', 'medium', 'heuristic', relativePath, undefined, 'No USER instruction found', 'Use USER to run the application as a dedicated non-root account.', undefined, maxFindings);
  }
  if (!hasHealthcheck && fromLines.length > 0) {
    addFinding(findings, 'dockerfile', 'docker.healthcheck-missing', 'No container health check is defined', 'low', 'heuristic', relativePath, undefined, 'No HEALTHCHECK instruction found', 'Add a health check when the image is intended to run as a service.', undefined, maxFindings);
  }
}

function scanWorkflow(
  relativePath: string,
  lines: string[],
  findings: SecurityFinding[],
  maxFindings: number
): void {
  const hasPermissions = lines.some((line) => /^\s*permissions\s*:/i.test(line));
  const pullRequestTargetLine = lines.findIndex((line) => /^\s*pull_request_target\s*:/i.test(line));
  if (!hasPermissions) {
    addFinding(findings, 'github-actions', 'actions.permissions-unspecified', 'Workflow permissions are not explicitly restricted', 'medium', 'heuristic', relativePath, undefined, 'No permissions block found', 'Declare the minimum required workflow permissions, preferably read-only.', undefined, maxFindings);
  }
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!.trim();
    const uses = line.match(/\buses:\s*([^\s#]+)/i);
    if (uses && !uses[1]!.includes('@')) {
      addFinding(findings, 'github-actions', 'actions.reference-unpinned', 'Action reference is not pinned', 'medium', 'confirmed', relativePath, index + 1, 'Action uses a branch/tag without a full commit SHA', 'Pin third-party actions to a verified full commit SHA and document the upstream version.', undefined, maxFindings);
    } else if (uses && !/@[a-f0-9]{40}(?:\s|$)/i.test(uses[1]!)) {
      addFinding(findings, 'github-actions', 'actions.reference-not-sha-pinned', 'Action reference is not pinned to a full commit SHA', 'medium', 'heuristic', relativePath, index + 1, 'Action reference does not use a 40-character commit SHA', 'Pin the action to a verified full commit SHA.', undefined, maxFindings);
    }
    if (/^\s*permissions\s*:\s*write-all\b/i.test(line)) {
      addFinding(findings, 'github-actions', 'actions.write-all', 'Workflow grants write-all permissions', 'high', 'confirmed', relativePath, index + 1, 'permissions: write-all', 'Replace write-all with the smallest required per-scope permissions.', undefined, maxFindings);
    }
    if (/\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/.test(line) && /^\s*run\s*:/i.test(line)) {
      addFinding(findings, 'github-actions', 'actions.secret-in-shell', 'Secret is interpolated directly into a shell command', 'high', 'heuristic', relativePath, index + 1, 'run step interpolates a secret expression', 'Pass secrets through an environment variable and quote/validate their use; avoid shell interpolation.', undefined, maxFindings);
    }
    if (pullRequestTargetLine >= 0 && /actions\/checkout@/i.test(line)) {
      const checkoutBlock = lines.slice(Math.max(pullRequestTargetLine, index - 8), Math.min(lines.length, index + 12)).join('\n');
      if (/ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)/i.test(checkoutBlock)) {
        addFinding(findings, 'github-actions', 'actions.pull-request-target-checkout', 'Privileged pull_request_target workflow checks out untrusted PR code', 'critical', 'heuristic', relativePath, index + 1, 'pull_request_target workflow checks out the pull request head', 'Do not execute untrusted pull request code in a privileged pull_request_target workflow. Use pull_request or isolate privileged actions.', undefined, maxFindings);
      }
    }
  }
}

function scanConfigLine(
  relativePath: string,
  lines: string[],
  scanner: SecurityFinding['scanner'],
  findings: SecurityFinding[],
  maxFindings: number
): void {
  let configKind: 'kubernetes' | 'terraform' | 'configuration' = scanner === 'kubernetes' || scanner === 'terraform' ? scanner : 'configuration';
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const patterns: Array<[RegExp, string, string, SecuritySeverity, SecurityConfidence, string]> = [
      [/^(?:privileged|allowPrivilegeEscalation)\s*:\s*true\b/i, `${configKind}.privileged`, 'Privileged workload setting enabled', 'high', 'confirmed', 'Disable privileged mode and grant only the required capabilities.'],
      [/^(?:runAsNonRoot|run_as_non_root)\s*:\s*false\b/i, `${configKind}.run-as-root`, 'Workload permits root execution', 'high', 'confirmed', 'Require the workload to run as a non-root identity.'],
      [/^(?:hostNetwork|host_network)\s*:\s*true\b/i, `${configKind}.host-network`, 'Workload shares the host network namespace', 'high', 'confirmed', 'Disable host networking unless explicitly required and reviewed.'],
      [/^(?:readOnlyRootFilesystem|read_only_root_filesystem)\s*:\s*false\b/i, `${configKind}.writable-root-filesystem`, 'Root filesystem is writable', 'medium', 'confirmed', 'Use a read-only root filesystem and mount explicit writable paths.'],
      [/^(?:publicly_accessible|public_access|public)\s*=\s*true\b/i, `${configKind}.public-access`, 'Resource is configured for public access', 'high', 'heuristic', 'Verify the exposure is intended and restrict network access where possible.'],
      [/^(?:force_destroy|skip_final_snapshot)\s*=\s*true\b/i, `${configKind}.destructive-setting`, 'Destructive infrastructure lifecycle setting enabled', 'medium', 'confirmed', 'Review the recovery requirements before enabling destructive lifecycle behavior.'],
      [/^(?:encrypted|encryption_enabled|storage_encrypted)\s*=\s*false\b/i, `${configKind}.encryption-disabled`, 'Encryption is explicitly disabled', 'high', 'confirmed', 'Enable encryption at rest using the service-supported mechanism.'],
      [/^(?:hostPath|host_path)\s*:/i, `${configKind}.host-path`, 'Container mounts a host path', 'high', 'confirmed', 'Avoid hostPath mounts or restrict them to a narrowly scoped, read-only path.'],
      [/^\s*image\s*:\s*["']?[^#\s]+:latest\b/i, `${configKind}.floating-image`, 'Workload image uses the latest tag', 'medium', 'heuristic', 'Pin the image to a specific version or immutable digest.'],
      [/^\s*(?:debug|debug_mode)\s*[:=]\s*true\b/i, 'config.debug-enabled', 'Debug mode is enabled in configuration', 'medium', 'heuristic', 'Disable debug mode in production configuration.'],
      [/^\s*(?:access_control_allow_origin|cors_origin)\s*[:=]\s*["']?\*["']?\s*$/i, 'config.cors-wildcard', 'Wildcard cross-origin policy configured', 'medium', 'heuristic', 'Restrict allowed origins to the minimum required set.']
    ];
    for (const [pattern, ruleId, title, severity, confidence, remediation] of patterns) {
      if (!pattern.test(line)) continue;
      addFinding(findings, scanner, ruleId, title, severity, confidence, relativePath, index + 1, 'Configuration line matches a security rule; values are not copied into evidence', remediation, undefined, maxFindings);
    }
    if (/^\s*(?:verify_ssl|tls_verify)\s*[:=]\s*false\b/i.test(line) ||
      /^\s*insecure_skip_verify\s*[:=]\s*true\b/i.test(line)) {
      addFinding(findings, scanner, 'config.tls-verification-disabled', 'TLS verification is disabled', 'high', 'confirmed', relativePath, index + 1, 'TLS verification is explicitly disabled; configured value is not copied into evidence', 'Keep TLS certificate verification enabled.', undefined, maxFindings);
    }
  }
}

function damerauLevenshteinAtMostOne(left: string, right: string): boolean {
  if (left === right) return false;
  if (Math.abs(left.length - right.length) > 1) return false;
  let i = 0;
  let j = 0;
  let edits = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) {
      i++;
      j++;
      continue;
    }
    edits++;
    if (edits > 1) return false;
    if (left.length === right.length) {
      if (left[i + 1] === right[j] && left[i] === right[j + 1]) {
        i += 2;
        j += 2;
      } else {
        i++;
        j++;
      }
    } else if (left.length > right.length) i++;
    else j++;
  }
  if (i < left.length || j < right.length) edits++;
  return edits === 1;
}

function scanTyposquatPackages(
  root: string,
  files: string[],
  findings: SecurityFinding[],
  warnings: string[],
  maxFindings: number
): void {
  for (const manifestPath of files) {
    const name = path.basename(manifestPath).toLowerCase();
    try {
      let packages: Array<{ name: string; version: string; ecosystem: 'npm' | 'pypi' }>;
      if (name === 'package-lock.json') {
        packages = parseNpmManifests(undefined, fs.readFileSync(manifestPath, 'utf8')).packages;
      } else if (name === 'requirements.txt') {
        packages = parseRequirementsTxt(fs.readFileSync(manifestPath, 'utf8')).packages;
      } else if (name === 'poetry.lock') {
        packages = parsePoetryLock(fs.readFileSync(manifestPath, 'utf8')).packages;
      } else continue;

      for (const pkg of packages) {
        const canonical = pkg.ecosystem === 'pypi' ? canonicalizePythonPackageName(pkg.name) : pkg.name.toLowerCase();
        const candidate = KNOWN_PACKAGES.find((known) =>
          damerauLevenshteinAtMostOne(canonical, pkg.ecosystem === 'pypi' ? canonicalizePythonPackageName(known) : known)
        );
        if (candidate) {
          addFinding(
            findings,
            'typosquatting',
            'package.name-near-known-package',
            'Package name resembles a well-known package',
            'low',
            'heuristic',
            path.relative(root, manifestPath).split(path.sep).join('/'),
            undefined,
            `Package name is similar to "${candidate}"`,
            'Verify the package publisher, repository, and intended package identity before installation.',
            pkg.name,
            maxFindings
          );
        }
      }
    } catch {
      warnings.push(`Skipped typosquatting checks for ${path.relative(root, manifestPath).split(path.sep).join('/')}: manifest could not be parsed.`);
    }
  }
}

function scanLicenseMetadata(
  root: string,
  files: string[],
  allowedLicenses: string[],
  findings: SecurityFinding[],
  warnings: string[],
  maxFindings: number
): void {
  const allow = new Set(allowedLicenses.map((license) => license.trim().toUpperCase()).filter(Boolean));
  if (allow.size === 0) {
    warnings.push('License policy was not evaluated because no allowed license identifiers were configured.');
    return;
  }
  for (const manifestPath of files) {
    const name = path.basename(manifestPath).toLowerCase();
    let entries: Array<{ name: string; version: string; license?: string }>;
    try {
      const content = fs.readFileSync(manifestPath, 'utf8');
      if (name === 'package-lock.json') {
        const parsed = JSON.parse(content) as { packages?: Record<string, { name?: string; version?: string; license?: unknown }> };
        entries = Object.entries(parsed.packages ?? {})
          .filter(([location]) => location.startsWith('node_modules/'))
          .flatMap(([location, value]) => {
            const packageName = value.name ?? location.slice(location.lastIndexOf('node_modules/') + 13);
            return packageName && value.version ? [{
              name: packageName,
              version: value.version,
              ...(typeof value.license === 'string' ? { license: value.license } : {})
            }] : [];
          });
      } else if (name === 'poetry.lock') {
        const parsed = parsePoetryLock(content);
        const blocks = content.split(/(?=^\[\[package\]\]\s*$)/m).slice(1);
        const licensesByPackage = new Map<string, string>();
        for (const block of blocks) {
          const packageName = block.match(/^name\s*=\s*["']([^"']+)["']/m)?.[1];
          const license = block.match(/^license\s*=\s*["']([^"']+)["']/m)?.[1];
          if (packageName && license) licensesByPackage.set(canonicalizePythonPackageName(packageName), license);
        }
        entries = parsed.packages.map((pkg) => ({
          name: pkg.name,
          version: pkg.version,
          ...(licensesByPackage.get(canonicalizePythonPackageName(pkg.name))
            ? { license: licensesByPackage.get(canonicalizePythonPackageName(pkg.name)) }
            : {})
        }));
      } else continue;
    } catch {
      warnings.push(`Skipped license metadata in ${path.relative(root, manifestPath).split(path.sep).join('/')}: manifest could not be parsed.`);
      continue;
    }

    for (const entry of entries) {
      if (!entry.license) {
        addFinding(findings, 'license', 'license.metadata-missing', 'License metadata is unavailable in the lockfile', 'info', 'heuristic', path.relative(root, manifestPath).split(path.sep).join('/'), undefined, 'Lockfile contains no license identifier for this package', 'Review the package publisher metadata and your organization’s licensing requirements.', entry.name, maxFindings);
        continue;
      }
      const identifiers = entry.license.toUpperCase().split(/\s+(?:AND|OR)\s+|[(),]/).map((token) => token.trim()).filter(Boolean);
      const allowed = /\bAND\b/i.test(entry.license)
        ? identifiers.length > 0 && identifiers.every((identifier) => allow.has(identifier))
        : identifiers.some((identifier) => allow.has(identifier));
      if (!allowed) {
        addFinding(findings, 'license', 'license.not-allowlisted', 'Package license is not in the configured allowlist', 'medium', 'heuristic', path.relative(root, manifestPath).split(path.sep).join('/'), undefined, `Declared license identifier: ${entry.license.slice(0, 100)}`, 'Review the declared license with qualified counsel or add it to the policy allowlist if approved.', entry.name, maxFindings);
      }
    }
  }
}

export function inspectDockerImage(
  image: string,
  inspect: (image: string) => DockerImageInspection,
  findings: SecurityFinding[],
  maxFindings = DEFAULT_MAX_FINDINGS
): void {
  if (!image || image.length > 256 || /[\s;&|`$<>]/.test(image)) {
    throw new Error('Docker image reference contains unsupported characters.');
  }
  const data = inspect(image);
  if (data.user === undefined || data.user.trim() === '' || /^(?:0|root)(?::|$)/i.test(data.user)) {
    addFinding(findings, 'docker-image', 'docker-image.root-user', 'Image defaults to root or does not declare a user', 'high', 'heuristic', undefined, undefined, 'Image config does not declare a non-root user', 'Build the image with a dedicated non-root USER.', undefined, maxFindings);
  }
  if (!data.healthcheck) {
    addFinding(findings, 'docker-image', 'docker-image.healthcheck-missing', 'Image has no health check configured', 'low', 'heuristic', undefined, undefined, 'Docker image configuration contains no health check', 'Add a health check if this image is intended to run as a service.', undefined, maxFindings);
  }
  if (data.envNames?.some((name) => /(?:password|secret|token|api[_-]?key)/i.test(name))) {
    addFinding(findings, 'docker-image', 'docker-image.secret-env-name', 'Image configuration defines a credential-like environment variable', 'medium', 'heuristic', undefined, undefined, 'Credential-like environment variable name found; values redacted', 'Avoid baking credentials into image metadata; provide secrets at runtime.', undefined, maxFindings);
  }
  if (image.endsWith(':latest') || !image.includes(':') && !image.includes('@')) {
    addFinding(findings, 'docker-image', 'docker-image.floating-tag', 'Image reference uses a floating tag', 'medium', 'heuristic', undefined, undefined, 'Image tag is latest or omitted', 'Pin the image to an immutable digest or reviewed version.', undefined, maxFindings);
  }
}

export function runDockerImageInspection(image: string): DockerImageInspection {
  const result = spawnSync('docker', ['image', 'inspect', image], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
    timeout: 15_000,
    maxBuffer: 1024 * 1024
  });
  if (result.error) {
    throw new Error(`Could not run Docker image inspection: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error('Docker image inspection failed. Verify Docker is installed and the local image exists.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error('Docker returned an invalid image inspection response.');
  }
  if (!Array.isArray(parsed) || !parsed[0] || typeof parsed[0] !== 'object') {
    throw new Error('Docker image inspection returned no image metadata.');
  }
  const config = (parsed[0] as { Config?: Record<string, unknown> }).Config ?? {};
  const env = Array.isArray(config.Env) ? config.Env.filter((value): value is string => typeof value === 'string') : [];
  const exposedPorts = config.ExposedPorts && typeof config.ExposedPorts === 'object'
    ? Object.keys(config.ExposedPorts)
    : [];
  return {
    image,
    ...(typeof config.User === 'string' ? { user: config.User } : {}),
    healthcheck: config.Healthcheck,
    exposedPorts,
    envNames: env.map((entry) => entry.split('=', 1)[0]!)
  };
}

export function scanLocalSecurity(
  targetPath: string,
  options: LocalSecurityScanOptions = {}
): SecurityScanResult {
  const absoluteTarget = path.resolve(targetPath);
  const rootStat = fs.lstatSync(absoluteTarget);
  if (rootStat.isSymbolicLink() || (!rootStat.isDirectory() && !rootStat.isFile())) {
    throw new Error('Security scan target must be a regular file or directory; symbolic links are not followed.');
  }

  const root = rootStat.isDirectory() ? absoluteTarget : path.dirname(absoluteTarget);
  const maxFiles = Math.max(1, Math.floor(options.maxFiles ?? DEFAULT_MAX_FILES));
  const maxDepth = Math.max(0, Math.floor(options.maxDepth ?? DEFAULT_MAX_DEPTH));
  const maxFileSizeBytes = Math.max(1, Math.floor(options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_BYTES));
  const maxTotalBytes = Math.max(1, Math.floor(options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES));
  const maxEntries = Math.max(1, Math.floor(options.maxEntries ?? DEFAULT_MAX_ENTRIES));
  const maxFindings = Math.max(1, Math.floor(options.maxFindings ?? DEFAULT_MAX_FINDINGS));
  if (options.allowedLicenses?.some((license) => !/^[A-Za-z0-9][A-Za-z0-9.+-]{0,80}$/.test(license.trim()))) {
    throw new Error('Allowed license entries must be simple SPDX-style identifiers.');
  }
  const findings: SecurityFinding[] = [];
  const warnings: string[] = [];
  const textFiles: Array<{ absolutePath: string; relativePath: string; content: string }> = [];
  let filesScanned = 0;
  let bytesScanned = 0;
  let entriesVisited = 0;
  let stopped = false;

  const visitFile = (filePath: string): void => {
    if (options.signal?.aborted) throw new Error('Security scan was cancelled.');
    if (stopped || filesScanned >= maxFiles) {
      stopped = true;
      return;
    }
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) return;
    if (options.discoveredFiles) {
      const realPath = fs.realpathSync(filePath);
      const realRelative = path.relative(root, realPath);
      if (path.isAbsolute(realRelative) || realRelative === '..' || realRelative.startsWith(`..${path.sep}`)) {
        throw new Error('Discovered scan file resolves outside the security scan root.');
      }
    }
    const relative = path.relative(root, filePath).split(path.sep).join('/');
    if (stat.size > maxFileSizeBytes) {
      warnings.push(`Skipped ${relative}: file exceeds the configured per-file size limit.`);
      return;
    }
    if (bytesScanned + stat.size > maxTotalBytes) {
      warnings.push('Stopped scanning because the configured total byte limit was reached.');
      stopped = true;
      return;
    }
    const buffer = fs.readFileSync(filePath);
    bytesScanned += buffer.byteLength;
    if (buffer.includes(0)) return;
    const content = buffer.toString('utf8');
    filesScanned++;
    textFiles.push({ absolutePath: filePath, relativePath: relative, content });
    const lines = content.split(/\r?\n/);
    const scanner = classify(relative);
    const kubernetes = scanner === 'configuration' && /^\s*apiVersion\s*:/m.test(content) && /^\s*kind\s*:/m.test(content);
    const effectiveScanner = kubernetes ? 'kubernetes' : scanner;
    if (effectiveScanner === 'dockerfile') scanDockerfile(relative, lines, findings, maxFindings);
    else if (effectiveScanner === 'github-actions') scanWorkflow(relative, lines, findings, maxFindings);
    scanConfigLine(relative, lines, effectiveScanner, findings, maxFindings);

    for (const finding of scanSecretContent(content, relative)) {
      addFinding(
        findings,
        'secrets',
        finding.ruleId,
        finding.title,
        finding.severity,
        'heuristic',
        finding.filePath,
        finding.lineNumber,
        finding.evidence,
        finding.remediation,
        undefined,
        maxFindings
      );
    }

    for (const rule of options.customRules ?? []) {
      if (rule.extensions?.length && !rule.extensions.includes(path.extname(relative).toLowerCase())) continue;
      for (let index = 0; index < lines.length; index++) {
        if (findings.length >= maxFindings) break;
        if (lines[index]!.includes(rule.contains)) {
          addFinding(findings, 'custom', rule.id, rule.title, rule.severity, 'heuristic', relative, index + 1, 'Line contains a configured literal marker; full line is not included', rule.remediation, undefined, maxFindings);
        }
      }
    }
  };

  const visitDirectory = (directory: string, depth: number): void => {
    if (options.signal?.aborted) throw new Error('Security scan was cancelled.');
    if (stopped) return;
    if (depth > maxDepth) {
      warnings.push(`Skipped directories below ${maxDepth} levels.`);
      return;
    }
    const handle = fs.opendirSync(directory);
    const entries: fs.Dirent[] = [];
    let hasMoreEntries = false;
    try {
      while (entriesVisited < maxEntries) {
        const entry = handle.readSync();
        if (!entry) break;
        entriesVisited++;
        entries.push(entry);
      }
      hasMoreEntries = entriesVisited >= maxEntries && handle.readSync() !== null;
      if (hasMoreEntries) {
        warnings.push('Stopped scanning because the configured filesystem entry limit was reached; results may be incomplete.');
      }
      entries.sort((left, right) => left.name.localeCompare(right.name));
    } finally {
      handle.closeSync();
    }
    for (const entry of entries) {
      if (options.signal?.aborted) throw new Error('Security scan was cancelled.');
      if (stopped) break;
      const entryPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry.name.toLowerCase())) continue;
        visitDirectory(entryPath, depth + 1);
      } else if (entry.isFile()) visitFile(entryPath);
    }
    if (hasMoreEntries) stopped = true;
  };

  if (options.discoveredFiles) {
    for (const discoveredFile of options.discoveredFiles) {
      const filePath = path.resolve(discoveredFile);
      const relativePath = path.relative(root, filePath);
      if (path.isAbsolute(relativePath) || relativePath === '..' || relativePath.startsWith(`..${path.sep}`)) {
        throw new Error('Discovered scan files must remain within the security scan root.');
      }
      visitFile(filePath);
    }
  } else if (rootStat.isFile()) visitFile(absoluteTarget);
  else visitDirectory(absoluteTarget, 0);

  const manifestFiles = textFiles
    .filter((file) => ['package-lock.json', 'requirements.txt', 'poetry.lock'].includes(path.basename(file.absolutePath).toLowerCase()))
    .map((file) => file.absolutePath);
  scanTyposquatPackages(root, manifestFiles, findings, warnings, maxFindings);
  if (options.allowedLicenses) {
    scanLicenseMetadata(root, manifestFiles, options.allowedLicenses, findings, warnings, maxFindings);
  }
  if (findings.length >= maxFindings) {
    warnings.push(`Finding limit (${maxFindings}) reached; additional findings may have been omitted.`);
  }
  if (stopped) warnings.push('Security scan stopped after reaching a configured resource limit; results may be incomplete.');

  return {
    target: path.basename(absoluteTarget),
    findings: findings.slice(0, maxFindings),
    warnings: Array.from(new Set(warnings)),
    filesScanned,
    bytesScanned
  };
}
