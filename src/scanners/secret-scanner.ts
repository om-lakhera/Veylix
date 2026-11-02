import * as fs from 'node:fs';
import * as path from 'node:path';

export type SecretFindingSeverity = 'high' | 'medium';

export interface SecretFinding {
  ruleId: string;
  title: string;
  severity: SecretFindingSeverity;
  filePath: string;
  lineNumber: number;
  evidence: 'Potential credential value redacted';
  remediation: string;
}

export interface SecretScanResult {
  target: string;
  filesScanned: number;
  bytesScanned: number;
  findings: SecretFinding[];
  warnings: string[];
}

export interface SecretScanOptions {
  maxFiles?: number;
  maxDepth?: number;
  maxFileSizeBytes?: number;
  maxTotalBytes?: number;
  maxEntries?: number;
  maxFindings?: number;
}

const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_DEPTH = 20;
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 50 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 50_000;
const DEFAULT_MAX_FINDINGS = 10_000;
const IGNORED_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  '.next',
  '.cache',
  'node_modules',
  'vendor',
  'venv',
  '.venv',
  '__pycache__',
  'dist',
  'build',
  'coverage'
]);

const rules: Array<{
  id: string;
  title: string;
  severity: SecretFindingSeverity;
  pattern: RegExp;
  remediation: string;
}> = [
  {
    id: 'secret.private-key',
    title: 'Private key material',
    severity: 'high',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    remediation: 'Remove the private key from the repository, rotate it, and store it in a secrets manager.'
  },
  {
    id: 'secret.aws-access-key',
    title: 'AWS access key identifier',
    severity: 'high',
    pattern: /(?:^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:$|[^A-Z0-9])/,
    remediation: 'Revoke or rotate the exposed AWS credential and use short-lived credentials.'
  },
  {
    id: 'secret.github-token',
    title: 'GitHub token pattern',
    severity: 'high',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    remediation: 'Revoke the token, review its access, and use a narrowly scoped secret outside source control.'
  },
  {
    id: 'secret.credential-assignment',
    title: 'Possible hard-coded credential assignment',
    severity: 'medium',
    pattern: /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{16,})/i,
    remediation: 'Verify this is not a real credential. If exposed, rotate it and load it from a secrets manager or environment.'
  }
];

function isPlaceholderLine(line: string): boolean {
  return /\b(?:example|sample|placeholder|changeme|change-me|replace[-_ ]?me|your[-_ ]|dummy|not[-_ ]?real)\b/i.test(line);
}

function relativePath(root: string, filePath: string): string {
  return path.relative(root, filePath).split(path.sep).join('/') || path.basename(filePath);
}

export function scanSecretContent(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index]!;
    if (isPlaceholderLine(line)) continue;
    const matchedHighConfidenceRule = rules
      .filter((rule) => rule.severity === 'high')
      .some((rule) => rule.pattern.test(line));
    for (const rule of rules) {
      if (matchedHighConfidenceRule && rule.severity === 'medium') continue;
      if (!rule.pattern.test(line)) continue;
      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        filePath,
        lineNumber: index + 1,
        evidence: 'Potential credential value redacted',
        remediation: rule.remediation
      });
    }
  }
  return findings;
}

export function scanForSecrets(targetPath: string, options: SecretScanOptions = {}): SecretScanResult {
  if (typeof targetPath !== 'string' || targetPath.trim().length === 0) {
    throw new Error('A file or directory path is required for secret scanning.');
  }

  const absoluteTarget = path.resolve(targetPath);
  if (!fs.existsSync(absoluteTarget)) {
    throw new Error(`Secret scan target does not exist: ${targetPath}`);
  }
  const rootStat = fs.lstatSync(absoluteTarget);
  if (rootStat.isSymbolicLink()) {
    throw new Error('Secret scan does not follow symbolic links.');
  }
  if (!rootStat.isFile() && !rootStat.isDirectory()) {
    throw new Error('Secret scan target must be a regular file or directory.');
  }

  const rootDirectory = rootStat.isDirectory() ? absoluteTarget : path.dirname(absoluteTarget);
  const maxFiles = Math.max(1, Math.floor(options.maxFiles ?? DEFAULT_MAX_FILES));
  const maxDepth = Math.max(0, Math.floor(options.maxDepth ?? DEFAULT_MAX_DEPTH));
  const maxFileSizeBytes = Math.max(1, Math.floor(options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_BYTES));
  const maxTotalBytes = Math.max(1, Math.floor(options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES));
  const maxEntries = Math.max(1, Math.floor(options.maxEntries ?? DEFAULT_MAX_ENTRIES));
  const maxFindings = Math.max(1, Math.floor(options.maxFindings ?? DEFAULT_MAX_FINDINGS));
  const findings: SecretFinding[] = [];
  const warnings: string[] = [];
  let filesScanned = 0;
  let filesVisited = 0;
  let bytesScanned = 0;
  let stoppedAtLimit = false;
  let depthWarningAdded = false;
  let findingsLimitWarningAdded = false;
  let entriesVisited = 0;
  let entriesLimitWarningAdded = false;

  const inspectFile = (filePath: string): void => {
    if (filesVisited >= maxFiles || stoppedAtLimit) {
      stoppedAtLimit = true;
      return;
    }

    const fileStat = fs.lstatSync(filePath);
    if (!fileStat.isFile() || fileStat.isSymbolicLink()) return;
    filesVisited++;
    const relative = relativePath(rootDirectory, filePath);
    if (fileStat.size > maxFileSizeBytes) {
      warnings.push(`Skipped ${relative}: file exceeds the configured per-file size limit.`);
      return;
    }
    if (bytesScanned + fileStat.size > maxTotalBytes) {
      warnings.push('Stopped scanning because the configured total byte limit was reached.');
      stoppedAtLimit = true;
      return;
    }

    const content = fs.readFileSync(filePath);
    bytesScanned += content.byteLength;
    if (content.includes(0)) return;
    filesScanned++;

    for (const finding of scanSecretContent(content.toString('utf8'), relative)) {
      if (findings.length >= maxFindings) {
        stoppedAtLimit = true;
        if (!findingsLimitWarningAdded) {
          warnings.push(`Stopped scanning after reaching the configured limit of ${maxFindings} findings.`);
          findingsLimitWarningAdded = true;
        }
        return;
      }
      findings.push(finding);
    }
  };

  if (rootStat.isFile()) {
    inspectFile(absoluteTarget);
  } else {
    const visit = (directory: string, depth: number): void => {
      if (stoppedAtLimit) return;
      if (depth > maxDepth) {
        if (!depthWarningAdded) {
          warnings.push(`Skipped directories below ${maxDepth} levels.`);
          depthWarningAdded = true;
        }
        return;
      }
      const entries: fs.Dirent[] = [];
      let exceededEntryLimit = false;
      const directoryHandle = fs.opendirSync(directory);
      try {
        while (entriesVisited < maxEntries) {
          const entry = directoryHandle.readSync();
          if (!entry) break;
          entriesVisited++;
          entries.push(entry);
        }
        if (entriesVisited >= maxEntries && directoryHandle.readSync()) {
          exceededEntryLimit = true;
        }
      } finally {
        directoryHandle.closeSync();
      }
      entries.sort((left, right) => left.name.localeCompare(right.name));
      for (const entry of entries) {
        if (stoppedAtLimit) break;
        const entryPath = path.join(directory, entry.name);
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          if (!IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) visit(entryPath, depth + 1);
        } else if (entry.isFile()) {
          inspectFile(entryPath);
        }
      }
      if (exceededEntryLimit) {
        stoppedAtLimit = true;
        if (!entriesLimitWarningAdded) {
          warnings.push(`Stopped scanning after reaching the configured limit of ${maxEntries} filesystem entries.`);
          entriesLimitWarningAdded = true;
        }
      }
    };
    visit(absoluteTarget, 0);
  }

  if (stoppedAtLimit && filesVisited >= maxFiles) {
    warnings.push(`Stopped scanning after reaching the configured limit of ${maxFiles} files.`);
  }

  return {
    target: path.basename(absoluteTarget),
    filesScanned,
    bytesScanned,
    findings,
    warnings
  };
}
