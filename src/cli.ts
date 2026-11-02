import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

const packageJson = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
  version: string;
};

export const VEYLIX_VERSION = packageJson.version;
export const VEYLIX_ENGINE_VERSION = '1.0.0';

import { VeylixEngine } from './engine.js';
import { AnalysisReport, SupportedEcosystem } from './types.js';
import { serializeReportFormat } from './report-formats.js';
import { MAX_MANIFEST_SIZE_BYTES, MAX_TOTAL_MANIFEST_SIZE_BYTES } from './limits.js';
import { scanForSecrets } from './scanners/secret-scanner.js';
import { createOsvCachedFetch } from './osv-cache.js';
import {
  inspectDockerImage,
  loadDeclarativeRules,
  runDockerImageInspection,
  scanLocalSecurity,
  SecurityFinding,
  SecuritySeverity
} from './scanners/local-security-scanner.js';
import { watchLocalSecurity } from './scanners/security-watch.js';
import { RepositoryScanOptions, scanRepository } from './scanners/repository-scanner.js';

export type CliSeverityThreshold = 'critical' | 'high' | 'moderate' | 'low' | 'none';
export type CliFormat = 'text' | 'json' | 'sarif' | 'cyclonedx' | 'spdx' | 'markdown' | 'html';

export interface ParsedCliArgs {
  help: boolean;
  input?: string;
  ecosystem?: SupportedEcosystem;
  threshold: CliSeverityThreshold;
  format: CliFormat;
  fetchExploitIntelligence: boolean;
  cacheFile?: string;
  offline?: boolean;
  cacheMaxAgeDays?: number;
  error?: string;
}

const HELP_TEXT = `Veylix CLI

Usage:
  veylix [--help|--version|--banner]
  veylix scan --file <path> [--ecosystem npm|pypi] [--threshold critical|high|moderate|low|none] [--format text|json|sarif|cyclonedx|spdx|markdown|html] [--exploit-intel] [--cache-file <path> [--offline [--cache-max-age-days <days>]]]
  veylix security scan [--path <file-or-directory>] [--image <local-image>] [--rules-file <json>] [--license-allow <id,...>] [--threshold critical|high|medium|low|none] [--format text|json]
  veylix secrets --path <file-or-directory> [--format text|json]
  veylix repository scan [--path <directory>] [--format text|json] [--exclude <glob>] [--max-depth <n>] [--max-files <n>] [--max-entries <n>] [--max-file-size <bytes>] [--max-total-bytes <bytes>]

Examples:
  veylix
  veylix --help
  veylix --version
  veylix scan --file ./package-lock.json --ecosystem npm --threshold high --format json
  veylix scan --file ./requirements.txt --ecosystem pypi --threshold low
  veylix scan --file ./package-lock.json --exploit-intel
  veylix scan --file ./package-lock.json --format sarif > veylix.sarif
  veylix scan --file ./package-lock.json --format cyclonedx > veylix.cdx.json
  veylix scan --file ./package-lock.json --cache-file ./.veylix/osv-cache.json
  veylix scan --file ./package-lock.json --cache-file ./.veylix/osv-cache.json --offline
  veylix security scan --path . --format json
  veylix security scan --path . --image example:1.2 --license-allow MIT,Apache-2.0
  veylix security scan --path . --rules-file ./veylix-rules.json
  veylix secrets --path .
  veylix repository scan --path . --format json

Exit codes:
  0  Scan succeeded and the threshold was not exceeded.
  1  Scan succeeded but vulnerabilities met or exceeded the configured threshold.
  2  Invalid arguments or scan execution failure.
`;

function supportsAnsi(): boolean {
  const forced = process.env.NO_COLOR !== undefined;
  const dumbTerm = process.env.TERM === 'dumb';
  return !forced && !dumbTerm && Boolean(process.stdout.isTTY) && !process.env.CI;
}

function terminalWidth(): number {
  const reported = Number(process.env.COLUMNS ?? process.stdout.columns ?? 80);
  return Number.isFinite(reported) && reported > 0 ? Math.max(60, Math.min(reported, 160)) : 80;
}

export function renderStartupBanner(options: { width?: number; supportsAnsi?: boolean } = {}): string {
  const width = options.width ?? terminalWidth();
  const colors = options.supportsAnsi ?? supportsAnsi();
  const green = colors ? '\x1b[32m' : '';
  const dim = colors ? '\x1b[2m' : '';
  const cyan = colors ? '\x1b[36m' : '';
  const reset = colors ? '\x1b[0m' : '';

  const logo = [
    '  __     ______   ___    ___  __   __  ______   ___   ___   ___',
    ' / /\   / __  /  / _ \\  / _ \\|  \\ /  |/ __  /  / _ \\ / _ \\ / _ \\',
    '/ /_/ / / /_/ /  / /_\\ \\/ /_\\ \\  \\  / / /_/ /  / /_\\ \\ /_\\ \\ /_\\ \\',
    '\\____/  \\____/   \\____/ \\____/  \\_/\\_\\\\____/   \\____/ \\____/ \\____/',
    '  __  __  __  __   _   _   __   ______  ___   __  __  __',
    ' |  \\|  \\/  | | | | | |  \\ \ / /  / /| | | |  \\|  \\/  |',
    ' | .` | |\/| | | |_| | | |\\ V / / /_| |_| | | .` | |\/| |',
    ' |_|_|_|_|  |_| |_|_|_| |_| \\_/  \\_____|_|_| |_|_|_|_|  |_|'
  ];

  const meta = [
    ['Product', 'Veylix'],
    ['Version', VEYLIX_VERSION],
    ['Engine', VEYLIX_ENGINE_VERSION],
    ['Runtime', `${process.platform} ${process.arch} / Node ${process.versions.node}`],
    ['Ecosystems', 'npm + PyPI'],
    ['Scanners', 'repo · deps · secrets · workflow · config'],
    ['Mode', 'local-first'],
    ['CLI', 'bin/veylix.js / npm install -g veylix']
  ];

  const leftWidth = Math.max(32, Math.min(40, Math.floor(width * 0.44)));
  const rightWidth = Math.max(28, width - leftWidth - 8);
  const bannerLines = [] as string[];
  const infoLines = meta.map(([label, value]) => `${label.padEnd(11)} ${value}`);
  const maxInfoLines = Math.max(logo.length, infoLines.length);

  for (let index = 0; index < maxInfoLines; index++) {
    const left = logo[index] ?? ''.padEnd(leftWidth, ' ');
    const right = infoLines[index] ?? '';
    const padded = left.padEnd(leftWidth, ' ');
    bannerLines.push(`${green}${padded}${reset}  ${cyan}${right}${reset}`);
  }

  const tagline = `${dim}Local-first security scanning for dependency, workflow, and repository risk${reset}`;
  const commandList = [
    'Commands:',
    '  veylix --help',
    '  veylix --version',
    '  veylix scan --file <path>',
    '  veylix security scan --path <dir>',
    '  veylix secrets --path <dir>',
    '  veylix repository scan --path <dir>'
  ];

  const content = [...bannerLines, '', `${green}Tagline:${reset} ${tagline}`, '', ...commandList ].join('\n');
  return content;
}

async function runRepositoryCli(
  argv: string[],
  io: { stdout: { write: (chunk: string) => void }; stderr: { write: (chunk: string) => void } }
): Promise<number> {
  let targetPath = '.';
  let format: 'text' | 'json' = 'text';
  let threshold: SecuritySeverity | 'none' = 'high';
  const exclude: string[] = [];
  const limits: Record<'maxDepth' | 'maxFiles' | 'maxEntries' | 'maxFileSizeBytes' | 'maxTotalBytes', number> = {
    maxDepth: 32,
    maxFiles: 50_000,
    maxEntries: 200_000,
    maxFileSizeBytes: 2 * 1024 * 1024,
    maxTotalBytes: 500 * 1024 * 1024
  };
  let pending: 'path' | 'format' | 'threshold' | 'exclude' | 'max-depth' | 'max-files' | 'max-entries' | 'max-file-size' | 'max-total-bytes' | null = null;
  const args = argv[0] === 'scan' ? argv.slice(1) : argv;
  const numericOptions = {
    'max-depth': { key: 'maxDepth', minimum: 0, maximum: 256 },
    'max-files': { key: 'maxFiles', minimum: 1, maximum: 1_000_000 },
    'max-entries': { key: 'maxEntries', minimum: 1, maximum: 2_000_000 },
    'max-file-size': { key: 'maxFileSizeBytes', minimum: 1, maximum: 1024 * 1024 * 1024 },
    'max-total-bytes': { key: 'maxTotalBytes', minimum: 1, maximum: 10 * 1024 * 1024 * 1024 }
  } as const;

  for (const item of args) {
    if (pending) {
      if (pending === 'path') targetPath = item;
      else if (pending === 'format') {
        if (item !== 'text' && item !== 'json') {
          io.stderr.write('Error: repository scan format must be text or json.\n');
          return 2;
        }
        format = item;
      } else if (pending === 'threshold') {
        if (!['critical', 'high', 'medium', 'low', 'info', 'none'].includes(item.toLowerCase())) {
          io.stderr.write('Error: repository threshold must be critical, high, medium, low, info, or none.\n');
          return 2;
        }
        threshold = item.toLowerCase() as SecuritySeverity | 'none';
      } else if (pending === 'exclude') {
        exclude.push(item);
      } else {
        const option = numericOptions[pending];
        const value = Number(item);
        if (!Number.isSafeInteger(value) || value < option.minimum || value > option.maximum) {
          io.stderr.write(`Error: --${pending} must be an integer between ${option.minimum} and ${option.maximum}.\n`);
          return 2;
        }
        limits[option.key] = value;
      }
      pending = null;
      continue;
    }
    if (item === '--help' || item === '-h') {
      io.stdout.write('Usage: veylix repository scan [--path <directory>] [--format text|json] [--threshold critical|high|medium|low|info|none] [--exclude <glob>] [--max-depth <n>] [--max-files <n>] [--max-entries <n>] [--max-file-size <bytes>] [--max-total-bytes <bytes>]\n');
      io.stdout.write('Discovers local project files and runs supported dependency and static security scanners. No source files are uploaded.\n');
      return 0;
    }
    if (item === '--path' || item === '-p') pending = 'path';
    else if (item === '--format') pending = 'format';
    else if (item === '--threshold') pending = 'threshold';
    else if (item === '--exclude') pending = 'exclude';
    else if (item === '--max-depth') pending = 'max-depth';
    else if (item === '--max-files') pending = 'max-files';
    else if (item === '--max-entries') pending = 'max-entries';
    else if (item === '--max-file-size') pending = 'max-file-size';
    else if (item === '--max-total-bytes') pending = 'max-total-bytes';
    else {
      io.stderr.write(`Error: unknown repository scan option: ${item}\n`);
      return 2;
    }
  }
  if (pending) {
    io.stderr.write(`Error: missing value for ${pending}.\n`);
    return 2;
  }

  try {
    const scanOptions: RepositoryScanOptions = { ...limits, exclude };
    const report = await scanRepository(targetPath, scanOptions);
    const thresholdWeight = threshold === 'none' ? Infinity : SECURITY_SEVERITY_WEIGHT[threshold];
    const exceeded = report.findings.some((finding) =>
      (finding.severity === 'unknown' ? SECURITY_SEVERITY_WEIGHT.low : SECURITY_SEVERITY_WEIGHT[finding.severity]) >= thresholdWeight
    );
    if (format === 'json') {
      io.stdout.write(`${JSON.stringify({ ...report, threshold, exceeded }, null, 2)}\n`);
    } else {
      io.stdout.write(`Repository: ${report.root}\n`);
      io.stdout.write(`Projects: ${report.projects.length}\n`);
      for (const project of report.projects) {
        io.stdout.write(`- ${project.root}: ${project.type.join(', ') || 'unclassified'}; languages: ${project.languages.join(', ') || 'none detected'}\n`);
      }
      io.stdout.write(`Languages: ${report.languages.join(', ') || 'none detected'}\n`);
      io.stdout.write(`Scan targets: ${report.scanTargets.length}\n`);
      io.stdout.write(`Findings: ${report.findings.length}${threshold === 'none' ? '' : `; threshold ${threshold} exceeded: ${exceeded ? 'yes' : 'no'}`}\n`);
      for (const finding of report.findings) {
        io.stdout.write(`${finding.severity.toUpperCase()} ${finding.ruleId} ${finding.filePath ?? finding.project ?? '.'}: ${finding.description} (${finding.confidenceLevel})\n`);
        io.stdout.write(`  Evidence: ${finding.evidence}\n  Remediation: ${finding.remediation}\n`);
      }
      for (const item of report.diagnostics) {
        const writer = item.severity === 'error' ? io.stderr : io.stdout;
        writer.write(`${item.severity === 'error' ? 'Error' : 'Warning'}: ${item.message}${item.path ? ` (${item.path})` : ''}\n`);
      }
    }
    if (report.cancelled || report.diagnostics.some((item) => item.severity === 'error')) return 2;
    return exceeded ? 1 : 0;
  } catch (error) {
    io.stderr.write(`Error: ${error instanceof Error ? error.message : 'Repository scan failed.'}\n`);
    return 2;
  }
}

const SECURITY_SEVERITY_WEIGHT: Record<SecuritySeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

async function runSecurityCli(
  argv: string[],
  io: { stdout: { write: (chunk: string) => void }; stderr: { write: (chunk: string) => void } }
): Promise<number> {
  let targetPath: string | undefined;
  const images: string[] = [];
  const rulesFiles: string[] = [];
  const allowedLicenses: string[] = [];
  let format: 'text' | 'json' = 'text';
  let threshold: SecuritySeverity | 'none' = 'high';
  let watch = false;
  let pending: 'path' | 'image' | 'rules-file' | 'license-allow' | 'format' | 'threshold' | null = null;
  const args = argv[0] === 'scan' ? argv.slice(1) : argv;

  for (const item of args) {
    if (pending) {
      switch (pending) {
        case 'path':
          targetPath = item;
          break;
        case 'image':
          images.push(item);
          break;
        case 'rules-file':
          rulesFiles.push(item);
          break;
        case 'license-allow':
          allowedLicenses.push(...item.split(',').map((value) => value.trim()).filter(Boolean));
          break;
        case 'format':
          if (item !== 'text' && item !== 'json') {
            io.stderr.write('Error: security scan format must be text or json.\n');
            return 2;
          }
          format = item;
          break;
        case 'threshold':
          if (!['critical', 'high', 'medium', 'low', 'none'].includes(item.toLowerCase())) {
            io.stderr.write('Error: security threshold must be critical, high, medium, low, or none.\n');
            return 2;
          }
          threshold = item.toLowerCase() as SecuritySeverity | 'none';
          break;
      }
      pending = null;
      continue;
    }

    if (item === '--help' || item === '-h') {
      io.stdout.write('Usage: veylix security scan [--path <file-or-directory>] [--image <local-image>] [--rules-file <json>] [--license-allow <id,...>] [--threshold critical|high|medium|low|none] [--format text|json]\n');
      io.stdout.write('Scans source and configuration locally. Add --watch to rescan after local changes. Docker image checks inspect image configuration only; they do not scan image layers or OS packages.\n');
      return Promise.resolve(0);
    }
    if (item === '--path' || item === '-p') pending = 'path';
    else if (item === '--image') pending = 'image';
    else if (item === '--rules-file') pending = 'rules-file';
    else if (item === '--license-allow') pending = 'license-allow';
    else if (item === '--format') pending = 'format';
    else if (item === '--threshold') pending = 'threshold';
    else if (item === '--watch') watch = true;
    else {
      io.stderr.write(`Error: unknown security scan option: ${item}\n`);
      return Promise.resolve(2);
    }
  }

  if (pending) {
    io.stderr.write(`Error: missing value for ${pending}.\n`);
    return Promise.resolve(2);
  }
  if (!targetPath && images.length === 0) {
    io.stderr.write('Error: provide --path, --image, or both.\n');
    return Promise.resolve(2);
  }
  if (watch && !targetPath) {
    io.stderr.write('Error: --watch requires --path and cannot be used with image-only scans.\n');
    return Promise.resolve(2);
  }

  try {
    const customRules = rulesFiles.flatMap(loadDeclarativeRules);
    const duplicateRuleIds = customRules.filter((rule, index) =>
      customRules.findIndex((candidate) => candidate.id === rule.id) !== index
    );
    if (duplicateRuleIds.length) {
      throw new Error(`Duplicate custom rule id: ${duplicateRuleIds[0]!.id}`);
    }

    const scanOptions = {
        customRules,
        ...(allowedLicenses.length ? { allowedLicenses } : {})
      };
    const result = targetPath
      ? scanLocalSecurity(targetPath, scanOptions)
      : { target: 'Docker images', findings: [] as SecurityFinding[], warnings: [], filesScanned: 0, bytesScanned: 0 };
    for (const image of images) {
      inspectDockerImage(image, runDockerImageInspection, result.findings);
    }
    const thresholdWeight = threshold === 'none' ? Infinity : SECURITY_SEVERITY_WEIGHT[threshold];
    const exceeded = result.findings.some((finding) => SECURITY_SEVERITY_WEIGHT[finding.severity] >= thresholdWeight);
    const writeResult = (scanResult: typeof result): void => {
      const thresholdExceeded = scanResult.findings.some((finding) =>
        threshold !== 'none' && SECURITY_SEVERITY_WEIGHT[finding.severity] >= SECURITY_SEVERITY_WEIGHT[threshold]
      );
      if (format === 'json') {
        io.stdout.write(`${JSON.stringify({ ...scanResult, threshold, exceeded: thresholdExceeded })}\n`);
        return;
      }
      io.stdout.write(`Scanned ${scanResult.filesScanned} files (${scanResult.bytesScanned} bytes) in ${scanResult.target}.\n`);
      io.stdout.write(`Findings: ${scanResult.findings.length}${threshold === 'none' ? '' : `; threshold ${threshold} exceeded: ${thresholdExceeded ? 'yes' : 'no'}`}\n`);
      for (const finding of scanResult.findings) {
        const location = finding.filePath
          ? `${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ''}`
          : finding.packageName ?? 'Docker image configuration';
        io.stdout.write(`${finding.severity.toUpperCase()} ${finding.ruleId} ${location}: ${finding.title} (${finding.confidence})\n`);
        io.stdout.write(`  Evidence: ${finding.evidence}\n  Remediation: ${finding.remediation}\n`);
      }
      for (const warning of scanResult.warnings) io.stderr.write(`Warning: ${warning}\n`);
    };
    writeResult(result);
    if (watch && targetPath) {
      return await new Promise<number>((resolve) => {
        let stopWatch = (): void => undefined;
        const onInterrupt = (): void => finish(0);
        const finish = (code: number): void => {
          stopWatch();
          process.removeListener('SIGINT', onInterrupt);
          resolve(code);
        };
        try {
          stopWatch = watchLocalSecurity(
            targetPath!,
            { ...scanOptions, runInitialScan: false },
            (updated) => writeResult(updated),
            (error) => {
              io.stderr.write(`Error: Security watch stopped: ${error.message}\n`);
              finish(2);
            }
          );
          process.once('SIGINT', onInterrupt);
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Security watch could not be started.';
          io.stderr.write(`Error: ${message}\n`);
          finish(2);
        }
      });
    }
    return exceeded ? 1 : 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Local security scan could not be completed.';
    io.stderr.write(`Error: ${message}\n`);
    return Promise.resolve(2);
  }
}

const SEVERITY_LEVEL_WEIGHT: Record<'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN', number> = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  LOW: 1,
  UNKNOWN: 1
};

export function parseThreshold(value?: string): CliSeverityThreshold {
  const normalized = (value ?? 'none').trim().toLowerCase();
  switch (normalized) {
    case 'critical':
    case 'crit':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'moderate';
    case 'low':
      return 'low';
    case 'none':
    case 'off':
      return 'none';
    default:
      throw new Error(`Unsupported threshold: ${value}. Use critical, high, moderate, low, or none.`);
  }
}

export function parseCliArgs(argv: string[]): ParsedCliArgs {
  const items = argv[0] === 'scan' ? argv.slice(1) : argv;
  const parsed: ParsedCliArgs = {
    help: false,
    threshold: 'none',
    format: 'text',
    fetchExploitIntelligence: false
  };

  let pendingKey: 'input' | 'ecosystem' | 'threshold' | 'format' | 'cache-file' | 'cache-max-age-days' | null = null;

  for (const item of items) {
    if (item === '--help' || item === '-h') {
      parsed.help = true;
      return parsed;
    }
    if (item === '--version') {
      return parsed;
    }
    if (item === '--banner' || item === '--no-banner') {
      continue;
    }

    if (item === '--exploit-intel') {
      parsed.fetchExploitIntelligence = true;
      continue;
    }
    if (item === '--offline') {
      parsed.offline = true;
      continue;
    }

    if (pendingKey) {
      switch (pendingKey) {
        case 'input':
          parsed.input = item;
          break;
        case 'ecosystem': {
          const normalized = item.trim().toLowerCase();
          if (normalized === 'npm' || normalized === 'pypi') {
            parsed.ecosystem = normalized;
          } else {
            return { ...parsed, error: `Unsupported ecosystem: ${item}. Use npm or pypi.` };
          }
          break;
        }
        case 'threshold': {
          try {
            parsed.threshold = parseThreshold(item);
          } catch (error) {
            return {
              ...parsed,
              error: error instanceof Error ? error.message : 'Invalid threshold option.'
            };
          }
          break;
        }
        case 'format': {
          const normalized = item.trim().toLowerCase();
          switch (normalized) {
            case 'json':
            case 'text':
            case 'sarif':
            case 'cyclonedx':
            case 'spdx':
            case 'markdown':
            case 'html':
              parsed.format = normalized;
              break;
            default:
              return {
                ...parsed,
                error: `Unsupported output format: ${item}. Use json, text, sarif, cyclonedx, spdx, markdown, or html.`
              };
          }
          break;
        }
        case 'cache-file':
          parsed.cacheFile = item;
          break;
        case 'cache-max-age-days': {
          const age = Number(item);
          if (!Number.isFinite(age) || age < 0 || age > 3650) {
            return { ...parsed, error: 'OSV cache maximum age must be a number between 0 and 3650 days.' };
          }
          parsed.cacheMaxAgeDays = age;
          break;
        }
      }
      pendingKey = null;
      continue;
    }

    if (item === '--input' || item === '--file') {
      pendingKey = 'input';
      continue;
    }
    if (item === '--ecosystem') {
      pendingKey = 'ecosystem';
      continue;
    }
    if (item === '--threshold') {
      pendingKey = 'threshold';
      continue;
    }
    if (item === '--format') {
      pendingKey = 'format';
      continue;
    }
    if (item === '--cache-file') {
      pendingKey = 'cache-file';
      continue;
    }
    if (item === '--cache-max-age-days') {
      pendingKey = 'cache-max-age-days';
      continue;
    }
    if (item === 'scan') {
      continue;
    }
    if (!parsed.input) {
      parsed.input = item;
      continue;
    }

    return { ...parsed, error: `Unknown argument: ${item}` };
  }

  if (pendingKey) {
    return { ...parsed, error: `Missing value for ${pendingKey}.` };
  }
  if (parsed.offline && !parsed.cacheFile) {
    return { ...parsed, error: '--offline requires --cache-file <path>.' };
  }
  if (parsed.cacheMaxAgeDays !== undefined && !parsed.cacheFile) {
    return { ...parsed, error: '--cache-max-age-days requires --cache-file <path>.' };
  }

  return parsed;
}

function getThresholdWeight(level: CliSeverityThreshold): number {
  switch (level) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'moderate':
      return 2;
    case 'low':
      return 1;
    default:
      return 0;
  }
}

export function evaluateThreshold(report: AnalysisReport, threshold: CliSeverityThreshold = 'none'): {
  exceeded: boolean;
  matchedSeverities: string[];
} {
  if (threshold === 'none') {
    return { exceeded: false, matchedSeverities: [] };
  }

  const thresholdWeight = getThresholdWeight(threshold);
  const matchedSeverities = (['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'] as const).filter((level) => {
    const count = report.summary.severityCounts[
      level.toLowerCase() as keyof typeof report.summary.severityCounts
    ];
    return count > 0 && SEVERITY_LEVEL_WEIGHT[level] >= thresholdWeight;
  });

  return {
    exceeded: matchedSeverities.length > 0,
    matchedSeverities: matchedSeverities.map((level) => level.toLowerCase())
  };
}

function detectEcosystemFromPath(inputPath: string): SupportedEcosystem | undefined {
  const lower = inputPath.toLowerCase();
  if (lower.endsWith('package-lock.json') || lower.endsWith('package.json')) {
    return 'npm';
  }
  if (lower.endsWith('requirements.txt') || lower.endsWith('poetry.lock') || lower.endsWith('pyproject.toml')) {
    return 'pypi';
  }
  return undefined;
}

async function scanInputPath(
  inputPath: string,
  ecosystem: SupportedEcosystem | undefined,
  fetchExploitIntelligence: boolean,
  cache?: { file: string; offline: boolean; maxAgeDays?: number }
): Promise<AnalysisReport> {
  const absolutePath = path.resolve(inputPath);
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Input path does not exist: ${inputPath}`);
  }

  const stats = fs.statSync(absolutePath);
  const engine = new VeylixEngine({
    fetchExploitIntelligence,
    ...(cache ? {
      osvOptions: {
        fetchFn: createOsvCachedFetch({
          cacheFile: cache.file,
          offline: cache.offline,
          maxAgeDays: cache.maxAgeDays
        })
      }
    } : {})
  });
  let totalManifestBytes = 0;
  const contents = new Map<string, string>();
  const readManifest = (manifestPath: string): string => {
    const existing = contents.get(manifestPath);
    if (existing !== undefined) return existing;
    const size = fs.statSync(manifestPath).size;
    if (size > MAX_MANIFEST_SIZE_BYTES) {
      throw new Error(`${path.basename(manifestPath)} exceeds the maximum allowed size of 5 MiB.`);
    }
    if (totalManifestBytes + size > MAX_TOTAL_MANIFEST_SIZE_BYTES) {
      throw new Error('Combined dependency files exceed the 10 MiB scan limit.');
    }
    const content = fs.readFileSync(manifestPath, 'utf8');
    const actualSize = Buffer.byteLength(content, 'utf8');
    if (actualSize > MAX_MANIFEST_SIZE_BYTES || totalManifestBytes + actualSize > MAX_TOTAL_MANIFEST_SIZE_BYTES) {
      throw new Error('Combined dependency files exceed the 10 MiB scan limit.');
    }
    totalManifestBytes += actualSize;
    contents.set(manifestPath, content);
    return content;
  };

  if (stats.isFile()) {
    const lower = absolutePath.toLowerCase();
    const content = readManifest(absolutePath);

    if (lower.endsWith('package-lock.json') || lower.endsWith('package.json') || ecosystem === 'npm') {
      const packageJsonPath = lower.endsWith('package.json') ? absolutePath : path.join(path.dirname(absolutePath), 'package.json');
      const packageJsonContent = fs.existsSync(packageJsonPath) && path.basename(packageJsonPath) === 'package.json'
        ? readManifest(packageJsonPath)
        : undefined;

      const packageLockContent = lower.endsWith('package-lock.json') ? content : fs.existsSync(path.join(path.dirname(absolutePath), 'package-lock.json'))
        ? readManifest(path.join(path.dirname(absolutePath), 'package-lock.json'))
        : undefined;

      if (!packageLockContent) {
        throw new Error('NPM scans require a package-lock.json file or a package.json with an adjacent lockfile.');
      }
      return engine.analyzeNpmProject(packageJsonContent, packageLockContent);
    }

    if (lower.endsWith('requirements.txt')) {
      return engine.analyzePythonRequirements(content);
    }

    if (lower.endsWith('poetry.lock')) {
      const pyprojectPath = path.join(path.dirname(absolutePath), 'pyproject.toml');
      const pyprojectContent = fs.existsSync(pyprojectPath) ? readManifest(pyprojectPath) : undefined;
      return engine.analyzePoetryProject(content, pyprojectContent);
    }

    if (ecosystem === 'pypi') return engine.analyzePythonRequirements(content);

    throw new Error(`Unsupported file type: ${absolutePath}. Supported inputs are package-lock.json, package.json, requirements.txt, and poetry.lock.`);
  }

  if (stats.isDirectory()) {
    const directoryEntries = fs.readdirSync(absolutePath);
    const packageJsonPath = directoryEntries.includes('package.json') ? path.join(absolutePath, 'package.json') : undefined;
    const packageLockPath = directoryEntries.includes('package-lock.json') ? path.join(absolutePath, 'package-lock.json') : undefined;
    const requirementsPath = directoryEntries.includes('requirements.txt') ? path.join(absolutePath, 'requirements.txt') : undefined;
    const poetryLockPath = directoryEntries.includes('poetry.lock') ? path.join(absolutePath, 'poetry.lock') : undefined;
    const pyprojectPath = directoryEntries.includes('pyproject.toml') ? path.join(absolutePath, 'pyproject.toml') : undefined;

    if (ecosystem === 'npm' || (!ecosystem && packageLockPath)) {
      if (!packageLockPath) {
        throw new Error('NPM project scans require a package-lock.json file in the supplied directory.');
      }
      return engine.analyzeNpmProject(
        packageJsonPath ? readManifest(packageJsonPath) : undefined,
        readManifest(packageLockPath)
      );
    }

    if (requirementsPath && (ecosystem === 'pypi' || !ecosystem)) {
      return engine.analyzePythonRequirements(readManifest(requirementsPath));
    }

    if (poetryLockPath) {
      return engine.analyzePoetryProject(
        readManifest(poetryLockPath),
        pyprojectPath ? readManifest(pyprojectPath) : undefined
      );
    }

    if (ecosystem === 'pypi') {
      throw new Error('PyPI project scans require a requirements.txt file or poetry.lock file in the supplied directory.');
    }

    throw new Error('The selected directory does not contain a supported dependency manifest. Use package-lock.json, requirements.txt, or poetry.lock.');
  }

  throw new Error(`Unsupported filesystem entry: ${absolutePath}`);
}

function formatTextReport(report: AnalysisReport, threshold: CliSeverityThreshold): string {
  const { summary } = report;
  const thresholdResult = evaluateThreshold(report, threshold);
  const lines = [
    `Ecosystem: ${summary.ecosystem}`,
    `Manifest: ${summary.manifestType}`,
    `Unique packages: ${summary.totalUniquePackages}`,
    `Vulnerable packages: ${summary.vulnerablePackagesCount}`,
    `Total advisory findings: ${summary.totalAdvisoriesCount}`,
    `Critical: ${summary.severityCounts.critical}`,
    `High: ${summary.severityCounts.high}`,
    `Moderate: ${summary.severityCounts.moderate}`,
    `Low: ${summary.severityCounts.low}`,
    `Unknown: ${summary.severityCounts.unknown}`,
    threshold === 'none'
      ? 'Threshold: none (exit 0 unless scanning fails)'
      : `Threshold: ${threshold} (exceeded: ${thresholdResult.exceeded ? 'yes' : 'no'})`
  ];
  for (const warning of report.warnings) lines.push(`Warning: ${warning}`);

  if (report.vulnerablePackages.length === 0) {
    lines.push('No vulnerabilities were detected.');
  } else {
    lines.push('Findings:');
    for (const pkg of report.vulnerablePackages.slice(0, 10)) {
      const topSeverity = pkg.vulnerabilities[0]?.severityLevel ?? 'UNKNOWN';
      lines.push(`- ${pkg.name}@${pkg.version} (${topSeverity})`);
    }
  }

  return lines.join('\n');
}

export async function runCli(
  argv: string[],
  io: { stdout: { write: (chunk: string) => void }; stderr: { write: (chunk: string) => void } } = {
    stdout: process.stdout,
    stderr: process.stderr
  }
): Promise<number> {
  if (argv.includes('--version')) {
    io.stdout.write(`${VEYLIX_VERSION}\n`);
    return 0;
  }

  if (argv[0] === 'secrets') {
    return runSecretsCli(argv.slice(1), io);
  }
  if (argv[0] === 'repository') {
    return runRepositoryCli(argv.slice(1), io);
  }
  if (argv[0] === 'security') {
    return runSecurityCli(argv.slice(1), io);
  }

  const shouldShowBanner = (argv.length === 0 || argv.includes('--banner')) && !process.env.CI;
  if (shouldShowBanner) {
    io.stdout.write(`${renderStartupBanner()}\n`);
    return 0;
  }

  const parsed = parseCliArgs(argv);

  if (parsed.help) {
    io.stdout.write(`${HELP_TEXT}\n`);
    return 0;
  }

  if (parsed.error) {
    io.stderr.write(`Error: ${parsed.error}\n\n${HELP_TEXT}\n`);
    return 2;
  }

  if (!parsed.input) {
    io.stderr.write(`Error: a file or directory path is required.\n\n${HELP_TEXT}\n`);
    return 2;
  }

  try {
    const ecosystem = parsed.ecosystem ?? detectEcosystemFromPath(parsed.input);
    const report = await scanInputPath(
      parsed.input,
      ecosystem,
      parsed.fetchExploitIntelligence,
      parsed.cacheFile
        ? { file: parsed.cacheFile, offline: Boolean(parsed.offline), maxAgeDays: parsed.cacheMaxAgeDays }
        : undefined
    );
    const thresholdResult = evaluateThreshold(report, parsed.threshold);
    const payload = {
      ecosystem: report.summary.ecosystem,
      threshold: parsed.threshold,
      exceeded: thresholdResult.exceeded,
      matchedSeverities: thresholdResult.matchedSeverities,
      summary: report.summary,
      warnings: report.warnings,
      findings: report.vulnerablePackages.map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        isDirect: pkg.isDirect,
        vulnerabilities: pkg.vulnerabilities.map((vuln) => ({
          advisoryId: vuln.advisoryId,
          severityLevel: vuln.severityLevel,
          fixedVersion: vuln.fixedVersion,
          modified: vuln.modified,
          summary: vuln.summary,
          aliases: vuln.aliases,
          exploitability: vuln.exploitability
        }))
      }))
    };

    if (parsed.format === 'json') {
      io.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    } else if (parsed.format === 'text') {
      io.stdout.write(`${formatTextReport(report, parsed.threshold)}\n`);
    } else {
      io.stdout.write(`${serializeReportFormat(report, parsed.format)}\n`);
    }

    return thresholdResult.exceeded ? 1 : 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'An unknown scanner error occurred.';
    io.stderr.write(`Error: ${message}\n`);
    return 2;
  }
}

function runSecretsCli(
  argv: string[],
  io: { stdout: { write: (chunk: string) => void }; stderr: { write: (chunk: string) => void } }
): number {
  let targetPath: string | undefined;
  let format: 'text' | 'json' = 'text';
  let pendingOption: 'path' | 'format' | null = null;

  for (const item of argv) {
    if (pendingOption === 'path') {
      targetPath = item;
      pendingOption = null;
      continue;
    }
    if (pendingOption === 'format') {
      if (item !== 'text' && item !== 'json') {
        io.stderr.write('Error: secrets format must be text or json.\n');
        return 2;
      }
      format = item;
      pendingOption = null;
      continue;
    }
    if (item === '--help' || item === '-h') {
      io.stdout.write('Usage: veylix secrets --path <file-or-directory> [--format text|json]\n');
      io.stdout.write('Potential secret matches are reported with evidence redacted. Exit code 1 indicates at least one match.\n');
      return 0;
    }
    if (item === '--path' || item === '-p') {
      pendingOption = 'path';
      continue;
    }
    if (item === '--format') {
      pendingOption = 'format';
      continue;
    }
    io.stderr.write(`Error: unknown secrets option: ${item}\n`);
    return 2;
  }

  if (pendingOption) {
    io.stderr.write(`Error: missing value for ${pendingOption}.\n`);
    return 2;
  }
  if (!targetPath) {
    io.stderr.write('Error: a file or directory path is required for secret scanning.\n');
    return 2;
  }

  try {
    const result = scanForSecrets(targetPath);
    if (format === 'json') {
      io.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      io.stdout.write(`Scanned ${result.filesScanned} files (${result.bytesScanned} bytes) in ${result.target}.\n`);
      io.stdout.write(`Potential findings: ${result.findings.length}\n`);
      for (const finding of result.findings) {
        io.stdout.write(
          `${finding.severity.toUpperCase()} ${finding.filePath}:${finding.lineNumber} ` +
          `${finding.ruleId} — ${finding.title} (evidence redacted)\n`
        );
        io.stdout.write(`  Remediation: ${finding.remediation}\n`);
      }
      for (const warning of result.warnings) io.stderr.write(`Warning: ${warning}\n`);
    }
    return result.findings.length > 0 ? 1 : 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Secret scan could not be completed.';
    io.stderr.write(`Error: ${message}\n`);
    return 2;
  }
}

const isDirectExecution = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectExecution) {
  const exitCode = await runCli(process.argv.slice(2));
  process.exit(exitCode);
}
