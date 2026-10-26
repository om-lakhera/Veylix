import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

import { VeylixEngine } from './engine.js';
import { AnalysisReport, SupportedEcosystem } from './types.js';

export type CliSeverityThreshold = 'critical' | 'high' | 'moderate' | 'low' | 'none';
export type CliFormat = 'text' | 'json';

export interface ParsedCliArgs {
  help: boolean;
  input?: string;
  ecosystem?: SupportedEcosystem;
  threshold: CliSeverityThreshold;
  format: CliFormat;
  error?: string;
}

const HELP_TEXT = `Veylix CLI

Usage:
  veylix scan --file <path> [--ecosystem npm|pypi] [--threshold critical|high|moderate|low|none] [--format text|json]

Examples:
  veylix scan --file ./package-lock.json --ecosystem npm --threshold high --format json
  veylix scan --file ./requirements.txt --ecosystem pypi --threshold low

Exit codes:
  0  Scan succeeded and the threshold was not exceeded.
  1  Scan succeeded but vulnerabilities met or exceeded the configured threshold.
  2  Invalid arguments or scan execution failure.
`;

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
    format: 'text'
  };

  let pendingKey: 'input' | 'ecosystem' | 'threshold' | 'format' | null = null;

  for (const item of items) {
    if (item === '--help' || item === '-h') {
      parsed.help = true;
      return parsed;
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
          if (normalized === 'json' || normalized === 'text') {
            parsed.format = normalized;
          } else {
            return { ...parsed, error: `Unsupported output format: ${item}. Use json or text.` };
          }
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
  if (lower.endsWith('package-lock.json') || lower.endsWith('package.json') || lower.includes('npm')) {
    return 'npm';
  }
  if (lower.endsWith('requirements.txt') || lower.endsWith('poetry.lock') || lower.endsWith('pyproject.toml') || lower.includes('pypi')) {
    return 'pypi';
  }
  return undefined;
}

async function scanInputPath(inputPath: string, ecosystem?: SupportedEcosystem): Promise<AnalysisReport> {
  const absolutePath = path.resolve(inputPath);
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Input path does not exist: ${inputPath}`);
  }

  const stats = fs.statSync(absolutePath);
  const engine = new VeylixEngine();

  if (stats.isFile()) {
    const lower = absolutePath.toLowerCase();
    const content = fs.readFileSync(absolutePath, 'utf8');

    if (ecosystem === 'npm' || lower.endsWith('package-lock.json') || lower.endsWith('package.json')) {
      const packageJsonPath = lower.endsWith('package.json') ? absolutePath : path.join(path.dirname(absolutePath), 'package.json');
      const packageJsonContent = fs.existsSync(packageJsonPath) && path.basename(packageJsonPath) === 'package.json'
        ? fs.readFileSync(packageJsonPath, 'utf8')
        : undefined;

      const packageLockContent = lower.endsWith('package-lock.json') ? content : fs.existsSync(path.join(path.dirname(absolutePath), 'package-lock.json'))
        ? fs.readFileSync(path.join(path.dirname(absolutePath), 'package-lock.json'), 'utf8')
        : undefined;

      if (!packageLockContent) {
        throw new Error('NPM scans require a package-lock.json file or a package.json with an adjacent lockfile.');
      }
      return engine.analyzeNpmProject(packageJsonContent, packageLockContent);
    }

    if (ecosystem === 'pypi' || lower.endsWith('requirements.txt')) {
      return engine.analyzePythonRequirements(content);
    }

    if (lower.endsWith('poetry.lock')) {
      const pyprojectPath = path.join(path.dirname(absolutePath), 'pyproject.toml');
      const pyprojectContent = fs.existsSync(pyprojectPath) ? fs.readFileSync(pyprojectPath, 'utf8') : undefined;
      return engine.analyzePoetryProject(content, pyprojectContent);
    }

    throw new Error(`Unsupported file type: ${absolutePath}. Supported inputs are package-lock.json, package.json, requirements.txt, and poetry.lock.`);
  }

  if (stats.isDirectory()) {
    const directoryEntries = fs.readdirSync(absolutePath);
    const packageJsonPath = directoryEntries.includes('package.json') ? path.join(absolutePath, 'package.json') : undefined;
    const packageLockPath = directoryEntries.includes('package-lock.json') ? path.join(absolutePath, 'package-lock.json') : undefined;
    const requirementsPath = directoryEntries.includes('requirements.txt') ? path.join(absolutePath, 'requirements.txt') : undefined;
    const poetryLockPath = directoryEntries.includes('poetry.lock') ? path.join(absolutePath, 'poetry.lock') : undefined;
    const pyprojectPath = directoryEntries.includes('pyproject.toml') ? path.join(absolutePath, 'pyproject.toml') : undefined;

    if ((ecosystem === 'npm' || (!ecosystem && packageLockPath))) {
      if (!packageLockPath) {
        throw new Error('NPM project scans require a package-lock.json file in the supplied directory.');
      }
      return engine.analyzeNpmProject(
        packageJsonPath ? fs.readFileSync(packageJsonPath, 'utf8') : undefined,
        fs.readFileSync(packageLockPath, 'utf8')
      );
    }

    if ((ecosystem === 'pypi' || (!ecosystem && requirementsPath))) {
      if (!requirementsPath) {
        throw new Error('PyPI project scans require a requirements.txt file in the supplied directory.');
      }
      return engine.analyzePythonRequirements(fs.readFileSync(requirementsPath, 'utf8'));
    }

    if (poetryLockPath) {
      return engine.analyzePoetryProject(
        fs.readFileSync(poetryLockPath, 'utf8'),
        pyprojectPath ? fs.readFileSync(pyprojectPath, 'utf8') : undefined
      );
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
    if (!ecosystem) {
      throw new Error('Unable to infer an ecosystem. Specify --ecosystem npm or --ecosystem pypi.');
    }

    const report = await scanInputPath(parsed.input, ecosystem);
    const thresholdResult = evaluateThreshold(report, parsed.threshold);
    const payload = {
      ecosystem: report.summary.ecosystem,
      threshold: parsed.threshold,
      exceeded: thresholdResult.exceeded,
      matchedSeverities: thresholdResult.matchedSeverities,
      summary: report.summary,
      findings: report.vulnerablePackages.map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        isDirect: pkg.isDirect,
        vulnerabilities: pkg.vulnerabilities.map((vuln) => ({
          advisoryId: vuln.advisoryId,
          severityLevel: vuln.severityLevel,
          fixedVersion: vuln.fixedVersion,
          summary: vuln.summary,
          aliases: vuln.aliases
        }))
      }))
    };

    if (parsed.format === 'json') {
      io.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    } else {
      io.stdout.write(`${formatTextReport(report, parsed.threshold)}\n`);
    }

    return thresholdResult.exceeded ? 1 : 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'An unknown scanner error occurred.';
    io.stderr.write(`Error: ${message}\n`);
    return 2;
  }
}

const isDirectExecution = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectExecution) {
  const exitCode = await runCli(process.argv.slice(2));
  process.exit(exitCode);
}
