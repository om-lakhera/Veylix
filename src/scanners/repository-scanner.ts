import * as fs from 'node:fs';
import * as path from 'node:path';
import { VeylixEngine } from '../engine.js';
import { AnalysisReport } from '../types.js';
import {
  DiscoveredProject,
  RepositoryDiagnostic,
  RepositoryDiscovery,
  RepositoryDiscoveryOptions,
  RepositoryProgress,
  RepositoryProjectType,
  discoverRepository
} from './repository-discovery.js';
import {
  DeclarativeRule,
  LocalSecurityScanOptions,
  scanLocalSecurity
} from './local-security-scanner.js';
import { normalizeDependencyFinding, normalizeSecurityFinding, UnifiedFinding } from './unified-finding.js';

export type RepositoryScanProgress = RepositoryProgress;

export interface RepositoryScannerContext {
  discovery: RepositoryDiscovery;
  signal?: AbortSignal;
  onProgress?: (progress: RepositoryScanProgress) => void;
}

export interface RepositoryScannerResult {
  findings: UnifiedFinding[];
  diagnostics?: RepositoryDiagnostic[];
}

export interface RepositoryScanner {
  id: string;
  version: string;
  supportedFileTypes: readonly string[];
  languages: readonly string[];
  scan(context: RepositoryScannerContext): Promise<RepositoryScannerResult> | RepositoryScannerResult;
}

export interface RepositoryScanOptions extends RepositoryDiscoveryOptions {
  customRules?: DeclarativeRule[];
  allowedLicenses?: string[];
  scanners?: RepositoryScanner[];
}

export interface RepositoryScanReport {
  root: string;
  projects: DiscoveredProject[];
  languages: string[];
  scanTargets: RepositoryDiscovery['scanTargets'];
  findings: UnifiedFinding[];
  diagnostics: RepositoryDiagnostic[];
  scanners: Array<{ id: string; version: string }>;
  cancelled: boolean;
  partial: boolean;
}

const LOCAL_SCANNER_ID = 'veylix.local-security';
const DEPENDENCY_SCANNER_ID = 'veylix.dependencies';
const SCANNER_VERSION = '1.0.0';

function aborted(signal?: AbortSignal): boolean {
  return Boolean(signal?.aborted);
}

function diagnostic(
  code: string,
  message: string,
  severity: RepositoryDiagnostic['severity'] = 'warning',
  filePath?: string
): RepositoryDiagnostic {
  return { code, message, severity, ...(filePath ? { path: filePath } : {}) };
}

function withinRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

function safeRead(discovery: RepositoryDiscovery, relativePath: string): string {
  const absolute = path.resolve(discovery.root, relativePath);
  if (!withinRoot(discovery.root, absolute)) throw new Error('Manifest path escaped the selected repository.');
  const discoveredTarget = discovery.scanTargets.find((target) => target.path === relativePath);
  if (!discoveredTarget) throw new Error('Manifest was not included in the repository scan targets.');
  const stat = fs.lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Manifest is not a regular file.');
  if (stat.size !== discoveredTarget.sizeBytes) throw new Error('Manifest changed after repository discovery; rescan before analysis.');
  const realPath = fs.realpathSync(absolute);
  if (!withinRoot(discovery.root, realPath)) throw new Error('Manifest resolves outside the selected repository.');
  const content = fs.readFileSync(absolute, 'utf8');
  if (Buffer.byteLength(content, 'utf8') !== discoveredTarget.sizeBytes) {
    throw new Error('Manifest changed while it was being read; rescan before analysis.');
  }
  return content;
}

function projectManifests(project: DiscoveredProject, discovery: RepositoryDiscovery): string[] {
  const prefix = project.root === '.' ? '' : `${project.root}/`;
  return discovery.scanTargets
    .filter((target) => target.kind === 'dependency-manifest' && target.path.startsWith(prefix) &&
      path.posix.dirname(target.path) === project.root)
    .map((target) => path.posix.basename(target.path));
}

function projectType(project: DiscoveredProject, type: RepositoryProjectType): boolean {
  return project.type.includes(type);
}

function abortableFetch(signal?: AbortSignal): typeof fetch {
  return (input, init = {}) => {
    const controller = new AbortController();
    const signals = [signal, init.signal].filter((item): item is AbortSignal => Boolean(item));
    const listeners = signals.map((source) => {
      const abort = (): void => controller.abort(source.reason);
      if (source.aborted) abort();
      else source.addEventListener('abort', abort, { once: true });
      return { source, abort };
    });
    return fetch(input, { ...init, signal: controller.signal }).finally(() => {
      for (const { source, abort } of listeners) source.removeEventListener('abort', abort);
    });
  };
}

function createDependencyScanner(): RepositoryScanner {
  return {
    id: DEPENDENCY_SCANNER_ID,
    version: SCANNER_VERSION,
    supportedFileTypes: ['package-lock.json', 'requirements.txt', 'poetry.lock'],
    languages: ['JavaScript', 'TypeScript', 'Python'],
    async scan(context) {
      const findings: UnifiedFinding[] = [];
      const diagnostics: RepositoryDiagnostic[] = [];
      const engine = new VeylixEngine({
        osvOptions: { fetchFn: abortableFetch(context.signal) }
      });
      const projectsToScan = context.discovery.projects.flatMap((project) => [
        ...(projectType(project, 'npm') ? [{ project, ecosystem: 'npm' as const }] : []),
        ...(projectType(project, 'python') ? [{ project, ecosystem: 'pypi' as const }] : [])
      ]);
      for (let index = 0; index < projectsToScan.length; index++) {
        if (aborted(context.signal)) break;
        const { project, ecosystem } = projectsToScan[index]!;
        const manifests = projectManifests(project, context.discovery);
        const npmLock = manifests.includes('package-lock.json') ? 'package-lock.json'
          : manifests.includes('npm-shrinkwrap.json') ? 'npm-shrinkwrap.json' : undefined;
        const pythonPoetry = manifests.includes('poetry.lock') ? 'poetry.lock' : undefined;
        const pythonRequirements = manifests.includes('requirements.txt') ? 'requirements.txt' : undefined;
        const projectPath = project.root;
        try {
          let report: AnalysisReport | undefined;
          let manifestPath: string | undefined;
          if (ecosystem === 'npm' && npmLock) {
            manifestPath = path.posix.join(projectPath, npmLock);
            const packageJsonPath = manifests.includes('package.json')
              ? path.posix.join(projectPath, 'package.json')
              : undefined;
            report = await engine.analyzeNpmProject(
              packageJsonPath ? safeRead(context.discovery, packageJsonPath) : undefined,
              safeRead(context.discovery, manifestPath)
            );
          } else if (ecosystem === 'pypi' && pythonPoetry) {
            manifestPath = path.posix.join(projectPath, pythonPoetry);
            const pyprojectPath = manifests.includes('pyproject.toml')
              ? path.posix.join(projectPath, 'pyproject.toml')
              : undefined;
            report = await engine.analyzePoetryProject(
              safeRead(context.discovery, manifestPath),
              pyprojectPath ? safeRead(context.discovery, pyprojectPath) : undefined
            );
          } else if (ecosystem === 'pypi' && pythonRequirements) {
            manifestPath = path.posix.join(projectPath, pythonRequirements);
            report = await engine.analyzePythonRequirements(safeRead(context.discovery, manifestPath));
          } else {
            const missingLock = ecosystem === 'npm'
              ? `No supported npm lockfile was discovered; Veylix currently analyzes package-lock.json and npm-shrinkwrap.json${project.manifests.some((name) => /(?:yarn\.lock|pnpm-lock\.yaml|bun\.lock)/i.test(name)) ? ', not the detected alternative lockfile' : ''}.`
              : `No supported Python lockfile or requirements file was discovered; Veylix currently analyzes poetry.lock and requirements*.txt${project.manifests.some((name) => /(?:uv\.lock|pipfile)/i.test(name)) ? ', not the detected alternative lockfile' : ''}.`;
            diagnostics.push(diagnostic('dependency.lockfile-missing', missingLock, 'warning', project.root));
            continue;
          }
          if (report && manifestPath) {
            for (const pkg of report.packages) {
              for (const advisory of pkg.vulnerabilities) {
                findings.push(normalizeDependencyFinding({
                  packageName: pkg.name,
                  version: pkg.version,
                  ecosystem: pkg.ecosystem,
                  direct: pkg.isDirect,
                  advisory,
                  filePath: manifestPath,
                  project: project.root,
                  scannerId: DEPENDENCY_SCANNER_ID
                }));
              }
            }
            for (const warning of report.warnings) {
              diagnostics.push(diagnostic('dependency.analysis-warning', warning, 'warning', manifestPath));
            }
          }
        } catch (error) {
          if (aborted(context.signal)) break;
          diagnostics.push(diagnostic(
            'dependency.project-failed',
            error instanceof Error ? error.message : 'Dependency scan failed.',
            'error',
            project.root
          ));
        }
        context.onProgress?.({
          phase: 'scanner',
          scanner: DEPENDENCY_SCANNER_ID,
          state: 'completed',
          completedScanners: index + 1,
          totalScanners: projectsToScan.length
        });
      }
      for (const project of context.discovery.projects) {
        const supported = projectType(project, 'npm') || projectType(project, 'python');
        if (!supported && project.type.length) {
          diagnostics.push(diagnostic(
            'dependency.ecosystem-unsupported',
            `Dependency vulnerability analysis is not implemented for detected project type(s): ${project.type.join(', ')}.`,
            'warning',
            project.root
          ));
        }
      }
      return { findings, diagnostics };
    }
  };
}

function createLocalSecurityScanner(options: RepositoryScanOptions): RepositoryScanner {
  return {
    id: LOCAL_SCANNER_ID,
    version: SCANNER_VERSION,
    supportedFileTypes: ['source files', 'configuration files', 'GitHub Actions workflows'],
    languages: ['*'],
    scan(context) {
      if (aborted(context.signal)) return { findings: [] };
      const result = scanLocalSecurity(context.discovery.root, {
        customRules: options.customRules,
        allowedLicenses: options.allowedLicenses,
        maxFiles: options.maxFiles,
        maxDepth: options.maxDepth,
        maxFileSizeBytes: options.maxFileSizeBytes,
        maxTotalBytes: options.maxTotalBytes,
        maxEntries: options.maxEntries,
        signal: context.signal,
        discoveredFiles: context.discovery.scanTargets
          .filter((target) => !/^(?:Dockerfile(?:\..*)?|Containerfile)$/i.test(path.posix.basename(target.path)))
          .map((target) => path.resolve(context.discovery.root, target.path))
      } satisfies LocalSecurityScanOptions);
      const projectsByDepth = [...context.discovery.projects]
        .sort((left, right) => right.root.length - left.root.length);
      const findings = result.findings.map((finding) => {
        const project = projectsByDepth.find((candidate) =>
          finding.filePath && (candidate.root === '.' || finding.filePath === candidate.root ||
            finding.filePath.startsWith(`${candidate.root}/`))
        );
        return normalizeSecurityFinding(finding, LOCAL_SCANNER_ID, project?.root);
      });
      const diagnostics = result.warnings.map((message) => diagnostic('local-security.warning', message));
      return { findings, diagnostics };
    }
  };
}

export function createRepositoryScanners(options: RepositoryScanOptions = {}): RepositoryScanner[] {
  return [createLocalSecurityScanner(options), createDependencyScanner()];
}

export async function scanRepository(
  targetPath: string,
  options: RepositoryScanOptions = {}
): Promise<RepositoryScanReport> {
  const scanners = options.scanners ?? createRepositoryScanners(options);
  let discovery: RepositoryDiscovery;
  try {
    discovery = discoverRepository(targetPath, options);
  } catch (error) {
    if (!aborted(options.signal)) throw error;
    return {
      root: path.resolve(targetPath),
      projects: [],
      languages: [],
      scanTargets: [],
      findings: [],
      diagnostics: [diagnostic('scan.cancelled', 'Repository discovery was cancelled.')],
      scanners: scanners.map(({ id, version }) => ({ id, version })),
      cancelled: true,
      partial: true
    };
  }
  const findings: UnifiedFinding[] = [];
  const findingIds = new Set<string>();
  const diagnostics = [...discovery.diagnostics];
  let cancelled = false;
  for (let index = 0; index < scanners.length; index++) {
    const scanner = scanners[index]!;
    if (aborted(options.signal)) {
      cancelled = true;
      diagnostics.push(diagnostic('scan.cancelled', 'Repository scan was cancelled before all scanners completed.'));
      break;
    }
    options.onProgress?.({
      phase: 'scanner',
      scanner: scanner.id,
      state: 'started',
      completedScanners: index,
      totalScanners: scanners.length
    });
    try {
      const result = await scanner.scan({
        discovery,
        signal: options.signal,
        onProgress: options.onProgress
      });
      for (const finding of result.findings) {
        if (!finding.id.trim()) {
          diagnostics.push(diagnostic('scanner.finding-id-missing', `${scanner.id} returned a finding without an ID.`, 'error'));
        } else if (findingIds.has(finding.id)) {
          diagnostics.push(diagnostic('scanner.finding-id-duplicate', `${scanner.id} returned a duplicate finding ID.`, 'warning'));
        } else {
          findingIds.add(finding.id);
          findings.push(finding);
        }
      }
      diagnostics.push(...(result.diagnostics ?? []));
      options.onProgress?.({
        phase: 'scanner',
        scanner: scanner.id,
        state: 'completed',
        completedScanners: index + 1,
        totalScanners: scanners.length
      });
    } catch (error) {
      if (aborted(options.signal)) {
        cancelled = true;
        diagnostics.push(diagnostic('scan.cancelled', 'Repository scan was cancelled; the active scanner stopped.'));
        break;
      }
      const message = error instanceof Error ? error.message : 'Scanner failed unexpectedly.';
      diagnostics.push(diagnostic(`scanner.${scanner.id}.failed`, `${scanner.id} failed: ${message}`, 'error'));
      options.onProgress?.({
        phase: 'scanner',
        scanner: scanner.id,
        state: 'failed',
        completedScanners: index + 1,
        totalScanners: scanners.length
      });
    }
    if (aborted(options.signal)) {
      cancelled = true;
      if (index < scanners.length - 1) {
        diagnostics.push(diagnostic('scan.cancelled', 'Repository scan was cancelled; remaining scanners were not run.'));
      }
      break;
    }
  }
  findings.sort((left, right) =>
    (left.filePath ?? '').localeCompare(right.filePath ?? '') ||
    left.ruleId.localeCompare(right.ruleId) ||
    left.id.localeCompare(right.id)
  );
  const scannerSummaries = scanners.map(({ id, version }) => ({ id, version }));
  return {
    root: discovery.root,
    projects: discovery.projects,
    languages: discovery.languages,
    scanTargets: discovery.scanTargets,
    findings,
    diagnostics,
    scanners: scannerSummaries,
    cancelled,
    partial: cancelled || diagnostics.some((entry) => entry.severity === 'error' || entry.severity === 'warning')
  };
}
