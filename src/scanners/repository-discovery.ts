import * as fs from 'node:fs';
import * as path from 'node:path';

export type RepositoryTargetKind = 'dependency-manifest' | 'source' | 'configuration';
export type RepositoryProjectType =
  | 'npm'
  | 'python'
  | 'rust'
  | 'go'
  | 'java'
  | 'php'
  | 'ruby'
  | 'dotnet'
  | 'dart'
  | 'c-cpp'
  | 'elixir'
  | 'perl'
  | 'unknown';

export interface RepositoryScanTarget {
  path: string;
  kind: RepositoryTargetKind;
  sizeBytes: number;
}

export interface DiscoveredProject {
  id: string;
  root: string;
  type: RepositoryProjectType[];
  languages: string[];
  manifests: string[];
}

export interface RepositoryDiagnostic {
  code: string;
  message: string;
  path?: string;
  severity: 'warning' | 'error';
}

export interface RepositoryDiscovery {
  root: string;
  projects: DiscoveredProject[];
  languages: string[];
  scanTargets: RepositoryScanTarget[];
  diagnostics: RepositoryDiagnostic[];
  entriesVisited: number;
  bytesConsidered: number;
}

export interface RepositoryDiscoveryOptions {
  maxDepth?: number;
  maxFiles?: number;
  maxEntries?: number;
  maxFileSizeBytes?: number;
  maxTotalBytes?: number;
  exclude?: string[];
  signal?: AbortSignal;
  onProgress?: (progress: RepositoryProgress) => void;
}

export interface RepositoryProgress {
  phase: 'discover' | 'scanner';
  scanner?: string;
  state?: 'started' | 'completed' | 'failed' | 'cancelled';
  entriesVisited?: number;
  filesFound?: number;
  completedScanners?: number;
  totalScanners?: number;
}

interface IgnoreRule {
  base: string;
  pattern: string;
  regex: RegExp;
  negated: boolean;
  directoryOnly: boolean;
  basenameOnly: boolean;
}

const DEFAULT_EXCLUDED_DIRECTORIES = new Set([
  '.git', '.hg', '.svn', '.next', '.nuxt', '.cache', '.turbo', '.vercel', '.pytest_cache',
  '.mypy_cache', '.ruff_cache', '.tox', '.venv', 'venv', 'node_modules', 'bower_components',
  'vendor', '__pycache__', 'dist', 'build', 'out', 'target', 'coverage', '.terraform',
  'site-packages', 'bin', 'obj'
]);
const DEFAULT_MAX_DEPTH = 32;
const DEFAULT_MAX_FILES = 50_000;
const DEFAULT_MAX_ENTRIES = 200_000;
const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 500 * 1024 * 1024;
const MAX_GITIGNORE_BYTES = 1024 * 1024;
const MAX_LIMITS = {
  maxDepth: 256,
  maxFiles: 1_000_000,
  maxEntries: 2_000_000,
  maxFileSizeBytes: 1024 * 1024 * 1024,
  maxTotalBytes: 10 * 1024 * 1024 * 1024
} as const;

const SOURCE_EXTENSIONS = new Map<string, string>([
  ['.js', 'JavaScript'], ['.jsx', 'JavaScript'], ['.mjs', 'JavaScript'], ['.cjs', 'JavaScript'],
  ['.ts', 'TypeScript'], ['.tsx', 'TypeScript'], ['.mts', 'TypeScript'], ['.cts', 'TypeScript'],
  ['.py', 'Python'], ['.pyi', 'Python'], ['.go', 'Go'], ['.rs', 'Rust'],
  ['.java', 'Java'], ['.kt', 'Kotlin'], ['.kts', 'Kotlin'], ['.scala', 'Scala'],
  ['.c', 'C'], ['.h', 'C/C++'], ['.cc', 'C++'], ['.cpp', 'C++'], ['.cxx', 'C++'],
  ['.hpp', 'C++'], ['.hh', 'C++'], ['.cs', 'C#'], ['.fs', 'F#'], ['.fsx', 'F#'],
  ['.rb', 'Ruby'], ['.php', 'PHP'], ['.swift', 'Swift'], ['.dart', 'Dart'],
  ['.sh', 'Shell'], ['.bash', 'Shell'], ['.zsh', 'Shell'], ['.pl', 'Perl'],
  ['.ex', 'Elixir'], ['.exs', 'Elixir'], ['.erl', 'Erlang'], ['.hrl', 'Erlang'],
  ['.lua', 'Lua'], ['.r', 'R'], ['.R', 'R'], ['.scala', 'Scala']
]);

const CONFIG_EXTENSIONS = new Set([
  '.yaml', '.yml', '.json', '.toml', '.tf', '.tfvars', '.hcl', '.conf', '.ini', '.env',
  '.properties', '.xml', '.cfg', '.config', '.dockerfile', '.txt', '.gradle', '.lock'
]);

const MANIFEST_TYPES = new Map<string, RepositoryProjectType>([
  ['package.json', 'npm'], ['package-lock.json', 'npm'], ['npm-shrinkwrap.json', 'npm'],
  ['yarn.lock', 'npm'], ['pnpm-lock.yaml', 'npm'], ['bun.lock', 'npm'], ['bun.lockb', 'npm'],
  ['requirements.txt', 'python'], ['pyproject.toml', 'python'], ['poetry.lock', 'python'],
  ['pipfile', 'python'], ['pipfile.lock', 'python'], ['uv.lock', 'python'],
  ['Cargo.toml', 'rust'], ['Cargo.lock', 'rust'],
  ['go.mod', 'go'], ['go.sum', 'go'], ['pom.xml', 'java'], ['build.gradle', 'java'],
  ['build.gradle.kts', 'java'], ['composer.json', 'php'], ['composer.lock', 'php'],
  ['gemfile', 'ruby'], ['gemfile.lock', 'ruby'],
  ['pubspec.yaml', 'dart'], ['pubspec.lock', 'dart'], ['cmakelists.txt', 'c-cpp'],
  ['conanfile.txt', 'c-cpp'], ['conanfile.py', 'c-cpp'], ['vcpkg.json', 'c-cpp'],
  ['mix.exs', 'elixir'], ['mix.lock', 'elixir'], ['cpanfile', 'perl']
]);

function isWithinRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}

function globToRegExp(pattern: string): RegExp {
  let source = '^';
  for (let index = 0; index < pattern.length; index++) {
    const character = pattern[index]!;
    if (character === '*') {
      if (pattern[index + 1] === '*') {
        while (pattern[index + 1] === '*') index++;
        if (pattern[index + 1] === '/') {
          index++;
          source += '(?:.*/)?';
        } else {
          source += '.*';
        }
      } else {
        source += '[^/]*';
      }
    } else if (character === '?') {
      source += '[^/]';
    } else {
      source += character.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
    }
  }
  return new RegExp(`${source}$`);
}

function parseIgnoreRules(content: string, base: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    let pattern = rawLine.trimEnd();
    if (!pattern || pattern.startsWith('#')) continue;
    if (pattern.startsWith('\\#') || pattern.startsWith('\\!')) pattern = pattern.slice(1);
    let negated = false;
    if (pattern.startsWith('!')) {
      negated = true;
      pattern = pattern.slice(1);
    }
    if (!pattern) continue;
    const directoryOnly = pattern.endsWith('/');
    const anchored = pattern.startsWith('/');
    pattern = pattern.replace(/^\/+|\/+$/g, '');
    if (!pattern) continue;
    const basenameOnly = !pattern.includes('/');
    rules.push({
      base,
      pattern,
      regex: globToRegExp(pattern),
      negated,
      directoryOnly,
      basenameOnly: basenameOnly && !anchored
    });
  }
  return rules;
}

function ruleMatches(rule: IgnoreRule, relativePath: string, isDirectory: boolean): boolean {
  const fromBase = path.relative(rule.base, relativePath).split(path.sep).join('/');
  if (!fromBase || fromBase === '..' || fromBase.startsWith('../')) return false;
  const components = fromBase.split('/');
  if (rule.basenameOnly) {
    const end = rule.directoryOnly && !isDirectory ? components.length - 1 : components.length;
    for (let index = 0; index < end; index++) {
      if (rule.regex.test(components[index]!)) return true;
    }
    return false;
  }
  if (rule.directoryOnly && !isDirectory) {
    const parentPath = components.slice(0, -1).join('/');
    return Boolean(parentPath) && rule.regex.test(parentPath);
  }
  return rule.regex.test(fromBase);
}

function isIgnored(relativePath: string, isDirectory: boolean, rules: IgnoreRule[]): boolean {
  let ignored = false;
  for (const rule of rules) {
    if (ruleMatches(rule, relativePath, isDirectory)) ignored = !rule.negated;
  }
  return ignored;
}

function manifestType(name: string): RepositoryProjectType | undefined {
  const lower = name.toLowerCase();
  const direct = MANIFEST_TYPES.get(lower);
  if (direct) return direct;
  if (lower.startsWith('requirements') && lower.endsWith('.txt')) return 'python';
  if (lower.endsWith('.csproj') || lower.endsWith('.fsproj')) return 'dotnet';
  if (lower === 'yarn.lock' || lower === 'pnpm-lock.yaml' || lower === 'bun.lock' || lower === 'bun.lockb') return 'npm';
  return undefined;
}

function targetKind(name: string, relativePath: string): RepositoryTargetKind | undefined {
  if (manifestType(name)) return 'dependency-manifest';
  if (/^(?:Dockerfile(?:\..*)?|Containerfile)$/i.test(name) ||
      /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(relativePath) ||
      /\.(?:tf|tfvars?|hcl)$/i.test(name) ||
      /\.(?:ya?ml|json)$/i.test(name)) return 'configuration';
  if (SOURCE_EXTENSIONS.has(path.extname(name))) return 'source';
  if (CONFIG_EXTENSIONS.has(path.extname(name)) || name === '.env') return 'configuration';
  return undefined;
}

function projectRootFor(relativeFile: string, manifestRoots: Set<string>): string {
  let current = path.dirname(relativeFile);
  while (current !== '.' && current !== '') {
    if (manifestRoots.has(current)) return current;
    current = path.dirname(current);
  }
  return '.';
}

function configuredLimit(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string
): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

export function discoverRepository(
  targetPath: string,
  options: RepositoryDiscoveryOptions = {}
): RepositoryDiscovery {
  if (typeof targetPath !== 'string' || targetPath.trim() === '') {
    throw new Error('A repository directory is required.');
  }
  const absoluteRoot = path.resolve(targetPath);
  let rootStat: fs.Stats;
  try {
    rootStat = fs.lstatSync(absoluteRoot);
  } catch {
    throw new Error(`Repository path does not exist: ${targetPath}`);
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('Repository scan target must be a regular directory; symbolic links are not followed.');
  }
  const root = fs.realpathSync(absoluteRoot);
  const maxDepth = configuredLimit(options.maxDepth, DEFAULT_MAX_DEPTH, 0, MAX_LIMITS.maxDepth, 'maxDepth');
  const maxFiles = configuredLimit(options.maxFiles, DEFAULT_MAX_FILES, 1, MAX_LIMITS.maxFiles, 'maxFiles');
  const maxEntries = configuredLimit(options.maxEntries, DEFAULT_MAX_ENTRIES, 1, MAX_LIMITS.maxEntries, 'maxEntries');
  const maxFileSizeBytes = configuredLimit(options.maxFileSizeBytes, DEFAULT_MAX_FILE_SIZE, 1, MAX_LIMITS.maxFileSizeBytes, 'maxFileSizeBytes');
  const maxTotalBytes = configuredLimit(options.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES, 1, MAX_LIMITS.maxTotalBytes, 'maxTotalBytes');
  const exclusionRules = (options.exclude ?? []).map((pattern) => {
    const cleaned = pattern.trim();
    if (!cleaned || cleaned.startsWith('!')) {
      throw new Error('Exclusion patterns must be non-empty and cannot start with "!".');
    }
    const directoryOnly = cleaned.endsWith('/');
    const normalized = cleaned.replace(/^\/+|\/+$/g, '');
    if (!normalized) throw new Error('Exclusion patterns must identify a path.');
    const anchored = cleaned.startsWith('/');
    return {
      base: '',
      pattern: normalized,
      regex: globToRegExp(normalized),
      negated: false,
      directoryOnly,
      basenameOnly: !normalized.includes('/') && !anchored,
    };
  });
  const diagnostics: RepositoryDiagnostic[] = [];
  const candidates: Array<{ relative: string; absolute: string; kind: RepositoryTargetKind; size: number }> = [];
  const manifestRoots = new Map<string, Set<RepositoryProjectType>>();
  const manifestPaths = new Map<string, string[]>();
  const sourceFiles: string[] = [];
  let entriesVisited = 0;
  let bytesConsidered = 0;
  let fileLimitReported = false;
  let entryLimitReported = false;
  let totalLimitReported = false;
  let stopped = false;
  const progressInterval = 256;

  const checkCancelled = (): void => {
    if (options.signal?.aborted) {
      throw new Error('Repository discovery was cancelled.');
    }
  };
  const reportProgress = (found: number): void => {
    if (entriesVisited % progressInterval === 0 || found < 20) {
      options.onProgress?.({ phase: 'discover', entriesVisited, filesFound: found });
    }
  };

  const visit = (directory: string, relativeDirectory: string, depth: number, inheritedRules: IgnoreRule[]): void => {
    if (stopped) return;
    checkCancelled();
    if (depth > maxDepth) {
      diagnostics.push({
        code: 'discovery.max-depth',
        message: `Skipped directories below depth ${maxDepth}.`,
        path: relativeDirectory || '.',
        severity: 'warning'
      });
      return;
    }
    let rules = inheritedRules;
    const ignoreFile = path.join(directory, '.gitignore');
    try {
      const ignoreStat = fs.lstatSync(ignoreFile);
      if (ignoreStat.isFile() && !ignoreStat.isSymbolicLink() && ignoreStat.size <= MAX_GITIGNORE_BYTES) {
        const content = fs.readFileSync(ignoreFile, 'utf8');
        rules = [...inheritedRules, ...parseIgnoreRules(content, relativeDirectory)];
      } else if (ignoreStat.size > MAX_GITIGNORE_BYTES) {
        diagnostics.push({
          code: 'discovery.gitignore-too-large',
          message: 'Ignored .gitignore file larger than 1 MiB.',
          path: path.relative(root, ignoreFile).split(path.sep).join('/'),
          severity: 'warning'
        });
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        diagnostics.push({
          code: 'discovery.gitignore-read',
          message: `Could not read .gitignore: ${error instanceof Error ? error.message : 'unknown error'}.`,
          path: path.relative(root, ignoreFile).split(path.sep).join('/'),
          severity: 'warning'
        });
      }
    }

    let entries: fs.Dirent[];
    try {
      entries = [];
      const handle = fs.opendirSync(directory);
      try {
        const remainingEntries = maxEntries - entriesVisited;
        while (entries.length <= remainingEntries) {
          const entry = handle.readSync();
          if (!entry) break;
          entries.push(entry);
        }
      } finally {
        handle.closeSync();
      }
    } catch (error) {
      diagnostics.push({
        code: 'discovery.directory-read',
        message: `Could not read directory: ${error instanceof Error ? error.message : 'unknown error'}.`,
        path: relativeDirectory || '.',
        severity: 'warning'
      });
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (stopped) return;
      checkCancelled();
      entriesVisited++;
      if (entriesVisited > maxEntries) {
        if (!entryLimitReported) {
          diagnostics.push({
            code: 'discovery.max-entries',
            message: `Stopped after reaching the configured entry limit (${maxEntries}); results may be incomplete.`,
            severity: 'warning'
          });
          entryLimitReported = true;
        }
        stopped = true;
        return;
      }
      const absolute = path.join(directory, entry.name);
      const relative = path.posix.join(relativeDirectory.split(path.sep).join('/'), entry.name);
      if (!isWithinRoot(root, absolute)) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (DEFAULT_EXCLUDED_DIRECTORIES.has(entry.name.toLowerCase())) continue;
        if (isIgnored(relative, true, [...rules, ...exclusionRules])) continue;
        visit(absolute, relative, depth + 1, rules);
        continue;
      }
      if (!entry.isFile() || isIgnored(relative, false, [...rules, ...exclusionRules])) continue;
      let stat: fs.Stats;
      try {
        stat = fs.lstatSync(absolute);
      } catch {
        diagnostics.push({ code: 'discovery.file-stat', message: 'Could not inspect file metadata.', path: relative, severity: 'warning' });
        continue;
      }
      const detectedManifestType = manifestType(entry.name);
      if (detectedManifestType) {
        const projectRoot = path.posix.dirname(relative) || '.';
        const types = manifestRoots.get(projectRoot) ?? new Set<RepositoryProjectType>();
        types.add(detectedManifestType);
        manifestRoots.set(projectRoot, types);
        const files = manifestPaths.get(projectRoot) ?? [];
        files.push(relative);
        manifestPaths.set(projectRoot, files);
      }
      if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) sourceFiles.push(relative);
      const kind = targetKind(entry.name, relative);
      if (!kind) continue;
      if (stat.size > maxFileSizeBytes) {
        diagnostics.push({
          code: 'discovery.max-file-size',
          message: `Skipped file larger than the configured per-file limit (${maxFileSizeBytes} bytes).`,
          path: relative,
          severity: 'warning'
        });
        continue;
      }
      if (bytesConsidered + stat.size > maxTotalBytes) {
        if (!totalLimitReported) {
          diagnostics.push({
            code: 'discovery.max-total-bytes',
            message: `Stopped after reaching the configured total byte limit (${maxTotalBytes}); results may be incomplete.`,
            severity: 'warning'
          });
          totalLimitReported = true;
        }
        stopped = true;
        return;
      }
      bytesConsidered += stat.size;
      if (candidates.length >= maxFiles) {
        if (!fileLimitReported) {
          diagnostics.push({
            code: 'discovery.max-files',
            message: `Stopped after reaching the configured file limit (${maxFiles}); results may be incomplete.`,
            severity: 'warning'
          });
          fileLimitReported = true;
        }
        stopped = true;
        return;
      }
      candidates.push({ relative, absolute, kind, size: stat.size });
      reportProgress(candidates.length);
    }
  };

  visit(root, '', 0, []);
  const targetProjects = new Map<string, { types: Set<RepositoryProjectType>; languages: Set<string>; manifests: string[] }>();
  const ensureProject = (projectRoot: string): { types: Set<RepositoryProjectType>; languages: Set<string>; manifests: string[] } => {
    const existing = targetProjects.get(projectRoot);
    if (existing) return existing;
    const created = {
      types: new Set(manifestRoots.get(projectRoot) ?? []),
      languages: new Set<string>(),
      manifests: [...(manifestPaths.get(projectRoot) ?? [])]
    };
    targetProjects.set(projectRoot, created);
    return created;
  };

  for (const candidate of candidates) {
    const detectedType = manifestType(path.basename(candidate.relative));
    let projectRoot = detectedType
      ? path.posix.dirname(candidate.relative) || '.'
      : projectRootFor(candidate.relative, new Set(manifestRoots.keys()));
    if (!isWithinRoot(root, path.resolve(root, projectRoot))) projectRoot = root;
    const project = ensureProject(projectRoot);
    const language = SOURCE_EXTENSIONS.get(path.extname(candidate.relative));
    if (language) project.languages.add(language);
    if (detectedType) {
      project.types.add(detectedType);
    }
  }

  for (const relativePath of sourceFiles) {
    const projectRoot = projectRootFor(relativePath, new Set(manifestRoots.keys()));
    const project = ensureProject(projectRoot);
    const language = SOURCE_EXTENSIONS.get(path.extname(relativePath));
    if (language) project.languages.add(language);
  }
  for (const projectRoot of manifestRoots.keys()) ensureProject(projectRoot);
  if (targetProjects.size === 0 && (candidates.length > 0 || sourceFiles.length > 0)) ensureProject('.');
  const projects: DiscoveredProject[] = Array.from(targetProjects.entries())
    .map(([projectRoot, project]) => {
      const relativeRoot = projectRoot === '.' || projectRoot === root
        ? '.'
        : path.relative(root, path.resolve(root, projectRoot)).split(path.sep).join('/');
      return {
        id: relativeRoot,
        root: relativeRoot,
        type: [...project.types].sort(),
        languages: [...project.languages].sort(),
        manifests: project.manifests.sort()
      };
    })
    .sort((left, right) => left.root.localeCompare(right.root));
  const languages = [...new Set(projects.flatMap((project) => project.languages))].sort();
  const scanTargets = candidates.map(({ relative, kind, size }) => ({ path: relative, kind, sizeBytes: size }))
    .sort((left, right) => left.path.localeCompare(right.path));
  options.onProgress?.({ phase: 'discover', entriesVisited, filesFound: scanTargets.length });
  return {
    root,
    projects,
    languages,
    scanTargets,
    diagnostics,
    entriesVisited,
    bytesConsidered
  };
}
