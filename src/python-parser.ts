import { ManifestParseResult, PackageIdentifier } from './types.js';

export interface PythonParseOptions {
  maxFileSize?: number; // default 10MB
}

const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

/**
 * Normalizes Python package names according to PEP 503 (lowercase, dashes instead of underscores/dots)
 */
export function canonicalizePythonPackageName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * Parses requirements.txt contents safely.
 * Handles comments, options (-r, -i, etc.), environment markers (; python_version),
 * extras (package[extra]), and version specifiers (==, ~=, >=, etc.).
 */
export function parseRequirementsTxt(
  content?: string | null,
  options: PythonParseOptions = {}
): ManifestParseResult {
  const maxBytes = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const warnings: string[] = [];

  if (!content || content.trim().length === 0) {
    throw new Error('A requirements.txt file content is required.');
  }

  if (Buffer.byteLength(content, 'utf8') > maxBytes) {
    throw new Error(`requirements.txt exceeds maximum allowed size of ${maxBytes} bytes.`);
  }

  const lines = content.split(/\r?\n/);
  const packageMap = new Map<string, PackageIdentifier>();

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    let rawLine = lines[lineIndex]!.trim();

    // Skip empty lines or pure comments
    if (!rawLine || rawLine.startsWith('#')) {
      continue;
    }

    // Strip inline comments if not inside quotes
    const commentIdx = rawLine.indexOf('#');
    if (commentIdx !== -1) {
      rawLine = rawLine.substring(0, commentIdx).trim();
    }
    if (!rawLine) continue;

    // Skip pip options and flags (-r, --index-url, -f, -e, etc.)
    if (rawLine.startsWith('-') || rawLine.startsWith('--')) {
      if (rawLine.startsWith('-r ') || rawLine.startsWith('--requirement ')) {
        warnings.push(`Recursive requirement reference skipped on line ${lineIndex + 1}: ${rawLine}`);
      } else if (rawLine.startsWith('-e ') || rawLine.startsWith('--editable ')) {
        warnings.push(`Editable install skipped on line ${lineIndex + 1}: "${rawLine}". Editable packages cannot be precisely analyzed without a concrete version.`);
      }
      continue;
    }

    // Strip environment markers (e.g. ; python_version < "3.8")
    let markerPart = '';
    const markerIdx = rawLine.indexOf(';');
    if (markerIdx !== -1) {
      markerPart = rawLine.substring(markerIdx + 1).trim();
      rawLine = rawLine.substring(0, markerIdx).trim();
    }
    if (!rawLine) continue;

    // Handle editable or VCS lines (e.g. git+https://...)
    if (rawLine.includes('://') || rawLine.includes('git+')) {
      warnings.push(`VCS / URL dependency cannot be precisely resolved on line ${lineIndex + 1}: ${rawLine}`);
      continue;
    }

    // Extract package name and version specifiers
    // Specifier regex per PEP 440: ==, ~=, >=, <=, >, <, !=, ===
    const specifierMatch = rawLine.match(/^([A-Za-z0-9_.\-]+)(?:\[([A-Za-z0-9_.,\- ]+)\])?\s*([=~><!].*)?$/);

    if (!specifierMatch) {
      warnings.push(`Unrecognized requirement format on line ${lineIndex + 1}: "${rawLine}"`);
      continue;
    }

    const rawName = specifierMatch[1]!;
    const canonicalName = canonicalizePythonPackageName(rawName);
    const specifiers = specifierMatch[3]?.trim();

    let version = '*';
    let declaredConstraint: string | undefined;

    if (specifiers) {
      declaredConstraint = specifiers;

      // Check for exact pinned version: e.g. == 2.28.1
      const exactMatch = specifiers.match(/^===?\s*([0-9A-Za-z.\-_+]+)/);
      if (exactMatch) {
        version = exactMatch[1]!.trim();
      } else {
        // Range or compatible release (e.g. ~= 1.26.5 or >= 2.0.0, < 3.0.0)
        // Extract the lower-bound reference version for security query matching.
        // NOTE: ~= 2.20 (compatible release, 2-part) is equivalent to >= 2.20, < 3.0.
        // We extract the lower-bound '2.20' as the query version, but warn about reduced accuracy.
        const lowerBoundMatch = specifiers.match(/(?:>=|~=|>)\s*([0-9A-Za-z.\-_+]+)/);
        if (lowerBoundMatch) {
          version = lowerBoundMatch[1]!.trim();
          // Check if the version is a short compatible release (fewer than 3 dot-separated parts)
          const partCount = version.split('.').length;
          if (specifiers.trimStart().startsWith('~=') && partCount < 3) {
            warnings.push(
              `Package "${canonicalName}" uses compatible release "${specifiers}" with a short version. ` +
              `Querying OSV with base version "${version}" may miss vulnerabilities; prefer an exact pin (==) for reliable analysis.`
            );
          } else {
            warnings.push(
              `Package "${canonicalName}" uses range constraint "${specifiers}". Analyzing base version "${version}".`
            );
          }
        } else {
          warnings.push(
            `Package "${canonicalName}" is not pinned to a concrete version ("${specifiers}"). Accurate vulnerability matching requires exact pinning.`
          );
        }
      }
    } else {
      warnings.push(
        `Package "${canonicalName}" has no version specified. Accurate vulnerability matching requires exact pinning.`
      );
    }

    const key = `${canonicalName}@${version}`;
    if (!packageMap.has(key)) {
      packageMap.set(key, {
        name: canonicalName,
        version,
        ecosystem: 'pypi',
        isDirect: true, // In requirements.txt, all listed packages are declared direct dependencies
        isDev: false,
        dependencyPaths: [canonicalName],
        declaredConstraint
      });
    }
  }

  return {
    manifestType: 'requirements.txt',
    packages: Array.from(packageMap.values()),
    warnings
  };
}

/**
 * Parses poetry.lock and optional pyproject.toml contents safely.
 * Implements a robust zero-dependency TOML parser specifically for Poetry package tables.
 */
export function parsePoetryLock(
  poetryLockStr?: string | null,
  pyprojectTomlStr?: string | null,
  options: PythonParseOptions = {}
): ManifestParseResult {
  const maxBytes = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const warnings: string[] = [];

  if (!poetryLockStr || poetryLockStr.trim().length === 0) {
    throw new Error('A poetry.lock file content is required.');
  }

  if (Buffer.byteLength(poetryLockStr, 'utf8') > maxBytes) {
    throw new Error(`poetry.lock exceeds maximum allowed size of ${maxBytes} bytes.`);
  }

  // 1. Identify declared direct & dev dependencies from pyproject.toml if supplied
  const directDeps = new Set<string>();
  const directDevDeps = new Set<string>();
  let manifestName: string | undefined;
  let manifestVersion: string | undefined;

  if (pyprojectTomlStr && pyprojectTomlStr.trim().length > 0) {
    try {
      const parsedPyProject = parseSimpleToml(pyprojectTomlStr);
      const toolPoetry = parsedPyProject?.tool?.poetry;
      if (toolPoetry && typeof toolPoetry === 'object') {
        manifestName = toolPoetry.name;
        manifestVersion = toolPoetry.version;

        if (toolPoetry.dependencies && typeof toolPoetry.dependencies === 'object') {
          for (const dep of Object.keys(toolPoetry.dependencies)) {
            if (dep.toLowerCase() !== 'python') {
              directDeps.add(canonicalizePythonPackageName(dep));
            }
          }
        }

        // Dev dependencies (Poetry 1.x dev-dependencies or 2.x group.dev.dependencies)
        const devDeps =
          toolPoetry['dev-dependencies'] ||
          toolPoetry?.group?.dev?.dependencies;

        if (devDeps && typeof devDeps === 'object') {
          for (const dep of Object.keys(devDeps)) {
            directDevDeps.add(canonicalizePythonPackageName(dep));
          }
        }
      }
    } catch (err: any) {
      warnings.push(`Failed to parse pyproject.toml: ${err?.message || 'Invalid format'}`);
    }
  }

  // 2. Parse [[package]] blocks from poetry.lock
  const packagesList = parsePoetryLockPackages(poetryLockStr);
  const packageMap = new Map<string, PackageIdentifier>();

  // Determine child dependencies across all packages to infer root packages if pyproject is missing
  const childDependencies = new Set<string>();
  for (const pkg of packagesList) {
    if (pkg.dependencies) {
      for (const child of Object.keys(pkg.dependencies)) {
        childDependencies.add(canonicalizePythonPackageName(child));
      }
    }
  }

  for (const pkg of packagesList) {
    const canonicalName = canonicalizePythonPackageName(pkg.name);
    const version = pkg.version;

    if (!canonicalName || !version) continue;

    let isDirect = false;
    let isDev = false;

    if (directDeps.size > 0 || directDevDeps.size > 0) {
      // Governed by pyproject.toml
      isDirect = directDeps.has(canonicalName) || directDevDeps.has(canonicalName);
      isDev = directDevDeps.has(canonicalName) || pkg.category === 'dev';
    } else {
      // Inferred from dependency tree: any package not depended upon by another is root/direct
      isDirect = !childDependencies.has(canonicalName);
      isDev = pkg.category === 'dev';
    }

    const key = `${canonicalName}@${version}`;
    packageMap.set(key, {
      name: canonicalName,
      version,
      ecosystem: 'pypi',
      isDirect,
      isDev,
      dependencyPaths: [canonicalName]
    });
  }

  return {
    manifestName,
    manifestVersion,
    manifestType: 'poetry.lock',
    packages: Array.from(packageMap.values()),
    warnings
  };
}

interface RawPoetryPackage {
  name: string;
  version: string;
  category?: string;
  optional?: boolean;
  dependencies?: Record<string, string>;
}

/**
 * Lightweight, deterministic TOML parser for poetry.lock [[package]] sections
 */
function parsePoetryLockPackages(tomlStr: string): RawPoetryPackage[] {
  const packages: RawPoetryPackage[] = [];
  const lines = tomlStr.split(/\r?\n/);

  let currentPkg: RawPoetryPackage | null = null;
  let inDependenciesSection = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    // New [[package]] table
    if (trimmed === '[[package]]') {
      if (currentPkg && currentPkg.name && currentPkg.version) {
        packages.push(currentPkg);
      }
      currentPkg = { name: '', version: '' };
      inDependenciesSection = false;
      continue;
    }

    // Sub-tables within [[package]]
    if (trimmed.startsWith('[')) {
      if (trimmed === '[package.dependencies]') {
        inDependenciesSection = true;
        if (currentPkg) currentPkg.dependencies = {};
      } else {
        inDependenciesSection = false;
      }
      continue;
    }

    // Key-value pairs
    const equalIdx = trimmed.indexOf('=');
    if (equalIdx !== -1 && currentPkg) {
      const key = trimmed.substring(0, equalIdx).trim();
      const rawVal = trimmed.substring(equalIdx + 1).trim();
      const val = cleanTomlValue(rawVal);

      if (inDependenciesSection && currentPkg.dependencies) {
        currentPkg.dependencies[key] = typeof val === 'string' ? val : String(val);
      } else {
        if (key === 'name') currentPkg.name = String(val);
        else if (key === 'version') currentPkg.version = String(val);
        else if (key === 'category') currentPkg.category = String(val);
        else if (key === 'optional') currentPkg.optional = Boolean(val);
      }
    }
  }

  // Flush final package
  if (currentPkg && currentPkg.name && currentPkg.version) {
    packages.push(currentPkg);
  }

  return packages;
}

/**
 * Strips quotes and parses basic TOML scalar values
 */
function cleanTomlValue(val: string): any {
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    return val.slice(1, -1);
  }
  if (val === 'true') return true;
  if (val === 'false') return false;
  const num = Number(val);
  if (!isNaN(num)) return num;
  return val;
}

/**
 * Basic nested TOML reader for pyproject.toml sections
 */
function parseSimpleToml(tomlStr: string): any {
  const root: Record<string, any> = {};
  let currentTarget = root;

  const lines = tomlStr.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Table header: [tool.poetry.dependencies]
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const section = trimmed.slice(1, -1).trim();
      const parts = section.split('.');
      currentTarget = root;
      for (const part of parts) {
        if (!currentTarget[part] || typeof currentTarget[part] !== 'object') {
          currentTarget[part] = {};
        }
        currentTarget = currentTarget[part];
      }
      continue;
    }

    const eqIdx = trimmed.indexOf('=');
    if (eqIdx !== -1) {
      const key = trimmed.substring(0, eqIdx).trim();
      const rawVal = trimmed.substring(eqIdx + 1).trim();
      currentTarget[key] = cleanTomlValue(rawVal);
    }
  }

  return root;
}
