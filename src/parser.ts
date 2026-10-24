import { ManifestParseResult, PackageIdentifier } from './types.js';

export interface ParseOptions {
  maxFileSize?: number; // default 10MB
}

const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

/**
 * Validates and parses package.json and package-lock.json strings safely.
 * Supports lockfile versions 1, 2, and 3.
 */
export function parseNpmManifests(
  packageJsonStr?: string | null,
  packageLockJsonStr?: string | null,
  options: ParseOptions = {}
): ManifestParseResult {
  const maxBytes = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const warnings: string[] = [];

  // 1. Guard against empty / missing lockfile
  if (!packageLockJsonStr || packageLockJsonStr.trim().length === 0) {
    throw new Error('A package-lock.json file content is required for resolving concrete dependency versions.');
  }

  // 2. Guard against file size abuse
  if (Buffer.byteLength(packageLockJsonStr, 'utf8') > maxBytes) {
    throw new Error(`package-lock.json exceeds maximum allowed size of ${maxBytes} bytes.`);
  }

  // 3. Safe JSON parsing of package.json if supplied
  let directDeps = new Set<string>();
  let directDevDeps = new Set<string>();
  let manifestName: string | undefined;
  let manifestVersion: string | undefined;

  if (packageJsonStr && packageJsonStr.trim().length > 0) {
    if (Buffer.byteLength(packageJsonStr, 'utf8') > maxBytes) {
      warnings.push('package.json exceeds maximum size limit and was skipped.');
    } else {
      try {
        const pkg = JSON.parse(packageJsonStr);
        if (typeof pkg === 'object' && pkg !== null) {
          manifestName = typeof pkg.name === 'string' ? pkg.name : undefined;
          manifestVersion = typeof pkg.version === 'string' ? pkg.version : undefined;

          if (pkg.dependencies && typeof pkg.dependencies === 'object') {
            for (const dep of Object.keys(pkg.dependencies)) {
              directDeps.add(dep);
            }
          }
          if (pkg.devDependencies && typeof pkg.devDependencies === 'object') {
            for (const dep of Object.keys(pkg.devDependencies)) {
              directDevDeps.add(dep);
            }
          }
        }
      } catch (err: any) {
        warnings.push(`Failed to parse package.json: ${err?.message || 'Invalid JSON format'}`);
      }
    }
  }

  // 4. Safe JSON parsing of package-lock.json
  let lock: any;
  try {
    lock = JSON.parse(packageLockJsonStr);
  } catch (err: any) {
    throw new Error(`Malformed package-lock.json: ${err?.message || 'Invalid JSON'}`);
  }

  if (typeof lock !== 'object' || lock === null || Array.isArray(lock)) {
    throw new Error('Malformed package-lock.json: Root must be a JSON object.');
  }

  const lockfileVersion = lock.lockfileVersion;
  if (typeof lockfileVersion !== 'number') {
    throw new Error('Malformed package-lock.json: Missing numeric "lockfileVersion".');
  }

  // We explicitly document and support lockfileVersion 1, 2, and 3
  if (lockfileVersion !== 1 && lockfileVersion !== 2 && lockfileVersion !== 3) {
    throw new Error(`Unsupported package-lock.json version: ${lockfileVersion}. Veylix supports lockfileVersion 1, 2, and 3.`);
  }

  // Map keyed by `${name}@${version}` to consolidate path references
  const packageMap = new Map<string, PackageIdentifier>();

  function registerPackage(
    name: string,
    version: string,
    isDirect: boolean,
    isDev: boolean,
    path: string
  ) {
    if (!name || !version || typeof name !== 'string' || typeof version !== 'string') {
      return;
    }
    const cleanName = name.trim();
    const cleanVersion = version.trim();
    if (!cleanName || !cleanVersion) return;

    const key = `${cleanName}@${cleanVersion}`;
    const existing = packageMap.get(key);
    if (existing) {
      if (isDirect) existing.isDirect = true;
      if (!isDev) existing.isDev = false; // if marked non-dev anywhere, treat as production dep
      if (path && !existing.dependencyPaths.includes(path)) {
        existing.dependencyPaths.push(path);
      }
    } else {
      packageMap.set(key, {
        name: cleanName,
        version: cleanVersion,
        ecosystem: 'npm',
        isDirect,
        isDev,
        dependencyPaths: path ? [path] : []
      });
    }
  }

  // Strategy A: lockfileVersion 2 or 3 with "packages" key
  if ((lockfileVersion === 2 || lockfileVersion === 3) && lock.packages && typeof lock.packages === 'object') {
    const packagesObj = lock.packages;

    // Check root package "" if present for direct dependencies
    const rootPkg = packagesObj[''];
    if (rootPkg && typeof rootPkg === 'object') {
      if (rootPkg.dependencies && typeof rootPkg.dependencies === 'object') {
        for (const dep of Object.keys(rootPkg.dependencies)) directDeps.add(dep);
      }
      if (rootPkg.devDependencies && typeof rootPkg.devDependencies === 'object') {
        for (const dep of Object.keys(rootPkg.devDependencies)) directDevDeps.add(dep);
      }
    }

    for (const [pkgPath, meta] of Object.entries(packagesObj)) {
      if (!pkgPath || pkgPath === '') continue; // Skip root project
      if (typeof meta !== 'object' || meta === null) continue;

      const metaObj = meta as any;
      let name = metaObj.name;
      const version = metaObj.version;

      if (!name) {
        // Derive name from node_modules path: e.g. "node_modules/@scope/pkg" or "node_modules/pkg"
        const lastIndex = pkgPath.lastIndexOf('node_modules/');
        if (lastIndex !== -1) {
          name = pkgPath.substring(lastIndex + 'node_modules/'.length);
        }
      }

      if (!name || !version) continue;

      // A package instance is direct only if it sits directly at top-level "node_modules/<name>"
      // and is declared in dependencies/devDependencies (or directDeps is empty, indicating no package.json supplied).
      const isTopLevel = pkgPath.startsWith('node_modules/') && !pkgPath.slice('node_modules/'.length).includes('node_modules/');
      const isDirect = isTopLevel && (directDeps.size === 0 || directDeps.has(name) || directDevDeps.has(name));
      const isDev = Boolean(metaObj.dev || (isTopLevel && directDevDeps.has(name)));

      // Build readable dependency path from node_modules hierarchy
      const segments = pkgPath.split('node_modules/').filter(Boolean).map(s => s.replace(/\/$/, ''));
      const formattedPath = segments.length > 0 ? segments.join(' -> ') : name;

      registerPackage(name, version, isDirect, isDev, formattedPath);
    }
  }

  // Strategy B: lockfileVersion 1 (or v2 fallback) using "dependencies" tree
  if (packageMap.size === 0 && lock.dependencies && typeof lock.dependencies === 'object') {
    function traverseV1Tree(depsObj: any, currentChain: string[] = []) {
      if (!depsObj || typeof depsObj !== 'object') return;

      for (const [name, meta] of Object.entries(depsObj)) {
        if (typeof meta !== 'object' || meta === null) continue;
        const metaObj = meta as any;
        const version = metaObj.version;
        if (!version || typeof version !== 'string') continue;

        const isDirect = currentChain.length === 0 && (directDeps.size === 0 || directDeps.has(name) || directDevDeps.has(name));
        const isDev = Boolean(metaObj.dev);
        const newChain = [...currentChain, `${name}@${version}`];
        const formattedPath = newChain.join(' -> ');

        registerPackage(name, version, isDirect, isDev, formattedPath);

        if (metaObj.dependencies && typeof metaObj.dependencies === 'object') {
          traverseV1Tree(metaObj.dependencies, newChain);
        }
      }
    }

    traverseV1Tree(lock.dependencies);
  }

  const packages = Array.from(packageMap.values());

  return {
    manifestName: manifestName || lock.name,
    manifestVersion: manifestVersion || lock.version,
    lockfileVersion,
    packages,
    warnings
  };
}
