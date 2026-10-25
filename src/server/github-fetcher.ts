/**
 * Safe, read-only public GitHub repository dependency manifest fetcher.
 * 
 * Strict ₹0 constraint:
 * - Uses raw.githubusercontent.com and/or public GitHub REST API without requiring auth tokens.
 * - Only downloads dependency manifests (package.json, package-lock.json, requirements.txt, poetry.lock, pyproject.toml).
 * - Enforces strict timeout, file size limits (<= 5MB), and repo URL format validation.
 * - Never executes repository code or installs dependencies.
 */

export interface GitHubRepoRef {
  owner: string;
  repo: string;
  subpath?: string;
  branch?: string;
}

export interface DiscoveredManifests {
  repoName: string;
  owner: string;
  branch: string;
  ecosystem: 'npm' | 'pypi' | 'unknown';
  foundFiles: string[];
  manifestContents: {
    packageJson?: string;
    packageLockJson?: string;
    requirementsTxt?: string;
    poetryLock?: string;
    pyprojectToml?: string;
  };
}

export class GitHubFetcherError extends Error {
  constructor(message: string, public readonly statusCode?: number, public readonly isRateLimit?: boolean) {
    super(message);
    this.name = 'GitHubFetcherError';
  }
}

const OWNER_REPO_REGEX = /^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$/;
const MAX_MANIFEST_SIZE_BYTES = 5 * 1024 * 1024; // 5MB safety limit
const FETCH_TIMEOUT_MS = 10000; // 10s timeout per file
const ALLOWED_MANIFESTS = new Set([
  'package.json',
  'package-lock.json',
  'requirements.txt',
  'poetry.lock',
  'pyproject.toml'
]);

/**
 * Parses and validates a public GitHub repository input string or URL.
 * Supports:
 * - "owner/repo"
 * - "https://github.com/owner/repo"
 * - "https://github.com/owner/repo.git"
 * - "github.com/owner/repo"
 */
export function parseGitHubRepoUrl(input: string): GitHubRepoRef {
  if (!input || typeof input !== 'string') {
    throw new GitHubFetcherError('Repository URL or "owner/repo" string is required.');
  }

  const trimmed = input.trim();
  let pathPart = trimmed;

  if (/^[a-z][a-z\d+.-]*:\/\//i.test(pathPart)) {
    try {
      const url = new URL(pathPart);
      if (
        url.protocol !== 'https:' ||
        (url.hostname.toLowerCase() !== 'github.com' && url.hostname.toLowerCase() !== 'www.github.com') ||
        url.username ||
        url.password ||
        url.port ||
        url.search ||
        url.hash
      ) {
        throw new GitHubFetcherError(`Invalid host "${url.hostname}". Only public GitHub repositories are supported.`);
      }
      pathPart = url.pathname;
    } catch (e) {
      if (e instanceof GitHubFetcherError) throw e;
      throw new GitHubFetcherError(`Malformed GitHub repository URL: "${trimmed}".`);
    }
  } else if (pathPart.toLowerCase().startsWith('github.com/')) {
    pathPart = pathPart.slice('github.com/'.length);
  }

  // Remove leading/trailing slashes
  pathPart = pathPart.replace(/^\/+|\/+$/g, '');

  // Strip .git suffix if present
  if (pathPart.endsWith('.git')) {
    pathPart = pathPart.slice(0, -4);
  }

  const segments = pathPart.split('/').filter(Boolean);
  if (segments.length < 2) {
    throw new GitHubFetcherError(
      `Invalid repository format "${trimmed}". Expected "owner/repo" or "https://github.com/owner/repo".`
    );
  }

  const owner = segments[0]!;
  const repo = segments[1]!;

  if (
    !OWNER_REPO_REGEX.test(owner) ||
    !OWNER_REPO_REGEX.test(repo) ||
    owner.includes('..') ||
    repo.includes('..') ||
    owner.endsWith('.') ||
    repo.endsWith('.')
  ) {
    throw new GitHubFetcherError(
      `Repository owner "${owner}" or repository name "${repo}" contains invalid characters. Only alphanumeric, hyphen, dot, and underscore are allowed.`
    );
  }

  let branch: string | undefined;
  let subpath: string | undefined;
  if (segments.length === 2 || (segments.length >= 4 && segments[2] === 'tree')) {
    if (segments.length >= 4) {
      branch = segments[3];
      const remaining = segments.slice(4);
      if (remaining.some((segment) => segment === '.' || segment === '..' || !/^[a-zA-Z0-9._-]+$/.test(segment))) {
        throw new GitHubFetcherError('The repository path contains an invalid branch or directory segment.');
      }
      subpath = remaining.length > 0 ? remaining.join('/') : undefined;
    }
  } else {
    throw new GitHubFetcherError(
      `Invalid repository format "${trimmed}". Expected "owner/repo" or a GitHub repository tree URL.`
    );
  }

  if (branch && (branch === '.' || branch === '..' || branch.includes('..') || !/^[a-zA-Z0-9._/-]+$/.test(branch))) {
    throw new GitHubFetcherError('The repository branch contains invalid characters.');
  }

  return { owner, repo, branch, subpath };
}

/**
 * Fetches a single raw file from a public GitHub repository.
 * Returns null if the file does not exist (404), or throws for network/rate-limit errors.
 */
export async function fetchRawGitHubFile(
  owner: string,
  repo: string,
  filePath: string,
  branch: string = 'HEAD',
  fetchFn: typeof fetch = fetch
): Promise<string | null> {
  if (
    !OWNER_REPO_REGEX.test(owner) ||
    !OWNER_REPO_REGEX.test(repo) ||
    !ALLOWED_MANIFESTS.has(filePath.split('/').at(-1) ?? '') ||
    filePath.split('/').slice(0, -1).some((segment) => !segment || segment === '.' || segment === '..' || !/^[a-zA-Z0-9._-]+$/.test(segment)) ||
    branch.split('/').some((segment) => !segment || segment === '.' || segment === '..' || !/^[a-zA-Z0-9._-]+$/.test(segment))
  ) {
    throw new GitHubFetcherError('Invalid repository manifest request.');
  }
  const safeBranch = branch.split('/').map(encodeURIComponent).join('/');
  const url = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${safeBranch}/${filePath}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetchFn(url, {
      signal: controller.signal,
      redirect: 'error',
      headers: {
        'User-Agent': 'Veylix-Engine/0.1.0'
      }
    });

    if (response.status === 404) {
      return null;
    }

    if (response.status === 429 || response.status === 403) {
      throw new GitHubFetcherError(
        `GitHub rate limit reached while accessing "${owner}/${repo}/${filePath}". Please try again in a few minutes.`,
        response.status,
        true
      );
    }

    if (!response.ok) {
      throw new GitHubFetcherError(
        `Failed to fetch "${filePath}" from "${owner}/${repo}": HTTP ${response.status} ${response.statusText}`,
        response.status
      );
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && Number(contentLength) > MAX_MANIFEST_SIZE_BYTES) {
      throw new GitHubFetcherError(
        `File "${filePath}" in "${owner}/${repo}" exceeds the maximum allowed size of 5 MB.`
      );
    }

    let text: string;
    if (response.body) {
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let totalBytes = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalBytes += value.byteLength;
        if (totalBytes > MAX_MANIFEST_SIZE_BYTES) {
          await reader.cancel();
          throw new GitHubFetcherError(
            `File "${filePath}" in "${owner}/${repo}" exceeds the maximum allowed size of 5 MB.`
          );
        }
        chunks.push(value);
      }
      const bytes = new Uint8Array(totalBytes);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      text = new TextDecoder().decode(bytes);
    } else {
      text = await response.text();
    }
    if (new TextEncoder().encode(text).byteLength > MAX_MANIFEST_SIZE_BYTES) {
      throw new GitHubFetcherError(
        `File "${filePath}" in "${owner}/${repo}" exceeds the maximum allowed size of 5 MB.`
      );
    }

    return text;
  } catch (err: any) {
    if (err instanceof GitHubFetcherError) throw err;
    if (err?.name === 'AbortError') {
      throw new GitHubFetcherError(`Network timeout fetching "${filePath}" from "${owner}/${repo}".`);
    }
    throw new GitHubFetcherError(
      `Network error fetching "${filePath}" from "${owner}/${repo}". Please try again.`
    );
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Probes and retrieves all supported dependency manifests from a public repository.
 */
export async function fetchRepositoryManifests(
  input: string,
  fetchFn: typeof fetch = fetch
): Promise<DiscoveredManifests> {
  const { owner, repo, branch: requestedBranch, subpath } = parseGitHubRepoUrl(input);
  const branch = requestedBranch || 'HEAD';

  // Candidate manifest files in order of ecosystem relevance
  const npmFiles = ['package-lock.json', 'package.json'];
  const pythonFiles = ['requirements.txt', 'poetry.lock', 'pyproject.toml'];

  const results: Record<string, string | null> = {};
  const fetchManifest = (filename: string) =>
    fetchRawGitHubFile(owner, repo, subpath ? `${subpath}/${filename}` : filename, branch, fetchFn);

  // Check npm lockfiles first
  for (const filename of npmFiles) {
    results[filename] = await fetchManifest(filename);
  }

  for (const filename of pythonFiles) {
    results[filename] = await fetchManifest(filename);
  }

  const foundFiles: string[] = [];
  if (results['package-lock.json']) foundFiles.push('package-lock.json');
  if (results['package.json']) foundFiles.push('package.json');
  if (results['requirements.txt']) foundFiles.push('requirements.txt');
  if (results['poetry.lock']) foundFiles.push('poetry.lock');
  if (results['pyproject.toml']) foundFiles.push('pyproject.toml');

  if (foundFiles.length === 0) {
    throw new GitHubFetcherError(
      `No supported dependency manifests found in public repository "${owner}/${repo}" (checked branch "${branch}"). ` +
      `Looked for: package-lock.json, package.json, requirements.txt, poetry.lock, pyproject.toml.`
    );
  }

  // Determine primary ecosystem
  let ecosystem: 'npm' | 'pypi' | 'unknown' = 'unknown';
  if (results['package-lock.json'] || results['package.json']) {
    ecosystem = 'npm';
  } else if (results['poetry.lock'] || results['requirements.txt']) {
    ecosystem = 'pypi';
  }

  const selectedFiles = ecosystem === 'npm'
    ? ['package-lock.json', 'package.json'].filter((filename) => Boolean(results[filename]))
    : ['poetry.lock', 'pyproject.toml', 'requirements.txt'].filter((filename) => Boolean(results[filename]));
  const selectedContents = ecosystem === 'npm'
    ? {
        packageJson: results['package.json'] ?? undefined,
        packageLockJson: results['package-lock.json'] ?? undefined
      }
    : results['poetry.lock']
      ? {
          poetryLock: results['poetry.lock'] ?? undefined,
          pyprojectToml: results['pyproject.toml'] ?? undefined
        }
      : {
          requirementsTxt: results['requirements.txt'] ?? undefined
        };

  return {
    repoName: `${owner}/${repo}`,
    owner,
    branch,
    ecosystem,
    foundFiles: selectedFiles,
    manifestContents: selectedContents
  };
}
