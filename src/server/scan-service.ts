/**
 * Unified Scan Service for Veylix
 * 
 * Orchestrates scans by invoking the actual VeylixEngine without duplicating any parsing
 * or vulnerability logic.
 */

import { VeylixEngine, AnalyzerOptions } from '../engine.js';
import { AnalysisReport } from '../types.js';
import { fetchRepositoryManifests, GitHubFetcherError } from './github-fetcher.js';
import {
  MAX_MANIFEST_SIZE_BYTES,
  MAX_TOTAL_MANIFEST_SIZE_BYTES
} from '../limits.js';
const FILE_PAYLOAD_FIELDS = new Set([
  'packageJson',
  'packageLockJson',
  'requirementsTxt',
  'poetryLock',
  'pyprojectToml',
  'fetchMaintenanceHealth'
]);

function getSafeScanError(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (
    /^(?:Malformed package-lock\.json:|Unsupported package-lock\.json version:|A (?:package-lock\.json|requirements\.txt|poetry\.lock)|(?:package-lock\.json|requirements\.txt|poetry\.lock) exceeds maximum allowed size)/.test(message) ||
    /^OSV API (?:rate limit encountered \(HTTP 429\)|server error \(HTTP \d+\)|request failed with HTTP \d+|request timed out after \d+ms|returned invalid non-object response|response missing "results" array|response alignment error: Sent \d+ package queries but received \d+ result items)/.test(message)
  ) {
    return message;
  }
  return 'Dependency analysis could not be completed. Check the submitted files and retry when the service is available.';
}

export interface FileScanPayload {
  packageJson?: string;
  packageLockJson?: string;
  requirementsTxt?: string;
  poetryLock?: string;
  pyprojectToml?: string;
  fetchMaintenanceHealth?: boolean;
}

export interface GitHubScanPayload {
  repoUrl: string;
  fetchMaintenanceHealth?: boolean;
}

export interface ScanResponse {
  success: boolean;
  target: {
    type: 'file-upload' | 'github-repo';
    name: string;
    branch?: string;
    scannedFiles: string[];
  };
  report?: AnalysisReport;
  error?: string;
  details?: string;
}

export class ScanService {
  private engineOptions: AnalyzerOptions;
  private githubFetchFn?: typeof fetch;

  constructor(options: AnalyzerOptions = {}, githubFetchFn?: typeof fetch) {
    this.engineOptions = options;
    this.githubFetchFn = githubFetchFn;
  }

  /**
   * Scans uploaded dependency manifest files using the existing VeylixEngine.
   */
  async scanFiles(payload: FileScanPayload): Promise<ScanResponse> {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: [] },
        error: 'The file scan payload must be a JSON object.'
      };
    }

    const input = payload as unknown as Record<string, unknown>;
    const unsupportedField = Object.keys(input).find((key) => !FILE_PAYLOAD_FIELDS.has(key));
    if (unsupportedField) {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: [] },
        error: 'The request contains an unsupported field.'
      };
    }

    if (input.fetchMaintenanceHealth !== undefined && typeof input.fetchMaintenanceHealth !== 'boolean') {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: [] },
        error: 'fetchMaintenanceHealth must be a boolean.'
      };
    }

    const fileFields = [...FILE_PAYLOAD_FIELDS].filter((field) => field !== 'fetchMaintenanceHealth');
    let totalBytes = 0;
    for (const field of fileFields) {
      const value = input[field];
      if (value === undefined) continue;
      if (typeof value !== 'string' || value.trim().length === 0) {
        return {
          success: false,
          target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: [] },
          error: `The supplied ${field} file is empty or invalid.`
        };
      }
      const size = new TextEncoder().encode(value).byteLength;
      totalBytes += size;
      if (size > MAX_MANIFEST_SIZE_BYTES) {
        return {
          success: false,
          target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: [] },
          error: `Each dependency file must be no larger than 5 MB.`
        };
      }
    }
    if (totalBytes > MAX_TOTAL_MANIFEST_SIZE_BYTES) {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: [] },
        error: 'Combined dependency files exceed the 10 MB scan limit.'
      };
    }

    const {
      packageJson,
      packageLockJson,
      requirementsTxt,
      poetryLock,
      pyprojectToml,
      fetchMaintenanceHealth = false
    } = payload;

    const providedFiles: string[] = [];
    if (packageLockJson) providedFiles.push('package-lock.json');
    if (packageJson) providedFiles.push('package.json');
    if (requirementsTxt) providedFiles.push('requirements.txt');
    if (poetryLock) providedFiles.push('poetry.lock');
    if (pyprojectToml) providedFiles.push('pyproject.toml');

    if (providedFiles.length === 0) {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: [] },
        error: 'No valid dependency files provided. Please upload at least one supported manifest (package-lock.json, requirements.txt, or poetry.lock).'
      };
    }

    try {
      if (packageJson) {
        let manifest: unknown;
        try {
          manifest = JSON.parse(packageJson);
        } catch {
          return {
            success: false,
            target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: ['package.json'] },
            error: 'Malformed package.json: expected a valid JSON object.'
          };
        }
        if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
          return {
            success: false,
            target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: ['package.json'] },
            error: 'Malformed package.json: the file must contain a JSON object.'
          };
        }
      }

      const engine = new VeylixEngine({
        ...this.engineOptions,
        fetchMaintenanceHealth
      });

      let report: AnalysisReport;
      let scannedFiles: string[];

      // 1. Prioritize npm lockfile if present
      if (packageLockJson) {
        report = await engine.analyzeNpmProject(packageJson, packageLockJson);
        scannedFiles = ['package-lock.json', ...(packageJson ? ['package.json'] : [])];
      }
      // 2. Poetry lockfile
      else if (poetryLock) {
        report = await engine.analyzePoetryProject(poetryLock, pyprojectToml);
        scannedFiles = ['poetry.lock', ...(pyprojectToml ? ['pyproject.toml'] : [])];
      }
      // 3. Python requirements.txt
      else if (requirementsTxt) {
        report = await engine.analyzePythonRequirements(requirementsTxt);
        scannedFiles = ['requirements.txt'];
      }
      // 4. Standalone package.json (requires lockfile per engine contract)
      else if (packageJson) {
        scannedFiles = ['package.json'];
        return {
          success: false,
          target: { type: 'file-upload', name: 'Manual Upload', scannedFiles },
          error: 'A package.json was provided without package-lock.json. Veylix requires a lockfile (package-lock.json) for deterministic dependency and vulnerability resolution.'
        };
      } else {
        return {
          success: false,
          target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: providedFiles },
          error: 'Unrecognized file combination. Please provide a supported manifest.'
        };
      }

      return {
        success: true,
        target: {
          type: 'file-upload',
          name: `Local Upload (${scannedFiles.join(', ')})`,
          scannedFiles
        },
        report
      };
    } catch (err: unknown) {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: providedFiles },
        error: getSafeScanError(err)
      };
    }
  }

  /**
   * Retrieves public GitHub repository dependency manifests and scans them.
   */
  async scanGitHub(payload: GitHubScanPayload): Promise<ScanResponse> {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return {
        success: false,
        target: { type: 'github-repo', name: 'GitHub Scan', scannedFiles: [] },
        error: 'The GitHub scan payload must be a JSON object.'
      };
    }
    const input = payload as unknown as Record<string, unknown>;
    if (Object.keys(input).some((key) => key !== 'repoUrl' && key !== 'fetchMaintenanceHealth')) {
      return {
        success: false,
        target: { type: 'github-repo', name: 'GitHub Scan', scannedFiles: [] },
        error: 'The request contains an unsupported field.'
      };
    }
    if (input.fetchMaintenanceHealth !== undefined && typeof input.fetchMaintenanceHealth !== 'boolean') {
      return {
        success: false,
        target: { type: 'github-repo', name: 'GitHub Scan', scannedFiles: [] },
        error: 'fetchMaintenanceHealth must be a boolean.'
      };
    }
    const repoUrl = input.repoUrl;
    const fetchMaintenanceHealth = input.fetchMaintenanceHealth === true;

    if (!repoUrl || typeof repoUrl !== 'string') {
      return {
        success: false,
        target: { type: 'github-repo', name: 'GitHub Scan', scannedFiles: [] },
        error: 'A valid GitHub repository URL or "owner/repo" is required.'
      };
    }
    if (repoUrl.length > 2048) {
      return {
        success: false,
        target: { type: 'github-repo', name: 'GitHub Scan', scannedFiles: [] },
        error: 'The GitHub repository reference is too long.'
      };
    }

    try {
      // 1. Fetch public repository manifests
      const discovered = this.githubFetchFn
        ? await fetchRepositoryManifests(repoUrl, this.githubFetchFn)
        : await fetchRepositoryManifests(repoUrl);

      // 2. Pass discovered manifests to scanFiles
      const scanResult = await this.scanFiles({
        ...discovered.manifestContents,
        fetchMaintenanceHealth
      });

      if (!scanResult.success) {
        return {
          ...scanResult,
          target: {
            type: 'github-repo',
            name: discovered.repoName,
            branch: discovered.branch,
            scannedFiles: discovered.foundFiles
          }
        };
      }

      return {
        success: true,
        target: {
          type: 'github-repo',
          name: discovered.repoName,
          branch: discovered.branch,
          scannedFiles: discovered.foundFiles
        },
        report: scanResult.report
      };
    } catch (err: unknown) {
      return {
        success: false,
        target: { type: 'github-repo', name: repoUrl, scannedFiles: [] },
        error: err instanceof GitHubFetcherError
          ? err.message
          : 'Could not retrieve public repository manifests. Check the repository reference and try again.',
        details: err instanceof GitHubFetcherError ? `Status: ${err.statusCode || 'N/A'}` : undefined
      };
    }
  }
}
