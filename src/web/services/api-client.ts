import { VeylixEngine } from '../../engine.js';
import { FileScanPayload, GitHubScanPayload, ScanResponse } from '../../server/scan-service.js';

function isScanResponse(value: unknown): value is ScanResponse {
  if (!value || typeof value !== 'object') return false;
  const response = value as Partial<ScanResponse>;
  if (typeof response.success !== 'boolean' || !response.target || typeof response.target !== 'object') return false;
  if (
    (response.target.type !== 'file-upload' && response.target.type !== 'github-repo') ||
    typeof response.target.name !== 'string' ||
    !Array.isArray(response.target.scannedFiles) ||
    !response.target.scannedFiles.every((file) => typeof file === 'string')
  ) return false;
  if (!response.success) return typeof response.error === 'string';
  return Boolean(
    response.report &&
    typeof response.report === 'object' &&
    response.report.summary &&
    Array.isArray(response.report.packages) &&
    Array.isArray(response.report.vulnerablePackages) &&
    Array.isArray(response.report.maintenanceRiskPackages) &&
    Array.isArray(response.report.warnings)
  );
}

async function readScanResponse(response: Response): Promise<ScanResponse> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new Error(`Scan service returned an invalid response (HTTP ${response.status}). Please try again.`);
  }
  if (!isScanResponse(body)) {
    throw new Error('Scan service returned an incomplete response. Please try again.');
  }
  return body;
}

export async function executeFileScan(payload: FileScanPayload): Promise<ScanResponse> {
  let response: Response | undefined;
  try {
    response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch {
    console.info('Scan API unavailable; attempting the existing browser-side file scanner.');
  }

  if (response?.ok) return readScanResponse(response);
  if (response && response.status !== 404) {
    const result = await readScanResponse(response);
    if (response.status < 500 && !result.success) return result;
    throw new Error(`Scan API failed with HTTP ${response.status}. Please retry when the service is available.`);
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
      error: 'No valid dependency files provided.'
    };
  }

  try {
    const engine = new VeylixEngine({ fetchMaintenanceHealth });
    let report;
    let scannedFiles: string[];

    if (packageLockJson) {
      report = await engine.analyzeNpmProject(packageJson, packageLockJson);
      scannedFiles = ['package-lock.json', ...(packageJson ? ['package.json'] : [])];
    } else if (poetryLock) {
      report = await engine.analyzePoetryProject(poetryLock, pyprojectToml);
      scannedFiles = ['poetry.lock', ...(pyprojectToml ? ['pyproject.toml'] : [])];
    } else if (requirementsTxt) {
      report = await engine.analyzePythonRequirements(requirementsTxt);
      scannedFiles = ['requirements.txt'];
    } else if (packageJson) {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: ['package.json'] },
        error: 'package.json provided without lockfile. A lockfile is required for accurate resolution.'
      };
    } else {
      return {
        success: false,
        target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: providedFiles },
        error: 'Unrecognized file combination.'
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
  } catch (error) {
    return {
      success: false,
      target: { type: 'file-upload', name: 'Manual Upload', scannedFiles: providedFiles },
      error: error instanceof Error ? error.message : 'Scan execution failed.'
    };
  }
}

export async function executeGitHubScan(payload: GitHubScanPayload): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch('/api/scan-github', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch {
    throw new Error('The GitHub scan API is unavailable. This deployment must include the Veylix server API.');
  }

  const result = await readScanResponse(response);
  if (!response.ok && response.status >= 500) {
    throw new Error(`GitHub scan API failed with HTTP ${response.status}. Please try again later.`);
  }
  return result;
}
