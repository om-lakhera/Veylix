import { describe, it, expect, vi } from 'vitest';
import { ScanService } from '../src/server/scan-service.js';

describe('ScanService', () => {
  it('returns failure when no files are uploaded', async () => {
    const service = new ScanService();
    const res = await service.scanFiles({});
    expect(res.success).toBe(false);
    expect(res.error).toContain('No valid dependency files provided');
  });

  it('rejects standalone package.json without lockfile with clear guidance', async () => {
    const service = new ScanService();
    const res = await service.scanFiles({
      packageJson: '{"name":"test","dependencies":{"express":"^4.18.2"}}'
    });
    expect(res.success).toBe(false);
    expect(res.error).toContain('package.json was provided without package-lock.json');
  });

  it('scans requirements.txt successfully with offline OSV mock', async () => {
    const mockFetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('api.osv.dev')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ results: [{ vulns: [] }] })
        });
      }
      return Promise.reject(new Error(`Unexpected url: ${url}`));
    });

    const service = new ScanService({
      osvOptions: { fetchFn: mockFetch }
    });

    const res = await service.scanFiles({
      requirementsTxt: 'requests==2.28.1\n'
    });

    expect(res.success).toBe(true);
    expect(res.report).toBeDefined();
    expect(res.report?.summary.totalUniquePackages).toBe(1);
    expect(res.report?.summary.ecosystem).toBe('pypi');
  });

  it('handles scan error gracefully without crashing or exposing stack traces', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('OSV network down'));
    const service = new ScanService({
      osvOptions: { fetchFn: mockFetch }
    });

    const res = await service.scanFiles({
      requirementsTxt: 'requests==2.28.1\n'
    });

    expect(res.success).toBe(false);
    expect(res.error).toBeDefined();
    expect(res.error).not.toContain('OSV network down');
  });

  it('does not return unexpected GitHub fetch errors to the client', async () => {
    const service = new ScanService({}, vi.fn().mockRejectedValue(new Error('upstream response secret')));

    const res = await service.scanGitHub({ repoUrl: 'owner/repo' });

    expect(res.success).toBe(false);
    expect(res.error).toContain('Network error fetching');
    expect(res.error).not.toContain('upstream response secret');
  });
});
