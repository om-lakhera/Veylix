import { describe, it, expect, vi } from 'vitest';
import { ScanService } from '../src/server/scan-service.js';
import { handleApiRequest } from '../src/server/api-handler.js';
import { calculateRiskScore } from '../src/web/types.js';

describe('End-to-End Scanner Integration & API Suite', () => {
  const service = new ScanService({
    osvOptions: {
      fetchFn: vi.fn().mockImplementation((url: string, opts: any) => {
        if (url.includes('querybatch')) {
          const body = JSON.parse(opts.body);
          const results = body.queries.map((q: any) => {
            if (q.package.name === 'lodash' && q.version === '4.17.15') {
              return {
                vulns: [
                  {
                    id: 'GHSA-p6mc-m468-83gw',
                    summary: 'Prototype Pollution in lodash',
                    database_specific: { severity: 'HIGH' },
                    affected: [
                      {
                        package: { name: 'lodash', ecosystem: 'npm' },
                        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }]
                      }
                    ]
                  }
                ]
              };
            }
            return { vulns: [] };
          });
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ results })
          });
        }
        return Promise.reject(new Error(`Unexpected url: ${url}`));
      }) as any
    }
  });

  describe('Dependency File Upload Scenarios', () => {
    it('successfully processes valid npm lockfile v3 with vulnerability findings', async () => {
      const packageLock = JSON.stringify({
        name: 'test-app',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'test-app',
            dependencies: { 'lodash': '4.17.15' }
          },
          'node_modules/lodash': {
            version: '4.17.15',
            resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz'
          }
        }
      });

      const res = await service.scanFiles({
        packageLockJson: packageLock
      });

      expect(res.success).toBe(true);
      expect(res.report).toBeDefined();
      expect(res.report?.summary.vulnerablePackagesCount).toBe(1);
      expect(res.report?.summary.totalAdvisoriesCount).toBe(1);
      expect(res.report?.vulnerablePackages[0]?.name).toBe('lodash');
      expect(res.report?.vulnerablePackages[0]?.vulnerabilities[0]?.fixedVersion).toBe('4.17.21');

      // Check risk score
      const risk = calculateRiskScore(res.report!);
      expect(risk.score).toBeGreaterThan(0);
      expect(risk.tier).toBe('MODERATE'); // 1 High severity = 15 pts => MODERATE
    });

    it('rejects empty file upload with descriptive user message', async () => {
      const res = await service.scanFiles({});
      expect(res.success).toBe(false);
      expect(res.error).toContain('No valid dependency files provided');
    });

    it('rejects standalone package.json without lockfile with clear guidance', async () => {
      const res = await service.scanFiles({
        packageJson: '{"name":"test"}'
      });
      expect(res.success).toBe(false);
      expect(res.error).toContain('package.json was provided without package-lock.json');
    });
  });

  describe('GitHub Repository Scanning Scenarios', () => {
    it('rejects invalid repository URLs with descriptive errors', async () => {
      const res = await service.scanGitHub({ repoUrl: 'invalid-url-without-slash' });
      expect(res.success).toBe(false);
      expect(res.error).toContain('Invalid repository format');
    });

    it('handles inaccessible / private / empty repositories gracefully', async () => {
      const fetchGitHub = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));
      const service = new ScanService({}, fetchGitHub);
      const apiRes = await handleApiRequest(
        'POST',
        '/api/scan-github',
        JSON.stringify({ repoUrl: 'public-owner/empty-repository' }),
        service
      );
      expect(apiRes.status).toBe(400);
      const json = JSON.parse(apiRes.body);
      expect(json.success).toBe(false);
      expect(json.error).toContain('No supported dependency manifests found');
      expect(fetchGitHub).toHaveBeenCalledTimes(5);
    });

    it('scans public repository manifests through the API with deterministic upstream responses', async () => {
      const fetchGitHub = vi.fn().mockImplementation((url: string) => {
        if (url.includes('/package-lock.json')) {
          return Promise.resolve(new Response(
            JSON.stringify({
              name: 'test-app',
              lockfileVersion: 3,
              packages: {
                '': { name: 'test-app', dependencies: { lodash: '4.17.15' } },
                'node_modules/lodash': { version: '4.17.15' }
              }
            }),
            { status: 200 }
          ));
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      });
      const fetchOsv = vi.fn().mockImplementation((_url: string, options: { body: string }) => {
        const request = JSON.parse(options.body);
        return Promise.resolve(new Response(
          JSON.stringify({ results: request.queries.map(() => ({ vulns: [] })) }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        ));
      });
      const service = new ScanService({ osvOptions: { fetchFn: fetchOsv } }, fetchGitHub);
      const response = await handleApiRequest(
        'POST',
        '/api/scan-github',
        JSON.stringify({ repoUrl: 'public-owner/sample-repository' }),
        service
      );

      expect(response.status).toBe(200);
      const result = JSON.parse(response.body);
      expect(result.success).toBe(true);
      expect(result.target.scannedFiles).toEqual(['package-lock.json']);
      expect(result.report.summary.totalDependenciesResolved).toBe(1);
      expect(fetchOsv).toHaveBeenCalledTimes(1);
    });
  });

  describe('API Endpoint Integration', () => {
    it('handles POST /api/scan with a deterministic OSV response', async () => {
      const fetchOsv = vi.fn().mockResolvedValue(new Response(
        JSON.stringify({ results: [{ vulns: [] }] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      ));
      const service = new ScanService({ osvOptions: { fetchFn: fetchOsv } });
      const body = JSON.stringify({
        requirementsTxt: 'requests==2.28.1\n'
      });

      const res = await handleApiRequest('POST', '/api/scan', body, service);
      expect(res.status).toBe(200);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(true);
      expect(json.report.summary.ecosystem).toBe('pypi');
      expect(json.report.summary.totalAdvisoriesCount).toBe(0);
      expect(fetchOsv).toHaveBeenCalledTimes(1);
    });

    it('handles POST /api/scan with invalid JSON payload', async () => {
      const res = await handleApiRequest('POST', '/api/scan', '{ invalid json');
      expect(res.status).toBe(400);
      const json = JSON.parse(res.body);
      expect(json.success).toBe(false);
    });
  });
});
