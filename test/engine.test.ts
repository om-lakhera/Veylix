import { describe, it, expect, vi } from 'vitest';
import { VeylixEngine } from '../src/engine.js';
import fs from 'node:fs';
import path from 'node:path';

describe('VeylixEngine Integration (Recorded Fixtures)', () => {
  const packageJsonStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/package.json'), 'utf8');
  const packageLockV3Str = fs.readFileSync(path.resolve(__dirname, 'fixtures/package-lock-v3.json'), 'utf8');
  const recordedOsvData = JSON.parse(
    fs.readFileSync(path.resolve(__dirname, 'fixtures/osv-recorded-v3.json'), 'utf8')
  );

  it('runs complete deterministic analysis mapping vulnerabilities to correct package versions', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => recordedOsvData
    });

    const engine = new VeylixEngine({
      osvOptions: { fetchFn: mockFetch }
    });

    const report = await engine.analyzeNpmProject(packageJsonStr, packageLockV3Str);

    // Verify summary statistics
    expect(report.summary.manifestType).toBe('package-lock.json');
    expect(report.summary.lockfileVersion).toBe(3);
    expect(report.summary.totalUniquePackages).toBe(3); // lodash, @scoped/safe-pkg, minimist
    expect(report.summary.totalDependenciesResolved).toBe(4); // includes 2 versions of lodash
    expect(report.summary.vulnerablePackagesCount).toBe(2); // lodash@4.17.15 and minimist@1.2.0
    expect(report.summary.severityCounts.high).toBe(1);
    expect(report.summary.severityCounts.critical).toBe(1);

    // Verify multi-version mapping:
    // lodash@4.17.15 has vulnerabilities
    const lodash15 = report.packages.find((p) => p.name === 'lodash' && p.version === '4.17.15');
    expect(lodash15).toBeDefined();
    expect(lodash15?.hasVulnerability).toBe(true);
    expect(lodash15?.vulnerabilities[0]?.advisoryId).toBe('GHSA-p6mc-m468-83gw');

    // lodash@4.17.21 is safe, has ZERO vulnerabilities!
    const lodash21 = report.packages.find((p) => p.name === 'lodash' && p.version === '4.17.21');
    expect(lodash21).toBeDefined();
    expect(lodash21?.hasVulnerability).toBe(false);
    expect(lodash21?.vulnerabilities.length).toBe(0);

    // scoped package is safe
    const scopedPkg = report.packages.find((p) => p.name === '@scoped/safe-pkg');
    expect(scopedPkg?.hasVulnerability).toBe(false);

    // minimist@1.2.0 is vulnerable
    const minimist = report.packages.find((p) => p.name === 'minimist' && p.version === '1.2.0');
    expect(minimist?.hasVulnerability).toBe(true);
    expect(minimist?.vulnerabilities[0]?.severityLevel).toBe('CRITICAL');

    // Verify vulnerablePackages list
    expect(report.vulnerablePackages.length).toBe(2);
    expect(report.vulnerablePackages.map((p) => p.name)).toEqual(['lodash', 'minimist']);
  });

  it('fails safely if OSV returns misaligned result count', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ results: [] }) // Empty results while queries were sent
    });

    const engine = new VeylixEngine({
      osvOptions: { fetchFn: mockFetch }
    });

    await expect(engine.analyzeNpmProject(packageJsonStr, packageLockV3Str)).rejects.toThrow(
      'OSV API response alignment error'
    );
  });

  it('runs complete analysis on Python requirements.txt mapping vulnerabilities correctly', async () => {
    const requirementsTxtStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/requirements.txt'), 'utf8');
    const recordedPythonOsv = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, 'fixtures/osv-recorded-python.json'), 'utf8')
    );

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => recordedPythonOsv
    });

    const engine = new VeylixEngine({
      osvOptions: { fetchFn: mockFetch }
    });

    const report = await engine.analyzePythonRequirements(requirementsTxtStr);

    expect(report.summary.manifestType).toBe('requirements.txt');
    expect(report.summary.ecosystem).toBe('pypi');
    expect(report.summary.totalDependenciesResolved).toBe(7);
    expect(report.summary.vulnerablePackagesCount).toBe(2); // requests and flask

    const requests = report.packages.find((p) => p.name === 'requests');
    expect(requests?.hasVulnerability).toBe(true);
    expect(requests?.vulnerabilities[0]?.advisoryId).toBe('GHSA-j8r2-6x86-q33q');
    expect(requests?.vulnerabilities[0]?.fixedVersion).toBe('2.20.1');

    const flask = report.packages.find((p) => p.name === 'flask');
    expect(flask?.hasVulnerability).toBe(true);
    expect(flask?.vulnerabilities[0]?.fixedVersion).toBe('1.0.3');

    const urllib3 = report.packages.find((p) => p.name === 'urllib3');
    expect(urllib3?.hasVulnerability).toBe(false);
  });

  it('enriches dependencies with maintenance health while strictly separating vulnerability and vitality data', async () => {
    const requirementsTxtStr = 'requests==2.20.0\nold-lib==1.0.0\n';

    const mockOsvFetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('api.osv.dev')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-j8r2-6x86-q33q',
                    summary: 'Security bypass',
                    database_specific: { severity: 'HIGH' }
                  }
                ]
              },
              { vulns: [] } // old-lib has NO vulnerabilities!
            ]
          })
        });
      }

      if (url.includes('/purl/')) {
        if (url.includes('requests')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({
              version: {
                publishedAt: '2022-01-01T00:00:00Z',
                isDeprecated: false,
                relatedProjects: [{ projectKey: { id: 'github.com/psf/requests' }, relationType: 'SOURCE_REPO' }]
              }
            })
          });
        }
        // old-lib is deprecated with low maintenance!
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            version: {
              publishedAt: '2019-01-01T00:00:00Z',
              isDeprecated: true,
              deprecatedReason: 'Library unmaintained, please migrate.'
            }
          })
        });
      }

      if (url.includes('/projects/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            scorecard: {
              overallScore: 8.5,
              checks: [{ name: 'Maintained', score: 10 }]
            }
          })
        });
      }

      return Promise.reject(new Error(`Unhandled URL: ${url}`));
    });

    const engine = new VeylixEngine({
      fetchMaintenanceHealth: true,
      osvOptions: { fetchFn: mockOsvFetch },
      depsDevOptions: { fetchFn: mockOsvFetch }
    });

    const report = await engine.analyzePythonRequirements(requirementsTxtStr);

    expect(report.summary.vulnerablePackagesCount).toBe(1); // requests only
    expect(report.summary.maintenanceRisksCount).toBe(1); // old-lib only
    expect(report.summary.deprecatedPackagesCount).toBe(1);

    // requests has vulnerability + active health
    const requests = report.packages.find((p) => p.name === 'requests');
    expect(requests?.hasVulnerability).toBe(true);
    expect(requests?.vulnerabilities.length).toBe(1);
    expect(requests?.maintenanceHealth?.status).toBe('ACTIVE');
    expect(requests?.maintenanceHealth?.scorecardScore).toBe(8.5);

    // old-lib has ZERO vulnerabilities, but is a MAINTENANCE_RISK
    const oldLib = report.packages.find((p) => p.name === 'old-lib');
    expect(oldLib?.hasVulnerability).toBe(false);
    expect(oldLib?.vulnerabilities.length).toBe(0); // STRICT SEPARATION!
    expect(oldLib?.maintenanceHealth?.status).toBe('MAINTENANCE_RISK');
    expect(oldLib?.maintenanceHealth?.isDeprecated).toBe(true);

    expect(report.maintenanceRiskPackages.map((p) => p.name)).toEqual(['old-lib']);
    expect(report.vulnerablePackages.map((p) => p.name)).toEqual(['requests']);
  });
});
