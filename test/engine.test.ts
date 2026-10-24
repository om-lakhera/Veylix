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
});
