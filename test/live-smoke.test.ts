import { describe, it, expect } from 'vitest';
import { VeylixEngine } from '../src/engine.js';
import { DepsDevClient } from '../src/deps-client.js';
import fs from 'node:fs';
import path from 'node:path';

describe('Live API Smoke Tests (Optional Network)', () => {
  const packageJsonStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/package.json'), 'utf8');
  const packageLockV3Str = fs.readFileSync(path.resolve(__dirname, 'fixtures/package-lock-v3.json'), 'utf8');
  const requirementsTxtStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/requirements.txt'), 'utf8');

  it('queries real public OSV batch API for npm and returns live security advisories', async () => {
    const engine = new VeylixEngine();

    const startTime = performance.now();
    const report = await engine.analyzeNpmProject(packageJsonStr, packageLockV3Str);
    const durationMs = performance.now() - startTime;

    console.log(`[LIVE SMOKE TEST: npm] Completed in ${Math.round(durationMs)}ms`);
    console.log(`[LIVE SMOKE TEST: npm] Resolved dependencies: ${report.summary.totalDependenciesResolved}`);
    console.log(`[LIVE SMOKE TEST: npm] Vulnerabilities found: ${report.summary.totalAdvisoriesCount}`);

    expect(report.summary.totalDependenciesResolved).toBe(4);
    expect(report.summary.vulnerablePackagesCount).toBeGreaterThanOrEqual(2);

    const lodash15 = report.packages.find((p) => p.name === 'lodash' && p.version === '4.17.15');
    expect(lodash15?.hasVulnerability).toBe(true);
    expect(lodash15?.vulnerabilities.length).toBeGreaterThan(0);
  }, 15000);

  it('queries real public OSV batch API for PyPI packages', async () => {
    const engine = new VeylixEngine();

    const startTime = performance.now();
    const report = await engine.analyzePythonRequirements(requirementsTxtStr);
    const durationMs = performance.now() - startTime;

    console.log(`[LIVE SMOKE TEST: PyPI] Completed in ${Math.round(durationMs)}ms`);
    console.log(`[LIVE SMOKE TEST: PyPI] Vulnerabilities found: ${report.summary.totalAdvisoriesCount}`);

    expect(report.summary.manifestType).toBe('requirements.txt');
    expect(report.summary.ecosystem).toBe('pypi');

    // requests 2.20.0 has known vulnerabilities in OSV
    const requests = report.packages.find((p) => p.name === 'requests');
    expect(requests?.hasVulnerability).toBe(true);
    expect(requests?.vulnerabilities.some((v) => v.advisoryId === 'GHSA-j8r2-6x86-q33q')).toBe(true);
  }, 15000);

  it('queries real public deps.dev API and returns actual OpenSSF Scorecard metrics', async () => {
    const client = new DepsDevClient();

    const startTime = performance.now();
    const health = await client.getPackageHealth('requests', '2.28.1', 'pypi');
    const durationMs = performance.now() - startTime;

    console.log(`[LIVE SMOKE TEST: deps.dev] Completed in ${Math.round(durationMs)}ms`);
    console.log(`[LIVE SMOKE TEST: deps.dev] Scorecard score: ${health.scorecardScore}`);
    console.log(`[LIVE SMOKE TEST: deps.dev] Maintained check: ${health.maintainedScore}`);
    console.log(`[LIVE SMOKE TEST: deps.dev] Source repo: ${health.sourceRepo}`);

    expect(health.status).toBe('ACTIVE');
    expect(health.scorecardScore).toBeGreaterThanOrEqual(5.0);
    expect(health.sourceRepo).toBe('github.com/psf/requests');
    expect(health.maintainedScore).toBeGreaterThanOrEqual(7);
  }, 15000);
});
