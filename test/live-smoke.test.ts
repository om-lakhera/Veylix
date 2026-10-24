import { describe, it, expect } from 'vitest';
import { VeylixEngine } from '../src/engine.js';
import fs from 'node:fs';
import path from 'node:path';

describe('Live OSV API Smoke Test (Optional Network)', () => {
  const packageJsonStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/package.json'), 'utf8');
  const packageLockV3Str = fs.readFileSync(path.resolve(__dirname, 'fixtures/package-lock-v3.json'), 'utf8');

  it('queries real public OSV batch API and returns live security advisories', async () => {
    const engine = new VeylixEngine();

    const startTime = performance.now();
    const report = await engine.analyzeNpmProject(packageJsonStr, packageLockV3Str);
    const durationMs = performance.now() - startTime;

    console.log(`[LIVE SMOKE TEST] Completed in ${Math.round(durationMs)}ms`);
    console.log(`[LIVE SMOKE TEST] Resolved dependencies: ${report.summary.totalDependenciesResolved}`);
    console.log(`[LIVE SMOKE TEST] Vulnerabilities found: ${report.summary.totalAdvisoriesCount}`);

    expect(report.summary.totalDependenciesResolved).toBe(4);
    expect(report.summary.vulnerablePackagesCount).toBeGreaterThanOrEqual(2);

    // lodash 4.17.15 has known vulnerabilities in OSV
    const lodash15 = report.packages.find((p) => p.name === 'lodash' && p.version === '4.17.15');
    expect(lodash15?.hasVulnerability).toBe(true);
    expect(lodash15?.vulnerabilities.length).toBeGreaterThan(0);

    // lodash 4.17.21 does NOT have the prototype pollution CVEs that were fixed prior to 4.17.21
    const lodash21 = report.packages.find((p) => p.name === 'lodash' && p.version === '4.17.21');
    expect(lodash21).toBeDefined();

    // Verify recommendations are grounded in data
    const firstVuln = lodash15?.vulnerabilities[0];
    expect(firstVuln?.actionableRecommendation).toBeDefined();
    expect(firstVuln?.actionableRecommendation.length).toBeGreaterThan(10);
  }, 15000); // 15s timeout for network smoke test
});
