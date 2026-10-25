import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../src/web/types.js';
import { AnalysisReport } from '../src/types.js';

describe('Veylix Risk Scoring Algorithm', () => {
  const createBaseReport = (overrides: Partial<AnalysisReport['summary']>): AnalysisReport => ({
    summary: {
      manifestType: 'package-lock.json',
      ecosystem: 'npm',
      totalUniquePackages: 10,
      totalDependenciesResolved: 15,
      directDependenciesCount: 5,
      vulnerablePackagesCount: 0,
      totalAdvisoriesCount: 0,
      maintenanceRisksCount: 0,
      deprecatedPackagesCount: 0,
      severityCounts: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 },
      scanDurationMs: 42,
      timestamp: new Date().toISOString(),
      ...overrides
    },
    packages: [],
    vulnerablePackages: [],
    maintenanceRiskPackages: [],
    warnings: []
  });

  it('evaluates clean repository with 0 findings as LOW risk', () => {
    const report = createBaseReport({});
    const res = calculateRiskScore(report);
    expect(res.score).toBe(0);
    expect(res.tier).toBe('LOW');
  });

  it('evaluates moderate severity findings appropriately', () => {
    const report = createBaseReport({
      severityCounts: { critical: 0, high: 0, moderate: 3, low: 1, unknown: 0 }
    });
    const res = calculateRiskScore(report);
    expect(res.score).toBe(16); // 3*5 + 1 = 16
    expect(res.tier).toBe('MODERATE');
  });

  it('evaluates critical findings as CRITICAL risk tier', () => {
    const report = createBaseReport({
      severityCounts: { critical: 2, high: 1, moderate: 0, low: 0, unknown: 0 }
    });
    const res = calculateRiskScore(report);
    // 2*30 + 15 = 75
    expect(res.score).toBe(75);
    expect(res.tier).toBe('CRITICAL');
  });

  it('caps risk score at 100', () => {
    const report = createBaseReport({
      severityCounts: { critical: 10, high: 10, moderate: 10, low: 10, unknown: 0 },
      maintenanceRisksCount: 10,
      deprecatedPackagesCount: 10
    });
    const res = calculateRiskScore(report);
    expect(res.score).toBe(100);
    expect(res.tier).toBe('CRITICAL');
  });
});
