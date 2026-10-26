import { describe, expect, it } from 'vitest';
import { AnalysisReport, AnalyzedPackage, VulnerabilityFinding } from '../src/types.js';
import { ScanHistoryItem } from '../src/web/types.js';
import { compareScans } from '../src/web/services/scan-comparison.js';

function packageWithFinding(
  name: string,
  version: string,
  advisoryId: string,
  severityLevel: VulnerabilityFinding['severityLevel'],
  aliases: string[] = [],
  ecosystem: 'npm' | 'pypi' = 'npm'
): AnalyzedPackage {
  const vulnerabilities: VulnerabilityFinding[] = advisoryId || severityLevel
    ? [{
        advisoryId,
        aliases,
        severityLevel,
        summary: 'Test advisory',
        actionableRecommendation: 'Review advisory'
      }]
    : [];
  return {
    name,
    version,
    ecosystem,
    isDirect: true,
    isDev: false,
    dependencyPaths: [],
    vulnerabilities,
    hasVulnerability: vulnerabilities.length > 0
  };
}

function scan(id: string, packages: AnalyzedPackage[], ecosystem: 'npm' | 'pypi' = 'npm'): ScanHistoryItem {
  const vulnerablePackages = packages.filter((pkg) => pkg.hasVulnerability);
  const report: AnalysisReport = {
    summary: {
      manifestType: ecosystem === 'npm' ? 'package-lock.json' : 'requirements.txt',
      ecosystem,
      totalUniquePackages: packages.length,
      totalDependenciesResolved: packages.length,
      directDependenciesCount: packages.filter((pkg) => pkg.isDirect).length,
      vulnerablePackagesCount: vulnerablePackages.length,
      totalAdvisoriesCount: vulnerablePackages.reduce((total, pkg) => total + pkg.vulnerabilities.length, 0),
      severityCounts: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 },
      scanDurationMs: 0,
      timestamp: `2025-01-0${id.length}T00:00:00.000Z`
    },
    packages,
    vulnerablePackages,
    maintenanceRiskPackages: [],
    warnings: []
  };
  return {
    id,
    timestamp: report.summary.timestamp,
    target: { type: 'file-upload', name: 'local', scannedFiles: [] },
    ecosystem,
    manifestType: report.summary.manifestType,
    totalPackages: packages.length,
    vulnerabilityCount: report.summary.totalAdvisoriesCount,
    criticalCount: 0,
    highCount: 0,
    moderateCount: 0,
    lowCount: 0,
    maintenanceRiskCount: 0,
    riskScore: 0,
    riskTier: 'LOW',
    report
  };
}

describe('browser-local scan comparison', () => {
  it('matches aliases across package version changes and reports severity changes', () => {
    const previous = scan('one', [packageWithFinding('lodash', '4.1.0', 'GHSA-abc', 'HIGH', ['CVE-1'])]);
    const current = scan('two', [packageWithFinding('lodash', '4.2.0', 'CVE-1', 'MODERATE', ['GHSA-abc'])]);
    const result = compareScans(previous, current);

    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.remainingFindings).toHaveLength(1);
    expect(result.remainingFindings[0]).toMatchObject({
      severityChanged: true,
      versionChanged: true
    });
    expect(result.vulnerablePackageCountDelta).toBe(0);
  });

  it('identifies reliable new and resolved advisory identifiers', () => {
    const previous = scan('one', [packageWithFinding('old-pkg', '1.0.0', 'GHSA-old', 'LOW')]);
    const current = scan('two', [packageWithFinding('new-pkg', '2.0.0', 'GHSA-new', 'HIGH')]);
    const result = compareScans(previous, current);

    expect(result.newFindings.map((finding) => finding.advisoryId)).toEqual(['GHSA-new']);
    expect(result.resolvedFindings.map((finding) => finding.advisoryId)).toEqual(['GHSA-old']);
  });

  it('marks missing identifiers and ambiguous duplicate matches uncertain', () => {
    const noIdPrevious = packageWithFinding('pkg', '1.0.0', '', 'UNKNOWN');
    const noIdCurrent = packageWithFinding('pkg', '1.1.0', '', 'UNKNOWN');
    const ambiguousPrevious = [
      packageWithFinding('dup', '1.0.0', 'GHSA-same', 'HIGH'),
      packageWithFinding('dup', '2.0.0', 'GHSA-same', 'HIGH')
    ];
    const ambiguousCurrent = [packageWithFinding('dup', '3.0.0', 'GHSA-same', 'HIGH')];
    const result = compareScans(
      scan('one', [noIdPrevious, ...ambiguousPrevious]),
      scan('two', [noIdCurrent, ...ambiguousCurrent])
    );

    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.uncertainFindings.length).toBeGreaterThanOrEqual(4);
  });

  it('does not call a finding new or resolved when the same package has an unidentifiable counterpart', () => {
    const previous = scan('one', [packageWithFinding('pkg', '1.0.0', 'GHSA-known', 'HIGH')]);
    const current = scan('two', [packageWithFinding('pkg', '1.1.0', '', 'UNKNOWN')]);
    const result = compareScans(previous, current);

    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.uncertainFindings).toHaveLength(2);
  });

  it('does not classify cross-ecosystem findings as new or resolved', () => {
    const previous = scan('one', [packageWithFinding('pkg', '1.0.0', 'GHSA-x', 'HIGH')]);
    const current = scan('two', [packageWithFinding('pkg', '1.0.0', 'GHSA-x', 'HIGH', [], 'pypi')], 'pypi');
    const result = compareScans(previous, current);

    expect(result.ecosystemMismatch).toBe(true);
    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
    expect(result.uncertainFindings).toHaveLength(2);
  });
});
