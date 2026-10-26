import { describe, expect, it } from 'vitest';
import { AnalysisReport, AnalyzedPackage } from '../src/types.js';
import { buildDependencyGraph } from '../src/web/services/dependency-graph.js';

function packageNode(
  name: string,
  version: string,
  options: { direct?: boolean; vulnerable?: boolean; paths?: string[] } = {}
): AnalyzedPackage {
  return {
    name,
    version,
    ecosystem: 'npm',
    isDirect: options.direct ?? false,
    isDev: false,
    dependencyPaths: options.paths ?? [],
    vulnerabilities: [],
    hasVulnerability: options.vulnerable ?? false
  };
}

function report(packages: AnalyzedPackage[]): AnalysisReport {
  return {
    summary: {
      manifestType: 'package-lock.json',
      ecosystem: 'npm',
      totalUniquePackages: packages.length,
      totalDependenciesResolved: packages.length,
      directDependenciesCount: packages.filter((pkg) => pkg.isDirect).length,
      vulnerablePackagesCount: packages.filter((pkg) => pkg.hasVulnerability).length,
      totalAdvisoriesCount: 0,
      severityCounts: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 },
      scanDurationMs: 0,
      timestamp: '2025-01-01T00:00:00.000Z'
    },
    packages,
    vulnerablePackages: packages.filter((pkg) => pkg.hasVulnerability),
    maintenanceRiskPackages: [],
    warnings: []
  };
}

describe('dependency path reconstruction', () => {
  it('builds only exact version-qualified parent edges and vulnerable paths', () => {
    const root = packageNode('root-dep', '1.0.0', {
      direct: true,
      paths: ['root-dep@1.0.0 -> nested-dep@2.0.0']
    });
    const vulnerable = packageNode('nested-dep', '2.0.0', {
      vulnerable: true,
      paths: ['root-dep@1.0.0 -> nested-dep@2.0.0']
    });
    const graph = buildDependencyGraph(report([root, vulnerable]));

    expect(graph.available).toBe(true);
    expect(graph.edges).toHaveLength(1);
    expect(graph.vulnerablePaths).toHaveLength(1);
    expect(graph.vulnerablePaths[0]?.map((node) => node.name)).toEqual(['root-dep', 'nested-dep']);
  });

  it('does not invent paths when metadata is missing, malformed, or version-ambiguous', () => {
    const root = packageNode('root-dep', '1.0.0', {
      direct: true,
      paths: ['root-dep -> missing@2.0.0', 'root-dep@1.0.0 -> duplicated@2.0.0']
    });
    const duplicateOne = packageNode('duplicated', '2.0.0');
    const duplicateTwo = packageNode('duplicated', '2.0.0', { vulnerable: true });
    const graph = buildDependencyGraph(report([root, duplicateOne, duplicateTwo]));

    expect(graph.available).toBe(false);
    expect(graph.edges).toHaveLength(0);
    expect(graph.vulnerablePaths).toHaveLength(0);
  });

  it('detects cycles and bounds path traversal', () => {
    const a = packageNode('a', '1.0.0', {
      direct: true,
      paths: ['a@1.0.0 -> b@1.0.0', 'a@1.0.0 -> b@1.0.0 -> a@1.0.0']
    });
    const b = packageNode('b', '1.0.0', {
      paths: ['a@1.0.0 -> b@1.0.0 -> a@1.0.0']
    });
    const graph = buildDependencyGraph(report([a, b]));

    expect(graph.cycleDetected).toBe(true);
    expect(graph.edges).toHaveLength(2);
    expect(graph.vulnerablePaths).toHaveLength(0);
  });

  it('reports unavailable relationships for inventory-only parser paths', () => {
    const graph = buildDependencyGraph(report([
      packageNode('dependency', '1.0.0', { direct: true, paths: ['dependency'] })
    ]));
    expect(graph.available).toBe(false);
  });

  it('preserves scoped npm package names in exact paths', () => {
    const root = packageNode('@scope/root', '1.0.0', {
      direct: true,
      paths: ['@scope/root@1.0.0 -> @scope/child@2.0.0']
    });
    const child = packageNode('@scope/child', '2.0.0', { vulnerable: true });
    const graph = buildDependencyGraph(report([root, child]));

    expect(graph.available).toBe(true);
    expect(graph.vulnerablePaths[0]?.map((node) => node.name)).toEqual(['@scope/root', '@scope/child']);
  });
});
