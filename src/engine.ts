import { parseNpmManifests, ParseOptions } from './parser.js';
import { OSVClient, OSVClientOptions } from './osv-client.js';
import {
  AnalysisReport,
  AnalyzedPackage,
  ScanSummary,
  VulnerabilityFinding,
  PackageIdentifier
} from './types.js';

export interface AnalyzerOptions {
  parseOptions?: ParseOptions;
  osvOptions?: OSVClientOptions;
}

export class VeylixEngine {
  private osvClient: OSVClient;
  private parseOptions: ParseOptions;

  constructor(options: AnalyzerOptions = {}) {
    this.osvClient = new OSVClient(options.osvOptions);
    this.parseOptions = options.parseOptions || {};
  }

  /**
   * Analyzes an npm project from manifest & lockfile contents.
   */
  async analyzeNpmProject(
    packageJsonStr?: string | null,
    packageLockJsonStr?: string | null
  ): Promise<AnalysisReport> {
    const startTime = performance.now();

    // 1. Parse manifests
    const parseResult = parseNpmManifests(packageJsonStr, packageLockJsonStr, this.parseOptions);
    const packages = parseResult.packages;

    // 2. Query OSV batch API
    const osvResponse = await this.osvClient.queryBatch(packages);

    // 3. Map responses strictly by array index to each package
    // OSV /v1/querybatch preserves the exact input query order in results array
    if (osvResponse.results.length !== packages.length) {
      throw new Error(
        `OSV API response alignment error: Sent ${packages.length} package queries but received ${osvResponse.results.length} result items.`
      );
    }

    const analyzedPackages: AnalyzedPackage[] = [];
    const vulnerablePackages: AnalyzedPackage[] = [];

    let totalAdvisoriesCount = 0;
    const severityCounts = {
      critical: 0,
      high: 0,
      moderate: 0,
      low: 0,
      unknown: 0
    };

    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i]!;
      const resultItem = osvResponse.results[i];
      const rawVulns = resultItem?.vulns || [];

      const vulnerabilities: VulnerabilityFinding[] = rawVulns.map((adv) => {
        const finding = OSVClient.transformAdvisory(adv, pkg.name, pkg.version);

        // Update aggregate severity counters
        switch (finding.severityLevel) {
          case 'CRITICAL':
            severityCounts.critical++;
            break;
          case 'HIGH':
            severityCounts.high++;
            break;
          case 'MODERATE':
            severityCounts.moderate++;
            break;
          case 'LOW':
            severityCounts.low++;
            break;
          default:
            severityCounts.unknown++;
            break;
        }

        return finding;
      });

      totalAdvisoriesCount += vulnerabilities.length;

      const analyzedPkg: AnalyzedPackage = {
        name: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        isDirect: pkg.isDirect,
        isDev: pkg.isDev,
        dependencyPaths: pkg.dependencyPaths,
        vulnerabilities,
        hasVulnerability: vulnerabilities.length > 0
      };

      analyzedPackages.push(analyzedPkg);
      if (analyzedPkg.hasVulnerability) {
        vulnerablePackages.push(analyzedPkg);
      }
    }

    const endTime = performance.now();
    const scanDurationMs = Math.round((endTime - startTime) * 100) / 100;

    // Count unique package names regardless of multiple versions
    const uniquePackageNames = new Set(packages.map((p) => p.name)).size;
    const directCount = packages.filter((p) => p.isDirect).length;

    const summary: ScanSummary = {
      manifestType: 'package-lock.json',
      lockfileVersion: parseResult.lockfileVersion,
      totalUniquePackages: uniquePackageNames,
      totalDependenciesResolved: packages.length,
      directDependenciesCount: directCount,
      vulnerablePackagesCount: vulnerablePackages.length,
      totalAdvisoriesCount,
      severityCounts,
      scanDurationMs,
      timestamp: new Date().toISOString()
    };

    return {
      summary,
      packages: analyzedPackages,
      vulnerablePackages,
      warnings: parseResult.warnings
    };
  }
}
