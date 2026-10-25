import { parseNpmManifests, ParseOptions } from './parser.js';
import { parseRequirementsTxt, parsePoetryLock, PythonParseOptions } from './python-parser.js';
import { OSVClient, OSVClientOptions } from './osv-client.js';
import { DepsDevClient, DepsDevClientOptions } from './deps-client.js';
import {
  AnalysisReport,
  AnalyzedPackage,
  ScanSummary,
  VulnerabilityFinding,
  PackageIdentifier,
  SupportedEcosystem,
  MaintenanceHealthEstimate
} from './types.js';

export interface AnalyzerOptions {
  parseOptions?: ParseOptions;
  pythonParseOptions?: PythonParseOptions;
  osvOptions?: OSVClientOptions;
  depsDevOptions?: DepsDevClientOptions;
  fetchMaintenanceHealth?: boolean; // When true, enriches packages with OpenSSF & deps.dev metrics
  maxMaintenanceLookups?: number; // Caps outbound maintenance queries (e.g. for direct packages only)
}

export class VeylixEngine {
  private osvClient: OSVClient;
  private depsDevClient: DepsDevClient;
  private parseOptions: ParseOptions;
  private pythonParseOptions: PythonParseOptions;
  private fetchMaintenanceHealth: boolean;
  private maxMaintenanceLookups: number;

  constructor(options: AnalyzerOptions = {}) {
    this.osvClient = new OSVClient(options.osvOptions);
    this.depsDevClient = new DepsDevClient(options.depsDevOptions);
    this.parseOptions = options.parseOptions || {};
    this.pythonParseOptions = options.pythonParseOptions || {};
    this.fetchMaintenanceHealth = Boolean(options.fetchMaintenanceHealth);
    this.maxMaintenanceLookups = options.maxMaintenanceLookups ?? 30;
  }

  /**
   * Analyzes an npm project from manifest & lockfile contents.
   */
  async analyzeNpmProject(
    packageJsonStr?: string | null,
    packageLockJsonStr?: string | null
  ): Promise<AnalysisReport> {
    const startTime = performance.now();
    const parseResult = parseNpmManifests(packageJsonStr, packageLockJsonStr, this.parseOptions);

    return this.processPackages(
      parseResult.packages,
      'package-lock.json',
      'npm',
      startTime,
      parseResult.lockfileVersion,
      parseResult.warnings
    );
  }

  /**
   * Analyzes a Python project using requirements.txt.
   */
  async analyzePythonRequirements(
    requirementsTxtStr: string
  ): Promise<AnalysisReport> {
    const startTime = performance.now();
    const parseResult = parseRequirementsTxt(requirementsTxtStr, this.pythonParseOptions);

    return this.processPackages(
      parseResult.packages,
      'requirements.txt',
      'pypi',
      startTime,
      undefined,
      parseResult.warnings
    );
  }

  /**
   * Analyzes a Python project using poetry.lock and optional pyproject.toml.
   */
  async analyzePoetryProject(
    poetryLockStr: string,
    pyprojectTomlStr?: string | null
  ): Promise<AnalysisReport> {
    const startTime = performance.now();
    const parseResult = parsePoetryLock(poetryLockStr, pyprojectTomlStr, this.pythonParseOptions);

    return this.processPackages(
      parseResult.packages,
      'poetry.lock',
      'pypi',
      startTime,
      undefined,
      parseResult.warnings
    );
  }

  /**
   * Shared execution pipeline:
   * 1. Query OSV for vulnerability advisories.
   * 2. (Optional) Query deps.dev for maintenance health estimates.
   * 3. Construct structured report keeping vulnerability and maintenance data strictly separated.
   */
  private async processPackages(
    packages: PackageIdentifier[],
    manifestType: 'package-lock.json' | 'requirements.txt' | 'poetry.lock',
    ecosystem: SupportedEcosystem,
    startTime: number,
    lockfileVersion?: number,
    warnings: string[] = []
  ): Promise<AnalysisReport> {
    // 1. Query OSV batch API (chunked up to 1,000 queries per HTTP request)
    const osvResponse = await this.osvClient.queryBatch(packages);

    if (osvResponse.results.length !== packages.length) {
      throw new Error(
        `OSV API response alignment error: Sent ${packages.length} package queries but received ${osvResponse.results.length} result items.`
      );
    }

    // 2. Query deps.dev for maintenance health if enabled
    const maintenanceHealthMap = new Map<string, MaintenanceHealthEstimate>();

    if (this.fetchMaintenanceHealth) {
      // Prioritize direct dependencies to stay within subrequest limits
      const targets = packages
        .filter((p) => p.isDirect)
        .slice(0, this.maxMaintenanceLookups);

      // Fetch health estimates concurrently
      await Promise.all(
        targets.map(async (pkg) => {
          const key = `${pkg.name}@${pkg.version}`;
          const health = await this.depsDevClient.getPackageHealth(pkg.name, pkg.version, pkg.ecosystem);
          maintenanceHealthMap.set(key, health);
        })
      );
    }

    const analyzedPackages: AnalyzedPackage[] = [];
    const vulnerablePackages: AnalyzedPackage[] = [];
    const maintenanceRiskPackages: AnalyzedPackage[] = [];

    let totalAdvisoriesCount = 0;
    let maintenanceRisksCount = 0;
    let deprecatedPackagesCount = 0;

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

      // 1. Map OSV vulnerabilities
      const vulnerabilities: VulnerabilityFinding[] = rawVulns.map((adv) => {
        const finding = OSVClient.transformAdvisory(adv, pkg.name, pkg.version);

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

      // 2. Map Maintenance Health (Strictly separate from vulnerability data)
      const healthKey = `${pkg.name}@${pkg.version}`;
      const maintenanceHealth = maintenanceHealthMap.get(healthKey);

      if (maintenanceHealth) {
        if (maintenanceHealth.status === 'MAINTENANCE_RISK') {
          maintenanceRisksCount++;
        }
        if (maintenanceHealth.isDeprecated) {
          deprecatedPackagesCount++;
        }
      }

      const analyzedPkg: AnalyzedPackage = {
        name: pkg.name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        isDirect: pkg.isDirect,
        isDev: pkg.isDev,
        dependencyPaths: pkg.dependencyPaths,
        vulnerabilities,
        hasVulnerability: vulnerabilities.length > 0,
        maintenanceHealth
      };

      analyzedPackages.push(analyzedPkg);

      if (analyzedPkg.hasVulnerability) {
        vulnerablePackages.push(analyzedPkg);
      }
      if (maintenanceHealth && maintenanceHealth.status === 'MAINTENANCE_RISK') {
        maintenanceRiskPackages.push(analyzedPkg);
      }
    }

    const endTime = performance.now();
    const scanDurationMs = Math.round((endTime - startTime) * 100) / 100;

    const uniquePackageNames = new Set(packages.map((p) => p.name)).size;
    const directCount = packages.filter((p) => p.isDirect).length;

    const summary: ScanSummary = {
      manifestType,
      ecosystem,
      lockfileVersion,
      totalUniquePackages: uniquePackageNames,
      totalDependenciesResolved: packages.length,
      directDependenciesCount: directCount,
      vulnerablePackagesCount: vulnerablePackages.length,
      totalAdvisoriesCount,
      maintenanceRisksCount: this.fetchMaintenanceHealth ? maintenanceRisksCount : undefined,
      deprecatedPackagesCount: this.fetchMaintenanceHealth ? deprecatedPackagesCount : undefined,
      severityCounts,
      scanDurationMs,
      timestamp: new Date().toISOString()
    };

    return {
      summary,
      packages: analyzedPackages,
      vulnerablePackages,
      maintenanceRiskPackages,
      warnings
    };
  }
}
