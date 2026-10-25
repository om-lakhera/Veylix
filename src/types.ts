/**
 * Core type definitions for Veylix Dependency Analysis Engine
 */

export type SupportedEcosystem = 'npm' | 'pypi';

export interface PackageIdentifier {
  name: string;
  version: string;
  ecosystem: SupportedEcosystem;
  isDirect: boolean;
  isDev: boolean;
  dependencyPaths: string[]; // e.g. ["root -> express -> qs"]
  declaredConstraint?: string; // e.g. ">=2.0,<3.0" if unpinned or range
}

export interface ManifestParseResult {
  manifestName?: string;
  manifestVersion?: string;
  manifestType: 'package-lock.json' | 'requirements.txt' | 'poetry.lock';
  lockfileVersion?: number;
  packages: PackageIdentifier[];
  warnings: string[];
}

export interface OSVQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version: string;
}

export interface OSVBatchRequest {
  queries: OSVQuery[];
}

export interface OSVSeverity {
  type: string; // e.g. "CVSS_V3", "CVSS_V4"
  score: string; // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}

export interface OSVAffectedRange {
  type: string; // "ECOSYSTEM", "SEMVER", "GIT"
  events: Array<{
    introduced?: string;
    fixed?: string;
    limit?: string;
    last_affected?: string;
  }>;
}

export interface OSVAffected {
  package: {
    name: string;
    ecosystem: string;
    purl?: string;
  };
  ranges?: OSVAffectedRange[];
  versions?: string[];
  ecosystem_specific?: Record<string, unknown>;
  database_specific?: Record<string, unknown>;
}

export interface OSVAdvisory {
  id: string; // GHSA-xxx or CVE-xxx
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  severities?: OSVSeverity[];
  severity?: Array<{ type: string; score: string }>;
  affected?: OSVAffected[];
  database_specific?: {
    severity?: string; // "MODERATE", "HIGH", "CRITICAL", "LOW"
    cwe_ids?: string[];
    github_reviewed?: boolean;
    [key: string]: unknown;
  };
}

export interface OSVBatchResponseItem {
  vulns?: OSVAdvisory[];
}

export interface OSVBatchResponse {
  results: OSVBatchResponseItem[];
}

export interface VulnerabilityFinding {
  advisoryId: string;
  aliases: string[];
  severityLevel: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN';
  cvssScore?: string;
  summary: string;
  details?: string;
  fixedVersion?: string;
  published?: string;
  affectedVersionRange?: string;
  actionableRecommendation: string;
}

/**
 * Maintenance and repository vitality estimate from OpenSSF Scorecard & deps.dev.
 * Kept strictly independent from vulnerability findings.
 */
export interface MaintenanceHealthEstimate {
  scorecardScore: number | null; // 0-10 overall Scorecard score
  maintainedScore: number | null; // 0-10 OpenSSF Maintained sub-check score
  publishedAt?: string;
  daysSinceRelease?: number;
  isDeprecated?: boolean;
  deprecatedReason?: string;
  sourceRepo?: string;
  starsCount?: number;
  openIssuesCount?: number;
  status: 'ACTIVE' | 'MAINTENANCE_RISK' | 'UNKNOWN' | 'DATA_UNAVAILABLE';
  signals: string[]; // Explanatory reasons grounded in empirical metrics
}

export interface AnalyzedPackage {
  name: string;
  version: string;
  ecosystem: SupportedEcosystem;
  isDirect: boolean;
  isDev: boolean;
  dependencyPaths: string[];
  vulnerabilities: VulnerabilityFinding[];
  hasVulnerability: boolean;
  maintenanceHealth?: MaintenanceHealthEstimate;
}

export interface ScanSummary {
  manifestType: 'package-lock.json' | 'requirements.txt' | 'poetry.lock';
  ecosystem: SupportedEcosystem;
  lockfileVersion?: number;
  totalUniquePackages: number;
  totalDependenciesResolved: number;
  directDependenciesCount: number;
  vulnerablePackagesCount: number;
  totalAdvisoriesCount: number;
  maintenanceRisksCount?: number;
  deprecatedPackagesCount?: number;
  severityCounts: {
    critical: number;
    high: number;
    moderate: number;
    low: number;
    unknown: number;
  };
  scanDurationMs: number;
  timestamp: string;
}

export interface AnalysisReport {
  summary: ScanSummary;
  packages: AnalyzedPackage[];
  vulnerablePackages: AnalyzedPackage[];
  maintenanceRiskPackages: AnalyzedPackage[];
  warnings: string[];
}
