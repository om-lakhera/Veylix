/**
 * Core type definitions for Veylix Dependency Analysis Engine
 */

export type SupportedEcosystem = 'npm';

export interface PackageIdentifier {
  name: string;
  version: string;
  ecosystem: SupportedEcosystem;
  isDirect: boolean;
  isDev: boolean;
  dependencyPaths: string[]; // e.g. ["root -> express -> qs"]
}

export interface ManifestParseResult {
  manifestName?: string;
  manifestVersion?: string;
  lockfileVersion: number;
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

export interface AnalyzedPackage {
  name: string;
  version: string;
  ecosystem: SupportedEcosystem;
  isDirect: boolean;
  isDev: boolean;
  dependencyPaths: string[];
  vulnerabilities: VulnerabilityFinding[];
  hasVulnerability: boolean;
}

export interface ScanSummary {
  manifestType: 'package-lock.json';
  lockfileVersion: number;
  totalUniquePackages: number;
  totalDependenciesResolved: number;
  directDependenciesCount: number;
  vulnerablePackagesCount: number;
  totalAdvisoriesCount: number;
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
  warnings: string[];
}
