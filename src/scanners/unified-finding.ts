import { createHash } from 'node:crypto';
import { SecurityFinding } from './local-security-scanner.js';
import { VulnerabilityFinding } from '../types.js';

export type UnifiedFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type UnifiedFindingCategory =
  | 'dependency'
  | 'secret'
  | 'configuration'
  | 'infrastructure'
  | 'workflow'
  | 'license'
  | 'typosquatting'
  | 'custom'
  | 'other';

export interface UnifiedFinding {
  id: string;
  scanner: string;
  ruleId: string;
  category: UnifiedFindingCategory;
  severity: UnifiedFindingSeverity;
  confidence: number;
  confidenceLevel: 'confirmed' | 'heuristic';
  filePath?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  evidence: string;
  description: string;
  impact: string;
  remediation: string;
  references: string[];
  project?: string;
  dependency?: {
    name: string;
    version?: string;
    ecosystem?: string;
    direct?: boolean;
  };
}

function stableFindingId(parts: Array<string | number | undefined>): string {
  const identity = parts.map((part) => String(part ?? '').trim()).join('\u0000');
  return `vf-${createHash('sha256').update(identity).digest('hex').slice(0, 24)}`;
}

function securityCategory(scanner: SecurityFinding['scanner']): UnifiedFindingCategory {
  switch (scanner) {
    case 'secrets': return 'secret';
    case 'terraform':
    case 'kubernetes': return 'infrastructure';
    case 'github-actions': return 'workflow';
    case 'license': return 'license';
    case 'typosquatting': return 'typosquatting';
    case 'custom': return 'custom';
    case 'dockerfile':
    case 'docker-image':
    case 'configuration': return 'configuration';
  }
}

export function normalizeSecurityFinding(
  finding: SecurityFinding,
  scannerId: string,
  project?: string
): UnifiedFinding {
  const confidenceLevel = finding.confidence;
  return {
    id: stableFindingId([
      scannerId, finding.ruleId, finding.filePath, finding.lineNumber,
      finding.packageName, finding.evidence
    ]),
    scanner: scannerId,
    ruleId: finding.ruleId,
    category: securityCategory(finding.scanner),
    severity: finding.severity,
    confidence: confidenceLevel === 'confirmed' ? 1 : 0.5,
    confidenceLevel,
    ...(finding.filePath ? { filePath: finding.filePath } : {}),
    ...(finding.lineNumber !== undefined ? { startLine: finding.lineNumber, endLine: finding.lineNumber } : {}),
    evidence: finding.evidence,
    description: finding.title,
    impact: finding.title,
    remediation: finding.remediation,
    references: [],
    ...(project ? { project } : {}),
    ...(finding.packageName ? {
      dependency: { name: finding.packageName }
    } : {})
  };
}

const severityFromOsv: Record<VulnerabilityFinding['severityLevel'], UnifiedFindingSeverity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  LOW: 'low',
  UNKNOWN: 'unknown'
};

export function normalizeDependencyFinding(input: {
  packageName: string;
  version: string;
  ecosystem: string;
  direct: boolean;
  advisory: VulnerabilityFinding;
  filePath: string;
  project?: string;
  scannerId: string;
}): UnifiedFinding {
  const advisory = input.advisory;
  const summary = advisory.summary || `Known vulnerability ${advisory.advisoryId}`;
  const references = [
    `https://osv.dev/vulnerability/${encodeURIComponent(advisory.advisoryId)}`,
    ...advisory.aliases.map((alias) => `https://osv.dev/vulnerability/${encodeURIComponent(alias)}`)
  ];
  return {
    id: stableFindingId([
      input.scannerId, input.ecosystem, input.packageName, advisory.advisoryId, input.filePath
    ]),
    scanner: input.scannerId,
    ruleId: `osv.${advisory.advisoryId.toLowerCase()}`,
    category: 'dependency',
    severity: severityFromOsv[advisory.severityLevel],
    confidence: 1,
    confidenceLevel: 'confirmed',
    filePath: input.filePath,
    evidence: `${input.packageName}@${input.version} is listed as affected by ${advisory.advisoryId}.`,
    description: summary,
    impact: advisory.details || summary,
    remediation: advisory.actionableRecommendation,
    references,
    ...(input.project ? { project: input.project } : {}),
    dependency: {
      name: input.packageName,
      version: input.version,
      ecosystem: input.ecosystem,
      direct: input.direct
    }
  };
}
