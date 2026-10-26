import { AnalysisReport, SupportedEcosystem } from '../types.js';

export type ActiveTab =
  | 'dashboard'
  | 'new-scan'
  | 'results'
  | 'history'
  | 'dependencies'
  | 'advisories'
  | 'about'
  | 'faq'
  | 'documentation'
  | 'privacy'
  | 'terms'
  | 'cookies'
  | 'support'
  | 'not-found';

export interface AppRoute {
  page: ActiveTab;
  scanId?: string;
}

export interface ScanTargetInfo {
  type: 'file-upload' | 'github-repo';
  name: string;
  branch?: string;
  scannedFiles: string[];
}

export interface ScanHistoryItem {
  id: string;
  timestamp: string;
  target: ScanTargetInfo;
  ecosystem: SupportedEcosystem;
  manifestType: string;
  totalPackages: number;
  vulnerabilityCount: number;
  criticalCount: number;
  highCount: number;
  moderateCount: number;
  lowCount: number;
  maintenanceRiskCount: number;
  riskScore: number;
  riskTier: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  report: AnalysisReport;
}

export interface RiskEvaluation {
  score: number; // 0 to 100
  tier: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  label: string;
  colorVar: string;
  badgeClass: string;
}

/**
 * Calculates deterministic Veylix Risk Score (0 - 100) based on severity counts and maintenance signals.
 */
export function calculateRiskScore(report: AnalysisReport): RiskEvaluation {
  const { severityCounts, maintenanceRisksCount = 0, deprecatedPackagesCount = 0 } = report.summary;

  let score = 0;
  score += Math.min(severityCounts.critical * 30, 60);
  score += Math.min(severityCounts.high * 15, 30);
  score += Math.min(severityCounts.moderate * 5, 15);
  score += Math.min(severityCounts.low * 1, 5);
  score += Math.min(maintenanceRisksCount * 8, 20);
  score += Math.min(deprecatedPackagesCount * 12, 24);

  const finalScore = Math.min(Math.round(score), 100);

  if (finalScore >= 70) {
    return {
      score: finalScore,
      tier: 'CRITICAL',
      label: 'Critical Risk',
      colorVar: 'var(--severity-critical)',
      badgeClass: 'badge-critical'
    };
  }

  if (finalScore >= 40) {
    return {
      score: finalScore,
      tier: 'HIGH',
      label: 'High Risk',
      colorVar: 'var(--severity-high)',
      badgeClass: 'badge-high'
    };
  }

  if (finalScore >= 15) {
    return {
      score: finalScore,
      tier: 'MODERATE',
      label: 'Moderate Risk',
      colorVar: 'var(--severity-moderate)',
      badgeClass: 'badge-moderate'
    };
  }

  return {
    score: finalScore,
    tier: 'LOW',
    label: 'Low Risk',
    colorVar: 'var(--severity-low)',
    badgeClass: 'badge-low'
  };
}
