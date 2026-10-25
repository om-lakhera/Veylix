import { AnalysisReport } from '../../types.js';
import { ScanHistoryItem, ScanTargetInfo, calculateRiskScore } from '../types.js';

const STORAGE_KEY = 'veylix_scan_history_v1';
const MAX_SAVED_SCANS = 25;

function isScanHistoryItem(value: unknown): value is ScanHistoryItem {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<ScanHistoryItem>;
  const report = item.report;
  return typeof item.id === 'string' &&
    typeof item.timestamp === 'string' &&
    Boolean(item.target && typeof item.target.name === 'string' &&
      Array.isArray(item.target.scannedFiles) &&
      (item.target.type === 'file-upload' || item.target.type === 'github-repo')) &&
    (item.ecosystem === 'npm' || item.ecosystem === 'pypi') &&
    typeof item.totalPackages === 'number' &&
    typeof item.vulnerabilityCount === 'number' &&
    Boolean(report && Array.isArray(report.packages) &&
      Array.isArray(report.vulnerablePackages) &&
      Array.isArray(report.maintenanceRiskPackages) &&
      Array.isArray(report.warnings) &&
      report.summary && typeof report.summary === 'object' &&
      report.summary.severityCounts && typeof report.summary.severityCounts === 'object');
}

export function loadScanHistory(): ScanHistoryItem[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      const validItems = parsed.filter(isScanHistoryItem);
      if (validItems.length !== parsed.length) {
        console.warn('Some saved scan history entries were invalid and have been skipped.');
      }
      return validItems.slice(0, MAX_SAVED_SCANS);
    }
    return [];
  } catch (e) {
    console.warn('Failed to load scan history from localStorage:', e);
    return [];
  }
}

export function saveScanToHistory(target: ScanTargetInfo, report: AnalysisReport): ScanHistoryItem {
  const risk = calculateRiskScore(report);
  const item: ScanHistoryItem = {
    id: `scan_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    target,
    ecosystem: report.summary.ecosystem,
    manifestType: report.summary.manifestType,
    totalPackages: report.summary.totalUniquePackages,
    vulnerabilityCount: report.summary.totalAdvisoriesCount,
    criticalCount: report.summary.severityCounts.critical,
    highCount: report.summary.severityCounts.high,
    moderateCount: report.summary.severityCounts.moderate,
    lowCount: report.summary.severityCounts.low,
    maintenanceRiskCount: report.summary.maintenanceRisksCount || 0,
    riskScore: risk.score,
    riskTier: risk.tier,
    report
  };

  try {
    const existing = loadScanHistory();
    const updated = [item, ...existing.filter((s) => s.id !== item.id)].slice(0, MAX_SAVED_SCANS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (e) {
    console.warn('Failed to persist scan history to localStorage:', e);
  }

  return item;
}

export function deleteScanFromHistory(
  id: string
): { success: boolean; items: ScanHistoryItem[] } {
  try {
    const existing = loadScanHistory();
    const updated = existing.filter((s) => s.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return { success: true, items: updated };
  } catch (e) {
    console.warn('Failed to delete scan item from localStorage:', e);
    return { success: false, items: [] };
  }
}

export function clearAllScanHistory(): boolean {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch (e) {
    console.warn('Failed to clear scan history from localStorage:', e);
    return false;
  }
}

export function downloadJsonFile(filename: string, data: unknown): void {
  const jsonStr = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
