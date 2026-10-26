import { ScanHistoryItem } from '../types.js';

export interface FindingSnapshot {
  ecosystem: string;
  packageName: string;
  packageVersion: string;
  advisoryId: string;
  severity: string;
  summary: string;
  identifiers: string[];
}

export interface UncertainFinding {
  side: 'previous' | 'current' | 'both';
  finding: FindingSnapshot;
  reason: string;
}

export interface ScanComparison {
  newFindings: FindingSnapshot[];
  resolvedFindings: FindingSnapshot[];
  remainingFindings: Array<{
    previous: FindingSnapshot;
    current: FindingSnapshot;
    severityChanged: boolean;
    versionChanged: boolean;
  }>;
  uncertainFindings: UncertainFinding[];
  previousVulnerablePackageCount: number;
  currentVulnerablePackageCount: number;
  vulnerablePackageCountDelta: number;
  ecosystemMismatch: boolean;
}

function normalizePackageName(name: string, ecosystem: string): string {
  return ecosystem.toLowerCase() === 'pypi'
    ? name.toLowerCase().replace(/[-_.]+/g, '-')
    : name.toLowerCase();
}

function flattenFindings(scan: ScanHistoryItem): FindingSnapshot[] {
  const findings: FindingSnapshot[] = [];
  for (const pkg of scan.report.packages) {
    if (
      !pkg ||
      typeof pkg.name !== 'string' ||
      typeof pkg.version !== 'string' ||
      typeof pkg.ecosystem !== 'string'
    ) continue;
    if (!Array.isArray(pkg.vulnerabilities)) continue;
    for (const finding of pkg.vulnerabilities) {
      if (!finding || typeof finding !== 'object') continue;
      const advisoryId = typeof finding.advisoryId === 'string' ? finding.advisoryId.trim() : '';
      const aliases = Array.isArray(finding.aliases) ? finding.aliases : [];
      const identifiers = [advisoryId, ...aliases]
        .filter((id) => typeof id === 'string' && id.trim().length > 0)
        .map((id) => id.trim().toUpperCase());
      findings.push({
        ecosystem: pkg.ecosystem,
        packageName: pkg.name,
        packageVersion: pkg.version,
        advisoryId,
        severity: typeof finding.severityLevel === 'string' ? finding.severityLevel : 'UNKNOWN',
        summary: typeof finding.summary === 'string' ? finding.summary : '',
        identifiers: Array.from(new Set(identifiers))
      });
    }
  }
  return findings;
}

function packageKey(finding: FindingSnapshot): string {
  return `${finding.ecosystem.toLowerCase()}:${normalizePackageName(finding.packageName, finding.ecosystem)}`;
}

function identitiesOverlap(left: Set<string>, right: Set<string>): boolean {
  for (const id of left) {
    if (right.has(id)) return true;
  }
  return false;
}

export function compareScans(previous: ScanHistoryItem, current: ScanHistoryItem): ScanComparison {
  const oldFindings = flattenFindings(previous);
  const newFindings = flattenFindings(current);
  const result: ScanComparison = {
    newFindings: [],
    resolvedFindings: [],
    remainingFindings: [],
    uncertainFindings: [],
    previousVulnerablePackageCount: previous.report.vulnerablePackages.length,
    currentVulnerablePackageCount: current.report.vulnerablePackages.length,
    vulnerablePackageCountDelta:
      current.report.vulnerablePackages.length - previous.report.vulnerablePackages.length,
    ecosystemMismatch: previous.ecosystem !== current.ecosystem
  };

  if (result.ecosystemMismatch) {
    for (const finding of oldFindings) {
      result.uncertainFindings.push({
        side: 'previous',
        finding,
        reason: 'The scans use different ecosystems, so findings cannot be matched reliably.'
      });
    }
    for (const finding of newFindings) {
      result.uncertainFindings.push({
        side: 'current',
        finding,
        reason: 'The scans use different ecosystems, so findings cannot be matched reliably.'
      });
    }
    return result;
  }

  const oldIdentities = oldFindings.map((finding) => new Set(finding.identifiers));
  const newIdentities = newFindings.map((finding) => new Set(finding.identifiers));
  const oldCandidates = oldFindings.map(() => [] as number[]);
  const newCandidates = newFindings.map(() => [] as number[]);
  const packagesWithMissingIdentity = new Set<string>();
  oldFindings.forEach((finding, index) => {
    if (oldIdentities[index]!.size === 0) packagesWithMissingIdentity.add(packageKey(finding));
  });
  newFindings.forEach((finding, index) => {
    if (newIdentities[index]!.size === 0) packagesWithMissingIdentity.add(packageKey(finding));
  });

  for (let oldIndex = 0; oldIndex < oldFindings.length; oldIndex++) {
    const oldFinding = oldFindings[oldIndex]!;
    if (oldIdentities[oldIndex]!.size === 0) continue;
    for (let newIndex = 0; newIndex < newFindings.length; newIndex++) {
      const newFinding = newFindings[newIndex]!;
      if (
        packageKey(oldFinding) === packageKey(newFinding) &&
        identitiesOverlap(oldIdentities[oldIndex]!, newIdentities[newIndex]!)
      ) {
        oldCandidates[oldIndex]!.push(newIndex);
        newCandidates[newIndex]!.push(oldIndex);
      }
    }
  }

  const matchedOld = new Set<number>();
  const matchedNew = new Set<number>();

  for (let oldIndex = 0; oldIndex < oldFindings.length; oldIndex++) {
    const newIndexes = oldCandidates[oldIndex]!;
    if (newIndexes.length !== 1) continue;
    const newIndex = newIndexes[0]!;
    if (newCandidates[newIndex]!.length !== 1) continue;

    const oldFinding = oldFindings[oldIndex]!;
    const newFinding = newFindings[newIndex]!;
    matchedOld.add(oldIndex);
    matchedNew.add(newIndex);
    result.remainingFindings.push({
      previous: oldFinding,
      current: newFinding,
      severityChanged: oldFinding.severity !== newFinding.severity,
      versionChanged: oldFinding.packageVersion !== newFinding.packageVersion
    });
  }

  const uncertainOld = new Set<number>();
  const uncertainNew = new Set<number>();
  for (let oldIndex = 0; oldIndex < oldFindings.length; oldIndex++) {
    if (matchedOld.has(oldIndex)) continue;
    const candidates = oldCandidates[oldIndex]!;
    if (candidates.length > 0) {
      uncertainOld.add(oldIndex);
      candidates.forEach((index) => uncertainNew.add(index));
    } else if (
      oldIdentities[oldIndex]!.size === 0 ||
      packagesWithMissingIdentity.has(packageKey(oldFindings[oldIndex]!))
    ) {
      uncertainOld.add(oldIndex);
    }
  }
  for (let newIndex = 0; newIndex < newFindings.length; newIndex++) {
    if (matchedNew.has(newIndex)) continue;
    if (
      newCandidates[newIndex]!.length > 0 ||
      newIdentities[newIndex]!.size === 0 ||
      packagesWithMissingIdentity.has(packageKey(newFindings[newIndex]!))
    ) {
      uncertainNew.add(newIndex);
    }
  }

  for (const index of uncertainOld) {
    result.uncertainFindings.push({
      side: 'previous',
      finding: oldFindings[index]!,
      reason: oldIdentities[index]!.size === 0
        ? 'The previous finding has no advisory identifier for a reliable match.'
        : oldCandidates[index]!.length > 0
          ? 'Multiple possible matches exist; this finding is not classified as resolved.'
          : 'A finding for this package lacks an identifier, so this finding is not classified as resolved.'
    });
  }
  for (const index of uncertainNew) {
    result.uncertainFindings.push({
      side: 'current',
      finding: newFindings[index]!,
      reason: newIdentities[index]!.size === 0
        ? 'The current finding has no advisory identifier for a reliable match.'
        : newCandidates[index]!.length > 0
          ? 'Multiple possible matches exist; this finding is not classified as new.'
          : 'A finding for this package lacks an identifier, so this finding is not classified as new.'
    });
  }

  for (let oldIndex = 0; oldIndex < oldFindings.length; oldIndex++) {
    if (!matchedOld.has(oldIndex) && !uncertainOld.has(oldIndex)) {
      result.resolvedFindings.push(oldFindings[oldIndex]!);
    }
  }
  for (let newIndex = 0; newIndex < newFindings.length; newIndex++) {
    if (!matchedNew.has(newIndex) && !uncertainNew.has(newIndex)) {
      result.newFindings.push(newFindings[newIndex]!);
    }
  }

  return result;
}
