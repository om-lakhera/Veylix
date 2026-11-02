import { SupportedEcosystem, VulnerabilityFinding } from '../../types.js';

const STORAGE_KEY = 'veylix_finding_dispositions_v1';
const MAX_DISPOSITIONS = 3_000;

export interface FindingDisposition {
  findingId: string;
  note: string;
  ignoredUntil?: string;
  updatedAt: string;
}

function isFindingDisposition(value: unknown): value is FindingDisposition {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<FindingDisposition>;
  return typeof item.findingId === 'string' &&
    item.findingId.length > 0 &&
    item.findingId.length <= 512 &&
    typeof item.note === 'string' &&
    item.note.length <= 1_000 &&
    typeof item.updatedAt === 'string' &&
    Number.isFinite(Date.parse(item.updatedAt)) &&
    (item.ignoredUntil === undefined || (
      typeof item.ignoredUntil === 'string' && Number.isFinite(Date.parse(item.ignoredUntil))
    ));
}

export function stableFindingId(
  ecosystem: SupportedEcosystem,
  packageName: string,
  finding: VulnerabilityFinding
): string {
  const identifiers = Array.from(new Set([finding.advisoryId, ...finding.aliases]
    .map((identifier) => identifier.trim().toUpperCase())
    .filter(Boolean))).sort();
  return [
    ecosystem,
    encodeURIComponent(packageName.trim().toLowerCase()),
    encodeURIComponent(identifiers.join(','))
  ].join(':');
}

export function loadFindingDispositions(): FindingDisposition[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      console.warn('Saved finding annotations were invalid and have been skipped.');
      return [];
    }
    const valid = parsed.filter(isFindingDisposition);
    if (valid.length !== parsed.length) {
      console.warn('Some saved finding annotations were invalid and have been skipped.');
    }
    return valid.slice(0, MAX_DISPOSITIONS);
  } catch (error) {
    console.warn('Failed to load local finding annotations:', error);
    return [];
  }
}

export function saveFindingDisposition(
  findingId: string,
  note: string,
  ignoredUntil?: string
): { success: boolean; disposition?: FindingDisposition; error?: string } {
  if (!findingId.trim() || findingId.length > 512) {
    return { success: false, error: 'Finding identifier is invalid.' };
  }
  if (note.length > 1_000) {
    return { success: false, error: 'Annotation must be 1,000 characters or fewer.' };
  }
  let expiresAt: string | undefined;
  if (ignoredUntil) {
    const date = new Date(`${ignoredUntil}T23:59:59.999`);
    if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) {
      return { success: false, error: 'Ignore expiration must be a future date.' };
    }
    expiresAt = date.toISOString();
  }

  const disposition: FindingDisposition = {
    findingId,
    note: note.trim(),
    ...(expiresAt ? { ignoredUntil: expiresAt } : {}),
    updatedAt: new Date().toISOString()
  };
  try {
    const existing = loadFindingDispositions().filter((item) => item.findingId !== findingId);
    if (!disposition.note && !expiresAt) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));
      return { success: true };
    }
    const updated = [disposition, ...existing].slice(0, MAX_DISPOSITIONS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return { success: true, disposition };
  } catch (error) {
    console.warn('Failed to save local finding annotation:', error);
    return { success: false, error: 'Could not save this annotation in browser storage.' };
  }
}

export function isFindingIgnored(
  disposition: FindingDisposition | undefined,
  now = Date.now()
): boolean {
  return Boolean(disposition?.ignoredUntil && Date.parse(disposition.ignoredUntil) > now);
}

export function clearFindingDispositions(): boolean {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch (error) {
    console.warn('Failed to clear local finding annotations:', error);
    return false;
  }
}
