import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  assignScanToProject,
  createLocalWorkspaceProject,
  deleteLocalWorkspaceProject,
  loadLocalWorkspace,
  setProjectBaseline
} from '../src/web/services/workspace-storage.js';
import {
  isFindingIgnored,
  loadFindingDispositions,
  saveFindingDisposition,
  stableFindingId
} from '../src/web/services/finding-dispositions.js';
import { VulnerabilityFinding } from '../src/types.js';

class MemoryStorage implements Storage {
  private values = new Map<string, string>();
  get length(): number { return this.values.size; }
  clear(): void { this.values.clear(); }
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  key(index: number): string | null { return Array.from(this.values.keys())[index] ?? null; }
  removeItem(key: string): void { this.values.delete(key); }
  setItem(key: string, value: string): void { this.values.set(key, String(value)); }
}

beforeEach(() => {
  vi.stubGlobal('localStorage', new MemoryStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Browser-local workspace and finding dispositions', () => {
  it('creates projects, groups scans, requires project assignment for a baseline, and cleans up assignments', () => {
    const created = createLocalWorkspaceProject('Payments');
    expect(created.success).toBe(true);
    const project = created.workspace.projects[0]!;
    expect(createLocalWorkspaceProject('payments').error).toContain('already exists');
    expect(setProjectBaseline(project.id, 'scan-a').error).toContain('assigned');
    expect(assignScanToProject('scan-a', project.id).success).toBe(true);
    expect(setProjectBaseline(project.id, 'scan-a').workspace.baselines[project.id]).toBe('scan-a');

    const deleted = deleteLocalWorkspaceProject(project.id);
    expect(deleted.workspace.projects).toEqual([]);
    expect(deleted.workspace.scanProjects).toEqual({});
    expect(deleted.workspace.baselines).toEqual({});
  });

  it('creates a stable advisory finding key independent of installed version', () => {
    const finding: VulnerabilityFinding = {
      advisoryId: 'GHSA-AbCd',
      aliases: ['CVE-2025-1234'],
      severityLevel: 'HIGH',
      summary: 'Test advisory',
      actionableRecommendation: 'Update the package.'
    };
    expect(stableFindingId('npm', 'Example', finding)).toBe(
      stableFindingId('npm', 'example', { ...finding, severityLevel: 'LOW' })
    );
    expect(stableFindingId('npm', 'example', finding)).not.toBe(stableFindingId('pypi', 'example', finding));
  });

  it('persists notes and expiring ignores locally and treats expired ignores as active findings', () => {
    const findingId = 'npm:example:ghsa-test';
    const result = saveFindingDisposition(findingId, 'Reviewed; tracking upstream fix.', '2099-12-31');
    expect(result.success).toBe(true);
    const disposition = loadFindingDispositions()[0]!;
    expect(disposition.note).toContain('tracking upstream');
    expect(isFindingIgnored(disposition, Date.parse('2099-01-01T00:00:00Z'))).toBe(true);
    expect(isFindingIgnored(disposition, Date.parse('2100-01-01T00:00:00Z'))).toBe(false);
    expect(saveFindingDisposition(findingId, '', '2000-01-01').error).toContain('future date');
  });
});
