import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { normalizeSecurityFinding } from '../src/scanners/unified-finding.js';
import { scanRepository, RepositoryScanner } from '../src/scanners/repository-scanner.js';
import { SecurityFinding } from '../src/scanners/local-security-scanner.js';

const temporaryDirectories: string[] = [];

function createTempDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-repository-scan-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

function emptyScanner(id: string, scan: RepositoryScanner['scan']): RepositoryScanner {
  return { id, version: 'test', supportedFileTypes: [], languages: [], scan };
}

describe('unified repository scanner', () => {
  it('normalizes findings to a stable, typed model without upgrading heuristic certainty', () => {
    const securityFinding: SecurityFinding = {
      id: 'legacy-id',
      scanner: 'secrets',
      ruleId: 'secret.github-token',
      title: 'Potential token',
      severity: 'high',
      confidence: 'heuristic',
      filePath: 'src/app.ts',
      lineNumber: 8,
      evidence: 'Potential credential value redacted',
      remediation: 'Rotate the value.'
    };
    const first = normalizeSecurityFinding(securityFinding, 'test.scanner', 'app');
    const second = normalizeSecurityFinding(securityFinding, 'test.scanner', 'app');

    expect(first).toMatchObject({
      scanner: 'test.scanner',
      ruleId: 'secret.github-token',
      category: 'secret',
      severity: 'high',
      confidence: 0.5,
      confidenceLevel: 'heuristic',
      filePath: 'src/app.ts',
      startLine: 8,
      endLine: 8
    });
    expect(first.id).toBe(second.id);
  });

  it('runs scanner failures in isolation and returns findings from other scanners', async () => {
    const root = createTempDirectory();
    const failing = emptyScanner('broken-scanner', () => { throw new Error('test failure'); });
    const succeeding = emptyScanner('healthy-scanner', () => ({
      findings: [{
        id: 'f-1', scanner: 'healthy-scanner', ruleId: 'rule', category: 'other',
        severity: 'low', confidence: 1, confidenceLevel: 'confirmed', evidence: 'safe evidence',
        description: 'Finding', impact: 'Impact', remediation: 'Fix', references: []
      }]
    }));

    const result = await scanRepository(root, { scanners: [failing, succeeding] });

    expect(result.findings.map(({ id }) => id)).toEqual(['f-1']);
    expect(result.diagnostics).toContainEqual(expect.objectContaining({
      code: 'scanner.broken-scanner.failed',
      severity: 'error'
    }));
    expect(result.partial).toBe(true);
  });

  it('keeps normalized finding IDs unique across scanners', async () => {
    const root = createTempDirectory();
    const finding = {
      id: 'same-id', scanner: 'shared', ruleId: 'rule', category: 'other' as const,
      severity: 'low' as const, confidence: 1, confidenceLevel: 'confirmed' as const,
      evidence: 'evidence', description: 'description', impact: 'impact',
      remediation: 'remediation', references: []
    };
    const result = await scanRepository(root, {
      scanners: [
        emptyScanner('first', () => ({ findings: [finding] })),
        emptyScanner('second', () => ({ findings: [finding] }))
      ]
    });

    expect(result.findings).toHaveLength(1);
    expect(result.diagnostics.map(({ code }) => code)).toContain('scanner.finding-id-duplicate');
  });

  it('stops before starting another scanner when cancellation is requested', async () => {
    const root = createTempDirectory();
    const controller = new AbortController();
    let secondRan = false;
    const first = emptyScanner('first', () => {
      controller.abort();
      return { findings: [] };
    });
    const second = emptyScanner('second', () => {
      secondRan = true;
      return { findings: [] };
    });

    const result = await scanRepository(root, { scanners: [first, second], signal: controller.signal });

    expect(secondRan).toBe(false);
    expect(result.cancelled).toBe(true);
    expect(result.diagnostics.map(({ code }) => code)).toContain('scan.cancelled');
  });

  it('returns a cancelled report when discovery progress requests cancellation', async () => {
    const root = createTempDirectory();
    fs.writeFileSync(path.join(root, 'app.ts'), 'export {};');
    const controller = new AbortController();
    const result = await scanRepository(root, {
      signal: controller.signal,
      onProgress: (progress) => {
        if (progress.phase === 'discover' && progress.filesFound) controller.abort();
      }
    });

    expect(result.cancelled).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.map(({ code }) => code)).toContain('scan.cancelled');
  });

  it('uses existing npm and PyPI engines for discovered manifests without requiring a network query for empty projects', async () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, 'python'), { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"root"}');
    fs.writeFileSync(path.join(root, 'package-lock.json'), '{"lockfileVersion":3,"packages":{"":{}}}');
    fs.writeFileSync(path.join(root, 'python', 'requirements.txt'), ' # empty');

    const result = await scanRepository(root);

    expect(result.projects.map(({ type }) => type)).toEqual(expect.arrayContaining([['npm'], ['python']]));
    expect(result.scanners.map(({ id }) => id)).toEqual(['veylix.local-security', 'veylix.dependencies']);
    expect(result.diagnostics.some(({ code }) => code === 'dependency.project-failed')).toBe(false);
  });

  it('finds local workflow risks only in discovered files without enabling Docker scanning', async () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
    fs.writeFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'name: ci\njobs:\n  build:\n    runs-on: ubuntu-latest\n');
    fs.writeFileSync(path.join(root, 'ignored.md'), `token=${`ghp_${'X'.repeat(30)}`}`);

    const result = await scanRepository(root);

    expect(result.findings.some(({ ruleId }) => ruleId === 'actions.permissions-unspecified')).toBe(true);
    expect(result.findings.some(({ ruleId }) => ruleId.startsWith('docker.'))).toBe(false);
    expect(result.findings.some(({ ruleId }) => ruleId === 'secret.github-token')).toBe(false);
    expect(JSON.stringify(result)).not.toContain(`ghp_${'X'.repeat(30)}`);
  });
});
