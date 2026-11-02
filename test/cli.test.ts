import { describe, it, expect } from 'vitest';
import { evaluateThreshold, parseCliArgs, parseThreshold, renderStartupBanner, runCli, VEYLIX_VERSION } from '../src/cli.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

describe('CLI utilities', () => {
  it('parses supported threshold values', () => {
    expect(parseThreshold('critical')).toBe('critical');
    expect(parseThreshold('HIGH')).toBe('high');
    expect(parseThreshold('medium')).toBe('moderate');
    expect(parseThreshold('none')).toBe('none');
  });

  it('rejects unsupported threshold values', () => {
    expect(() => parseThreshold('urgent')).toThrow('Unsupported threshold');
  });

  it('accepts standards-based and human-readable report formats', () => {
    for (const format of ['sarif', 'cyclonedx', 'spdx', 'markdown', 'html']) {
      expect(parseCliArgs(['scan', '--file', 'package-lock.json', '--format', format]).format).toBe(format);
    }
    expect(parseCliArgs(['scan', '--file', 'package-lock.json', '--format', 'pdf']).error)
      .toContain('Unsupported output format');
  });

  it('parses command-line arguments and accepts scan aliases', () => {
    expect(parseCliArgs(['scan', '--file', './package-lock.json', '--ecosystem', 'npm', '--threshold', 'high', '--format', 'json'])).toEqual({
      help: false,
      input: './package-lock.json',
      ecosystem: 'npm',
      threshold: 'high',
      format: 'json',
      fetchExploitIntelligence: false
    });

    expect(parseCliArgs(['--exploit-intel', 'scan', '--file', './package-lock.json'])).toMatchObject({
      help: false,
      input: './package-lock.json',
      fetchExploitIntelligence: true
    });
    expect(parseCliArgs(['--help'])).toEqual({
      help: true,
      threshold: 'none',
      format: 'text',
      fetchExploitIntelligence: false
    });
  });

  it('requires an explicit cache file for offline scans and validates cache age', () => {
    expect(parseCliArgs(['scan', '--file', 'package-lock.json', '--offline']).error)
      .toContain('--offline requires --cache-file');
    expect(parseCliArgs(['scan', '--file', 'package-lock.json', '--cache-file', 'cache.json', '--offline']))
      .toMatchObject({ cacheFile: 'cache.json', offline: true });
    expect(parseCliArgs(['scan', '--file', 'package-lock.json', '--cache-file', 'cache.json', '--cache-max-age-days', '3651']).error)
      .toContain('between 0 and 3650');
  });

  it('evaluates vulnerability thresholds using server-side severity definitions', () => {
    const report = {
      summary: {
        severityCounts: {
          critical: 1,
          high: 3,
          moderate: 0,
          low: 2,
          unknown: 1
        }
      }
    } as any;

    expect(evaluateThreshold(report, 'critical')).toEqual({
      exceeded: true,
      matchedSeverities: ['critical']
    });
    expect(evaluateThreshold(report, 'high')).toEqual({
      exceeded: true,
      matchedSeverities: ['critical', 'high']
    });
    expect(evaluateThreshold(report, 'low')).toEqual({
      exceeded: true,
      matchedSeverities: ['critical', 'high', 'low', 'unknown']
    });
    expect(evaluateThreshold(report, 'none')).toEqual({
      exceeded: false,
      matchedSeverities: []
    });
  });

  it('prints help and exits without error', async () => {
    let output = '';
    const exitCode = await runCli(['--help'], {
      stdout: { write: (chunk: string) => { output += chunk; } },
      stderr: { write: () => undefined }
    });

    expect(exitCode).toBe(0);
    expect(output).toContain('Veylix CLI');
  });

  it('prints a compact branded banner without arguments and supports version-only output', async () => {
    const banner = renderStartupBanner({ width: 110, supportsAnsi: false });
    expect(banner).toContain('Veylix');
    expect(banner).toContain('Commands:');

    let output = '';
    const emptyOutput = await runCli([], {
      stdout: { write: (chunk: string) => { output += chunk; } },
      stderr: { write: () => undefined }
    });

    expect(emptyOutput).toBe(0);
    expect(output).toContain('Veylix');

    output = '';
    const versionExitCode = await runCli(['--version'], {
      stdout: { write: (chunk: string) => { output += chunk; } },
      stderr: { write: () => undefined }
    });

    expect(versionExitCode).toBe(0);
    expect(output.trim()).toBe(VEYLIX_VERSION);
  });

  it('infers ecosystem from a supplied project directory without guessing from its path', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-cli-'));
    try {
      fs.writeFileSync(path.join(directory, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: { '': {} }
      }));
      let output = '';
      let error = '';
      const exitCode = await runCli(['--file', directory], {
        stdout: { write: (chunk: string) => { output += chunk; } },
        stderr: { write: (chunk: string) => { error += chunk; } }
      });

      expect(exitCode).toBe(0);
      expect(output).toContain('Ecosystem: npm');
      expect(error).toBe('');
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects oversized CLI manifests before reading or scanning them', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-cli-large-'));
    try {
      const lockPath = path.join(directory, 'package-lock.json');
      fs.writeFileSync(lockPath, Buffer.alloc(5 * 1024 * 1024 + 1));
      let error = '';
      const exitCode = await runCli(['--file', lockPath], {
        stdout: { write: () => undefined },
        stderr: { write: (chunk: string) => { error += chunk; } }
      });

      expect(exitCode).toBe(2);
      expect(error).toContain('exceeds the maximum allowed size of 5 MiB');
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('runs the secrets command with redacted evidence and deterministic exit status', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-cli-secrets-'));
    try {
      const token = `ghp_${'C'.repeat(30)}`;
      fs.writeFileSync(path.join(directory, '.env'), `GITHUB_TOKEN=${token}\n`);
      let output = '';
      let error = '';
      const exitCode = await runCli(['secrets', '--path', directory, '--format', 'json'], {
        stdout: { write: (chunk: string) => { output += chunk; } },
        stderr: { write: (chunk: string) => { error += chunk; } }
      });

      expect(exitCode).toBe(1);
      expect(output).toContain('secret.github-token');
      expect(output).toContain('Potential credential value redacted');
      expect(output).not.toContain(token);
      expect(error).toBe('');
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('runs the local security command and emits a machine-readable report', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-cli-security-'));
    try {
      fs.writeFileSync(path.join(directory, 'Dockerfile'), 'FROM node:latest\n');
      let output = '';
      let error = '';
      const exitCode = await runCli(['security', 'scan', '--path', directory, '--format', 'json', '--threshold', 'medium'], {
        stdout: { write: (chunk: string) => { output += chunk; } },
        stderr: { write: (chunk: string) => { error += chunk; } }
      });

      expect(exitCode).toBe(1);
      expect(JSON.parse(output)).toMatchObject({
        target: path.basename(directory),
        exceeded: true,
        findings: expect.arrayContaining([expect.objectContaining({ ruleId: 'docker.base-floating-tag' })])
      });
      expect(error).toBe('');
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('runs a full local repository scan and reports discovered projects as JSON', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-cli-repository-'));
    try {
      fs.writeFileSync(path.join(directory, 'package.json'), '{}');
      fs.writeFileSync(path.join(directory, 'package-lock.json'), '{"lockfileVersion":3,"packages":{"":{}}}');
      fs.mkdirSync(path.join(directory, '.github', 'workflows'), { recursive: true });
      fs.writeFileSync(path.join(directory, '.github', 'workflows', 'ci.yml'), 'name: ci\njobs:\n  build:\n    runs-on: ubuntu-latest\n');
      let output = '';
      let error = '';

      const exitCode = await runCli(['repository', 'scan', '--path', directory, '--format', 'json'], {
        stdout: { write: (chunk: string) => { output += chunk; } },
        stderr: { write: (chunk: string) => { error += chunk; } }
      });

      expect(exitCode).toBe(0);
      expect(JSON.parse(output)).toMatchObject({
        projects: [expect.objectContaining({ type: ['npm'] })],
        scanTargets: expect.arrayContaining([expect.objectContaining({ path: '.github/workflows/ci.yml' })]),
        findings: expect.arrayContaining([expect.objectContaining({ ruleId: 'actions.permissions-unspecified' })])
      });
      expect(error).toBe('');
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it('returns a clear CLI error for invalid repository scan limits', async () => {
    let error = '';
    const exitCode = await runCli(['repository', 'scan', '--max-files', '0'], {
      stdout: { write: () => undefined },
      stderr: { write: (chunk: string) => { error += chunk; } }
    });

    expect(exitCode).toBe(2);
    expect(error).toContain('--max-files must be an integer');
  });
});
