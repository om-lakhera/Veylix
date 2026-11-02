import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanForSecrets } from '../src/scanners/secret-scanner.js';

const temporaryDirectories: string[] = [];

function createTempDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-secrets-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('Local secret scanner', () => {
  it('detects supported credential patterns without including secret values in evidence', () => {
    const directory = createTempDirectory();
    const token = `ghp_${'A'.repeat(30)}`;
    const accessKey = `AKIA${'B'.repeat(16)}`;
    fs.writeFileSync(path.join(directory, '.env'), `GITHUB_TOKEN=${token}\nAWS_ACCESS_KEY_ID=${accessKey}\n`);
    fs.writeFileSync(path.join(directory, 'id_rsa'), '-----BEGIN RSA PRIVATE KEY-----\n');
    fs.writeFileSync(path.join(directory, 'config.txt'), 'api_key = "this-is-a-long-test-credential"\n');

    const result = scanForSecrets(directory);

    expect(result.filesScanned).toBe(3);
    expect(result.findings.map((finding) => finding.ruleId)).toEqual([
      'secret.github-token',
      'secret.aws-access-key',
      'secret.credential-assignment',
      'secret.private-key'
    ]);
    expect(result.findings.map((finding) => [finding.filePath, finding.lineNumber])).toEqual([
      ['.env', 1],
      ['.env', 2],
      ['config.txt', 1],
      ['id_rsa', 1]
    ]);
    const output = JSON.stringify(result);
    expect(output).not.toContain(token);
    expect(output).not.toContain(accessKey);
    expect(output).not.toContain('this-is-a-long-test-credential');
    expect(result.findings.every((finding) => finding.evidence === 'Potential credential value redacted')).toBe(true);
  });

  it('skips common generated and vendor directories and placeholder lines', () => {
    const directory = createTempDirectory();
    fs.mkdirSync(path.join(directory, 'node_modules'));
    fs.mkdirSync(path.join(directory, '.git'));
    fs.writeFileSync(path.join(directory, 'node_modules', 'copy.txt'), `ghp_${'A'.repeat(30)}`);
    fs.writeFileSync(path.join(directory, '.git', 'config'), `ghp_${'B'.repeat(30)}`);
    fs.writeFileSync(path.join(directory, 'sample.env'), 'API_KEY=replace-me-with-an-example-value\n');

    const result = scanForSecrets(directory);

    expect(result.findings).toEqual([]);
    expect(result.filesScanned).toBe(1);
  });

  it('enforces per-file, total-byte, and file-count limits with explicit warnings', () => {
    const directory = createTempDirectory();
    fs.writeFileSync(path.join(directory, 'a-large.txt'), 'x'.repeat(12));
    fs.writeFileSync(path.join(directory, 'b.txt'), 'safe');
    fs.writeFileSync(path.join(directory, 'c.txt'), 'safe');

    const perFile = scanForSecrets(directory, { maxFileSizeBytes: 8 });
    expect(perFile.warnings).toContain('Skipped a-large.txt: file exceeds the configured per-file size limit.');

    const totalBytes = scanForSecrets(directory, { maxFileSizeBytes: 8, maxTotalBytes: 5 });
    expect(totalBytes.warnings).toContain('Stopped scanning because the configured total byte limit was reached.');
    expect(totalBytes.bytesScanned).toBeLessThanOrEqual(5);

    const fileCount = scanForSecrets(directory, { maxFiles: 1, maxFileSizeBytes: 8 });
    expect(fileCount.warnings).toContain('Stopped scanning after reaching the configured limit of 1 files.');
  });

  it('rejects missing and symbolic-link targets without following the link', () => {
    const directory = createTempDirectory();
    expect(() => scanForSecrets(path.join(directory, 'missing'))).toThrow('does not exist');

    const file = path.join(directory, 'target.txt');
    const link = path.join(directory, 'link.txt');
    fs.writeFileSync(file, 'safe');
    try {
      fs.symlinkSync(file, link);
      expect(() => scanForSecrets(link)).toThrow('does not follow symbolic links');
    } catch (error) {
      if (error instanceof Error && !/EPERM|EACCES|operation not permitted/i.test(error.message)) throw error;
    }
  });
});
