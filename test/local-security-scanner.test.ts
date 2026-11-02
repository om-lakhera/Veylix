import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  inspectDockerImage,
  scanLocalSecurity,
  validateDeclarativeRules
} from '../src/scanners/local-security-scanner.js';

const temporaryDirectories: string[] = [];

function createTempDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-local-security-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('Local security scanners', () => {
  it('finds Dockerfile and GitHub Actions risks with source locations', () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
    fs.writeFileSync(path.join(root, 'Dockerfile'), [
      'FROM node:latest',
      'RUN curl https://example.invalid/install.sh | bash',
      'CMD ["node", "app.js"]'
    ].join('\n'));
    fs.writeFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), [
      'name: ci',
      'on: [push]',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          persist-credentials: false'
    ].join('\n'));

    const result = scanLocalSecurity(root);

    expect(result.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining([
      'docker.base-floating-tag',
      'docker.user-unspecified',
      'docker.healthcheck-missing',
      'docker.pipe-to-shell',
      'actions.permissions-unspecified',
      'actions.reference-not-sha-pinned'
    ]));
    expect(result.findings.find((finding) => finding.ruleId === 'docker.pipe-to-shell')).toMatchObject({
      filePath: 'Dockerfile',
      lineNumber: 2,
      confidence: 'confirmed'
    });
  });

  it('detects explicit Terraform and Kubernetes hardening issues without inferring graph data', () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, 'infra'));
    fs.writeFileSync(path.join(root, 'infra', 'main.tf'), [
      'resource "example" "db" {',
      '  publicly_accessible = true',
      '  storage_encrypted = false',
      '}'
    ].join('\n'));
    fs.writeFileSync(path.join(root, 'deployment.yaml'), [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'spec:',
      '  privileged: true',
      '  runAsNonRoot: false',
      '  hostNetwork: true',
      '  image: demo:latest'
    ].join('\n'));

    const result = scanLocalSecurity(root);

    expect(result.findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining([
      'terraform.public-access',
      'terraform.encryption-disabled',
      'kubernetes.privileged',
      'kubernetes.run-as-root',
      'kubernetes.host-network',
      'kubernetes.floating-image'
    ]));
    expect(result.findings.every((finding) => finding.confidence === 'confirmed' || finding.confidence === 'heuristic')).toBe(true);
  });

  it('applies license allowlists conservatively and marks missing metadata', () => {
    const root = createTempDirectory();
    fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/react': { name: 'react', version: '18.0.0', license: 'MIT' },
        'node_modules/example-and': { name: 'example-and', version: '1.0.0', license: 'MIT AND GPL-3.0-only' },
        'node_modules/example-unknown': { name: 'example-unknown', version: '1.0.0' }
      }
    }));

    const result = scanLocalSecurity(root, { allowedLicenses: ['MIT'] });

    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: 'license.not-allowlisted', packageName: 'example-and' }),
      expect.objectContaining({ ruleId: 'license.metadata-missing', packageName: 'example-unknown' })
    ]));
    expect(result.findings.some((finding) => finding.packageName === 'react' && finding.ruleId.startsWith('license.'))).toBe(false);
    expect(() => scanLocalSecurity(root, { allowedLicenses: ['MIT OR GPL-3.0-only'] })).toThrow('SPDX-style identifiers');
  });

  it('flags only near matches to a built-in package list as low-confidence typosquat heuristics', () => {
    const root = createTempDirectory();
    fs.writeFileSync(path.join(root, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/lodahs': { name: 'lodahs', version: '1.0.0' },
        'node_modules/ordinary-package': { name: 'ordinary-package', version: '1.0.0' }
      }
    }));

    const result = scanLocalSecurity(root);
    const finding = result.findings.find((item) => item.ruleId === 'package.name-near-known-package');

    expect(finding).toMatchObject({ packageName: 'lodahs', confidence: 'heuristic', severity: 'low' });
    expect(result.findings.some((item) => item.packageName === 'ordinary-package')).toBe(false);
  });

  it('accepts literal declarative rules and rejects executable-pattern configuration', () => {
    expect(validateDeclarativeRules([{
      id: 'no-debug',
      title: 'No debug marker',
      severity: 'medium',
      contains: 'debug=true',
      extensions: ['.env'],
      remediation: 'Disable debug mode.'
    }])).toHaveLength(1);
    expect(() => validateDeclarativeRules([{
      id: 'regex',
      title: 'Arbitrary regex',
      severity: 'high',
      pattern: '(a+)+$',
      remediation: 'Fix it.'
    }])).toThrow('literal contains');
  });

  it('does not expose Docker environment values and rejects unsafe image references', () => {
    const findings = [];
    inspectDockerImage('example:1.0', () => ({
      image: 'example:1.0',
      user: '',
      healthcheck: null,
      envNames: ['API_TOKEN=this-is-secret-value'],
      exposedPorts: []
    }), findings);

    expect(findings.map((finding) => finding.ruleId)).toEqual(expect.arrayContaining([
      'docker-image.root-user',
      'docker-image.healthcheck-missing',
      'docker-image.secret-env-name'
    ]));
    expect(JSON.stringify(findings)).not.toContain('this-is-secret-value');
    expect(() => inspectDockerImage('image;calc.exe', () => { throw new Error('must not inspect'); }, [])).toThrow('unsupported characters');
  });

  it('enforces byte limits and reports incomplete results explicitly', () => {
    const root = createTempDirectory();
    fs.writeFileSync(path.join(root, 'a.txt'), 'x'.repeat(12));
    fs.writeFileSync(path.join(root, 'b.txt'), 'safe');

    const result = scanLocalSecurity(root, { maxFileSizeBytes: 8, maxTotalBytes: 5 });

    expect(result.warnings).toContain('Skipped a.txt: file exceeds the configured per-file size limit.');
    expect(result.bytesScanned).toBeLessThanOrEqual(5);
  });
});
