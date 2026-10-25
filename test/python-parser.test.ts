import { describe, it, expect } from 'vitest';
import { parseRequirementsTxt, parsePoetryLock, canonicalizePythonPackageName } from '../src/python-parser.js';
import fs from 'node:fs';
import path from 'node:path';

describe('Python Manifest & Lockfile Parsers', () => {
  const requirementsTxtStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/requirements.txt'), 'utf8');
  const poetryLockStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/poetry.lock'), 'utf8');
  const pyprojectTomlStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/pyproject.toml'), 'utf8');

  describe('canonicalizePythonPackageName (PEP 503)', () => {
    it('normalizes uppercase, underscores, and dots to lowercase dashes', () => {
      expect(canonicalizePythonPackageName('Flask')).toBe('flask');
      expect(canonicalizePythonPackageName('Django_Crispy_Forms')).toBe('django-crispy-forms');
      expect(canonicalizePythonPackageName('zope.interface')).toBe('zope-interface');
      expect(canonicalizePythonPackageName('My_Package.Name')).toBe('my-package-name');
    });
  });

  describe('parseRequirementsTxt', () => {
    it('correctly parses requirements.txt with pinned versions, comments, and extras', () => {
      const result = parseRequirementsTxt(requirementsTxtStr);

      expect(result.manifestType).toBe('requirements.txt');
      expect(result.packages.length).toBe(7);

      // requests==2.20.0
      const requests = result.packages.find((p) => p.name === 'requests');
      expect(requests).toBeDefined();
      expect(requests?.version).toBe('2.20.0');
      expect(requests?.isDirect).toBe(true);
      expect(requests?.ecosystem).toBe('pypi');

      // flask==1.0.2 with inline comment
      const flask = result.packages.find((p) => p.name === 'flask');
      expect(flask?.version).toBe('1.0.2');

      // urllib3==1.24.1 with environment marker
      const urllib3 = result.packages.find((p) => p.name === 'urllib3');
      expect(urllib3?.version).toBe('1.24.1');

      // Django_Crispy_Forms canonicalized to django-crispy-forms
      const djangoForms = result.packages.find((p) => p.name === 'django-crispy-forms');
      expect(djangoForms).toBeDefined();
      expect(djangoForms?.version).toBe('1.9.0');

      // celery[redis]==5.2.0 (extras stripped from name)
      const celery = result.packages.find((p) => p.name === 'celery');
      expect(celery?.version).toBe('5.2.0');

      // cryptography>=3.4.0,<4.0.0
      const crypto = result.packages.find((p) => p.name === 'cryptography');
      expect(crypto?.version).toBe('3.4.0');
      expect(crypto?.declaredConstraint).toBe('>=3.4.0,<4.0.0');

      // unpinned six
      const six = result.packages.find((p) => p.name === 'six');
      expect(six?.version).toBe('*');

      // Warnings generated for options and unpinned
      expect(result.warnings.length).toBeGreaterThanOrEqual(2);
      expect(result.warnings.some((w) => w.includes('requirements-base.txt'))).toBe(true);
    });

    it('throws on empty or missing requirements.txt', () => {
      expect(() => parseRequirementsTxt('')).toThrow('A requirements.txt file content is required.');
      expect(() => parseRequirementsTxt(null as any)).toThrow('A requirements.txt file content is required.');
    });

    it('enforces maximum file size limit', () => {
      expect(() => parseRequirementsTxt('requests==2.20.0', { maxFileSize: 5 })).toThrow(
        'exceeds maximum allowed size of 5 bytes'
      );
    });

    it('emits a warning for editable installs (-e) and does not treat them as packages', () => {
      const content = '-e .\nrequests==2.20.0\n--editable ./local-lib\n';
      const result = parseRequirementsTxt(content);
      // Only requests should be in packages — editable installs are skipped
      expect(result.packages.length).toBe(1);
      expect(result.packages[0]?.name).toBe('requests');
      // Both -e . and --editable ./local-lib should produce warnings
      expect(result.warnings.filter((w) => w.includes('Editable install skipped')).length).toBe(2);
    });

    it('emits a specific warning for short compatible release (~= 2-part) due to reduced OSV matching accuracy', () => {
      const content = 'requests~=2.20\nflask~=2.2.2\n';
      const result = parseRequirementsTxt(content);
      // requests~=2.20 has a 2-part version (shorter warning)
      const shortVersionWarning = result.warnings.find((w) =>
        w.includes('requests') && w.includes('may miss vulnerabilities')
      );
      expect(shortVersionWarning).toBeDefined();
      // flask~=2.2.2 has a 3-part version (regular range warning)
      const regularWarning = result.warnings.find((w) =>
        w.includes('flask') && w.includes('Analyzing base version')
      );
      expect(regularWarning).toBeDefined();
    });
  });

  describe('parsePoetryLock', () => {
    it('correctly parses poetry.lock and correlates with pyproject.toml direct dependencies', () => {
      const result = parsePoetryLock(poetryLockStr, pyprojectTomlStr);

      expect(result.manifestType).toBe('poetry.lock');
      expect(result.manifestName).toBe('python-sample-app');
      expect(result.manifestVersion).toBe('0.1.0');
      expect(result.packages.length).toBe(6);

      // Direct dependencies from pyproject.toml: requests, flask
      const requests = result.packages.find((p) => p.name === 'requests');
      expect(requests?.version).toBe('2.28.1');
      expect(requests?.isDirect).toBe(true);
      expect(requests?.isDev).toBe(false);

      const flask = result.packages.find((p) => p.name === 'flask');
      expect(flask?.isDirect).toBe(true);

      // Transitive dependency: certifi, charset-normalizer, werkzeug
      const certifi = result.packages.find((p) => p.name === 'certifi');
      expect(certifi?.version).toBe('2022.9.24');
      expect(certifi?.isDirect).toBe(false);

      const werkzeug = result.packages.find((p) => p.name === 'werkzeug');
      expect(werkzeug?.isDirect).toBe(false);

      // Dev dependency: pytest
      const pytest = result.packages.find((p) => p.name === 'pytest');
      expect(pytest?.version).toBe('7.2.0');
      expect(pytest?.isDev).toBe(true);
    });

    it('infers root direct dependencies when pyproject.toml is not provided', () => {
      const result = parsePoetryLock(poetryLockStr, null);

      expect(result.packages.length).toBe(6);

      // requests and flask are not children of any other package in lock -> inferred direct
      const requests = result.packages.find((p) => p.name === 'requests');
      expect(requests?.isDirect).toBe(true);

      const flask = result.packages.find((p) => p.name === 'flask');
      expect(flask?.isDirect).toBe(true);

      // certifi is in requests.dependencies -> transitive
      const certifi = result.packages.find((p) => p.name === 'certifi');
      expect(certifi?.isDirect).toBe(false);
    });

    it('throws on empty or missing poetry.lock', () => {
      expect(() => parsePoetryLock('')).toThrow('A poetry.lock file content is required.');
    });
  });
});
