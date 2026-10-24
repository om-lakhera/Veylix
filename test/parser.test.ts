import { describe, it, expect } from 'vitest';
import { parseNpmManifests } from '../src/parser.js';
import fs from 'node:fs';
import path from 'node:path';

describe('npm Manifest & Lockfile Parser', () => {
  const packageJsonStr = fs.readFileSync(path.resolve(__dirname, 'fixtures/package.json'), 'utf8');
  const packageLockV3Str = fs.readFileSync(path.resolve(__dirname, 'fixtures/package-lock-v3.json'), 'utf8');
  const packageLockV1Str = fs.readFileSync(path.resolve(__dirname, 'fixtures/package-lock-v1.json'), 'utf8');

  it('correctly extracts packages, versions, and direct/dev flags from v3 lockfile', () => {
    const result = parseNpmManifests(packageJsonStr, packageLockV3Str);

    expect(result.lockfileVersion).toBe(3);
    expect(result.manifestName).toBe('sample-project');
    expect(result.packages.length).toBe(4);

    // Verify packages
    const lodashV15 = result.packages.find((p) => p.name === 'lodash' && p.version === '4.17.15');
    expect(lodashV15).toBeDefined();
    expect(lodashV15?.isDirect).toBe(true);
    expect(lodashV15?.isDev).toBe(false);

    const safePkg = result.packages.find((p) => p.name === '@scoped/safe-pkg');
    expect(safePkg).toBeDefined();
    expect(safePkg?.version).toBe('2.1.0');
    expect(safePkg?.isDirect).toBe(true);

    // Multiple versions of one package: lodash 4.17.15 and 4.17.21
    const lodashV21 = result.packages.find((p) => p.name === 'lodash' && p.version === '4.17.21');
    expect(lodashV21).toBeDefined();
    expect(lodashV21?.isDirect).toBe(false);
    expect(lodashV21?.dependencyPaths).toContain('@scoped/safe-pkg -> lodash');

    // Scoped package name correctly extracted
    expect(safePkg?.name).toBe('@scoped/safe-pkg');

    // Dev package
    const minimist = result.packages.find((p) => p.name === 'minimist');
    expect(minimist).toBeDefined();
    expect(minimist?.isDev).toBe(true);
  });

  it('correctly parses v1 lockfile with nested dependency structures', () => {
    const result = parseNpmManifests(null, packageLockV1Str);

    expect(result.lockfileVersion).toBe(1);
    expect(result.packages.length).toBe(4); // lodash@4.17.15, minimist@1.2.0, nested-parent@1.0.0, lodash@4.17.21

    const nestedLodash = result.packages.find((p) => p.name === 'lodash' && p.version === '4.17.21');
    expect(nestedLodash).toBeDefined();
    expect(nestedLodash?.dependencyPaths[0]).toContain('nested-parent@1.0.0 -> lodash@4.17.21');
  });

  it('throws an error if package-lock.json is empty or missing', () => {
    expect(() => parseNpmManifests(packageJsonStr, '')).toThrow(
      'A package-lock.json file content is required'
    );
    expect(() => parseNpmManifests(packageJsonStr, null as any)).toThrow(
      'A package-lock.json file content is required'
    );
  });

  it('safely handles missing or empty package.json gracefully', () => {
    const result = parseNpmManifests('', packageLockV3Str);
    expect(result.packages.length).toBeGreaterThan(0);
    expect(result.warnings.length).toBe(0);
  });

  it('safely captures warning on malformed package.json without crashing', () => {
    const result = parseNpmManifests('not-valid-json{{{', packageLockV3Str);
    expect(result.warnings.length).toBe(1);
    expect(result.warnings[0]).toContain('Failed to parse package.json');
    expect(result.packages.length).toBeGreaterThan(0);
  });

  it('throws a descriptive error on malformed package-lock.json', () => {
    expect(() => parseNpmManifests(packageJsonStr, '{"lockfileVersion": 3, "broken: json')).toThrow(
      'Malformed package-lock.json'
    );
  });

  it('throws a descriptive error on unsupported lockfileVersion', () => {
    const unsupportedLock = JSON.stringify({ name: 'unsupported', lockfileVersion: 4 });
    expect(() => parseNpmManifests(packageJsonStr, unsupportedLock)).toThrow(
      'Unsupported package-lock.json version: 4. Veylix supports lockfileVersion 1, 2, and 3.'
    );
  });

  it('enforces maximum input file size safety limit', () => {
    const hugeFakeLock = JSON.stringify({ lockfileVersion: 3, packages: {} });
    expect(() =>
      parseNpmManifests(packageJsonStr, hugeFakeLock, { maxFileSize: 10 })
    ).toThrow('exceeds maximum allowed size of 10 bytes');
  });
});
