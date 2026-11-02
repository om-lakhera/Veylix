import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discoverRepository } from '../src/scanners/repository-discovery.js';

const temporaryDirectories: string[] = [];

function createTempDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-repository-discovery-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('repository discovery', () => {
  it('finds nested projects, languages, dependency manifests, and scan targets', () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, 'packages', 'web', 'src'), { recursive: true });
    fs.mkdirSync(path.join(root, 'services', 'api'), { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), '{}');
    fs.writeFileSync(path.join(root, 'package-lock.json'), '{"lockfileVersion":3,"packages":{"":{}}}');
    fs.writeFileSync(path.join(root, 'packages', 'web', 'pyproject.toml'), '[tool.poetry]\nname="web"');
    fs.writeFileSync(path.join(root, 'packages', 'web', 'poetry.lock'), '[[package]]\nname = "safe"\nversion = "1.0.0"');
    fs.writeFileSync(path.join(root, 'packages', 'web', 'src', 'main.ts'), 'export {};');
    fs.writeFileSync(path.join(root, 'services', 'api', 'go.mod'), 'module example.invalid/api\n\ngo 1.22');
    fs.writeFileSync(path.join(root, 'services', 'api', 'main.go'), 'package main');
    fs.writeFileSync(path.join(root, 'infra.tf'), 'resource "x" "y" {}');

    const result = discoverRepository(root);

    expect(result.projects.map(({ root: projectRoot }) => projectRoot)).toEqual(['.', 'packages/web', 'services/api']);
    expect(result.projects.find((project) => project.root === '.')?.type).toContain('npm');
    expect(result.projects.find((project) => project.root === 'packages/web')).toMatchObject({
      type: ['python'],
      languages: ['TypeScript']
    });
    expect(result.languages).toEqual(['Go', 'TypeScript']);
    expect(result.scanTargets.map(({ path: target }) => target)).toEqual(expect.arrayContaining([
      'package-lock.json', 'package.json', 'packages/web/poetry.lock',
      'packages/web/pyproject.toml', 'packages/web/src/main.ts', 'services/api/main.go', 'infra.tf'
    ]));
  });

  it('respects root and nested gitignore patterns, including a supported negation', () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, 'ignored'), { recursive: true });
    fs.mkdirSync(path.join(root, 'nested', 'cache'), { recursive: true });
    fs.writeFileSync(path.join(root, '.gitignore'), 'ignored/*\n*.secret\nnested/cache/\n');
    fs.writeFileSync(path.join(root, 'ignored', '.gitignore'), '!keep.py\n');
    fs.writeFileSync(path.join(root, 'ignored', 'keep.py'), 'print("kept")');
    fs.writeFileSync(path.join(root, 'ignored', 'drop.py'), 'print("ignored")');
    fs.writeFileSync(path.join(root, 'nested', 'cache', 'module.ts'), 'export {};');
    fs.writeFileSync(path.join(root, 'token.secret'), 'not a target');
    fs.writeFileSync(path.join(root, 'src.py'), 'print("visible")');

    const result = discoverRepository(root);

    expect(result.scanTargets.map(({ path: target }) => target)).toContain('ignored/keep.py');
    expect(result.scanTargets.map(({ path: target }) => target)).not.toContain('ignored/drop.py');
    expect(result.scanTargets.map(({ path: target }) => target)).not.toContain('nested/cache/module.ts');
    expect(result.scanTargets.map(({ path: target }) => target)).not.toContain('token.secret');
  });

  it('applies configurable exclusions and skips generated directories by default', () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, 'node_modules', 'pkg'), { recursive: true });
    fs.mkdirSync(path.join(root, 'generated'), { recursive: true });
    fs.mkdirSync(path.join(root, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(root, 'node_modules', 'pkg', 'index.js'), 'module.exports = 1;');
    fs.writeFileSync(path.join(root, 'generated', 'bundle.js'), 'bundle();');
    fs.writeFileSync(path.join(root, 'app.js'), 'run();');
    fs.writeFileSync(path.join(root, 'root.py'), 'print("root")');
    fs.writeFileSync(path.join(root, 'nested', 'root.py'), 'print("nested")');

    const result = discoverRepository(root, { exclude: ['generated/**', '/root.py'] });

    expect(result.scanTargets.map(({ path: target }) => target)).toEqual(['app.js', 'nested/root.py']);
  });

  it('does not follow symbolic links and rejects a symlink scan root', () => {
    const root = createTempDirectory();
    const outside = createTempDirectory();
    fs.writeFileSync(path.join(outside, 'outside.py'), 'print("outside")');
    const linkPath = path.join(root, 'linked.py');
    try {
      fs.symlinkSync(path.join(outside, 'outside.py'), linkPath, 'file');
    } catch {
      return;
    }
    expect(discoverRepository(root).scanTargets).toEqual([]);
    expect(() => discoverRepository(linkPath)).toThrow('regular directory');
  });

  it('enforces depth, file, file-size, and total-byte limits with diagnostics', () => {
    const root = createTempDirectory();
    fs.mkdirSync(path.join(root, 'deep', 'deeper'), { recursive: true });
    fs.writeFileSync(path.join(root, 'large.py'), 'x'.repeat(12));
    fs.writeFileSync(path.join(root, 'small.py'), 'x');
    fs.writeFileSync(path.join(root, 'other.js'), 'x');
    fs.writeFileSync(path.join(root, 'deep', 'deeper', 'nested.py'), 'x');

    const limited = discoverRepository(root, {
      maxDepth: 1,
      maxFiles: 1,
      maxFileSizeBytes: 8,
      maxTotalBytes: 2
    });

    expect(limited.scanTargets.length).toBeLessThanOrEqual(1);
    expect(limited.diagnostics.map(({ code }) => code)).toContain('discovery.max-file-size');
    expect(limited.diagnostics.map(({ code }) => code)).toContain('discovery.max-depth');
    expect(discoverRepository(root, { maxFiles: 1 }).diagnostics.map(({ code }) => code)).toContain('discovery.max-files');
    expect(discoverRepository(root, { maxTotalBytes: 1 }).diagnostics.map(({ code }) => code)).toContain('discovery.max-total-bytes');
    expect(discoverRepository(root, { maxEntries: 1 }).diagnostics.map(({ code }) => code)).toContain('discovery.max-entries');
    expect(() => discoverRepository(root, { maxDepth: -1 })).toThrow('maxDepth must be an integer');
  });

  it('excludes unsupported file types from scan targets', () => {
    const root = createTempDirectory();
    fs.writeFileSync(path.join(root, 'notes.md'), 'not a scanner target');
    fs.writeFileSync(path.join(root, 'image.png'), Buffer.from([0, 1, 2]));
    expect(discoverRepository(root).scanTargets).toEqual([]);
  });

  it('rejects invalid exclusions and an already-cancelled discovery', () => {
    const root = createTempDirectory();
    const controller = new AbortController();
    controller.abort();
    expect(() => discoverRepository(root, { exclude: ['!reinclude'] })).toThrow('cannot start with');
    expect(() => discoverRepository(root, { signal: controller.signal })).toThrow('cancelled');
  });
});
