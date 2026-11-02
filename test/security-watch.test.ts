import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { watchLocalSecurity } from '../src/scanners/security-watch.js';

const temporaryDirectories: string[] = [];

function createTempDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-security-watch-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('Local security watch', () => {
  it('runs an initial scan and rescans after filesystem changes until stopped', async () => {
    const root = createTempDirectory();
    const dockerfile = path.join(root, 'Dockerfile');
    fs.writeFileSync(dockerfile, 'FROM node:20\n');
    let stop = (): void => undefined;

    await new Promise<void>((resolve, reject) => {
      let scans = 0;
      const timeout = setTimeout(() => reject(new Error('Watch did not rescan after a file change.')), 3_000);
      stop = watchLocalSecurity(root, { debounceMs: 50 }, () => {
        scans++;
        if (scans === 2) {
          clearTimeout(timeout);
          resolve();
        }
      }, reject);
      fs.writeFileSync(dockerfile, 'FROM node:latest\n');
    });

    stop();
    expect(stop).toBeTypeOf('function');
  });
});
