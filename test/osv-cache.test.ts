import { afterEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createOsvCachedFetch } from '../src/osv-cache.js';

const temporaryDirectories: string[] = [];

function createTempDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veylix-osv-cache-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('Local OSV query cache', () => {
  it('stores successful online responses and serves them in explicit offline mode with age metadata', async () => {
    const directory = createTempDirectory();
    const cacheFile = path.join(directory, 'osv-cache.json');
    const body = JSON.stringify({ queries: [{ package: { name: 'left-pad', ecosystem: 'npm' }, version: '1.0.0' }] });
    const network = vi.fn(async () => new Response(JSON.stringify({ results: [{ vulns: [{ id: 'OSV-1' }] }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    }));
    const online = createOsvCachedFetch({
      cacheFile,
      fetchFn: network as typeof fetch,
      now: () => new Date('2025-01-01T00:00:00Z')
    });

    await online('https://api.osv.dev/v1/querybatch', { method: 'POST', body });
    expect(fs.existsSync(cacheFile)).toBe(true);

    const offline = createOsvCachedFetch({
      cacheFile,
      offline: true,
      now: () => new Date('2025-01-01T02:00:00Z')
    });
    const response = await offline('https://api.osv.dev/v1/querybatch', { method: 'POST', body });
    expect(response.headers.get('x-veylix-cache-age-seconds')).toBe('7200');
    expect(await response.json()).toEqual({ results: [{ vulns: [{ id: 'OSV-1' }] }] });
    expect(network).toHaveBeenCalledTimes(1);
  });

  it('fails clearly for missing queries and stale entries in offline mode', async () => {
    const directory = createTempDirectory();
    const cacheFile = path.join(directory, 'osv-cache.json');
    const online = createOsvCachedFetch({
      cacheFile,
      fetchFn: async () => new Response(JSON.stringify({ results: [] }), { status: 200 }),
      now: () => new Date('2025-01-01T00:00:00Z')
    });
    await online('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{"queries":[]}' });
    const offline = createOsvCachedFetch({
      cacheFile,
      offline: true,
      maxAgeDays: 1,
      now: () => new Date('2025-01-03T00:00:00Z')
    });
    await expect(offline('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{"queries":[]}' }))
      .rejects.toThrow('older than the configured maximum');
    await expect(offline('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{"queries":[1]}' }))
      .rejects.toThrow('No matching OSV query');
  });

  it('rejects malformed, oversized, and symlink cache files', () => {
    const directory = createTempDirectory();
    const malformedPath = path.join(directory, 'bad.json');
    fs.writeFileSync(malformedPath, '{invalid');
    expect(() => createOsvCachedFetch({ cacheFile: malformedPath, offline: true })).toThrow('invalid JSON');
    expect(() => createOsvCachedFetch({ cacheFile: malformedPath })).toThrow('invalid JSON');

    const target = path.join(directory, 'target.json');
    const link = path.join(directory, 'link.json');
    fs.writeFileSync(target, '{}');
    try {
      fs.symlinkSync(target, link);
      expect(() => createOsvCachedFetch({ cacheFile: link })).toThrow('symbolic link');
    } catch (error) {
      if (error instanceof Error && !/EPERM|EACCES|operation not permitted/i.test(error.message)) throw error;
    }
  });
});
