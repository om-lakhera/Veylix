import * as fs from 'node:fs';
import * as path from 'node:path';

const MAX_CACHE_FILE_BYTES = 32 * 1024 * 1024;
const MAX_CACHE_ENTRIES = 5_000;
const MAX_CACHED_RESPONSE_BYTES = 4 * 1024 * 1024;
const CACHE_VERSION = 1;

interface OsvCacheEntry {
  savedAt: string;
  response: string;
}

interface OsvCacheFile {
  version: number;
  entries: Record<string, OsvCacheEntry>;
}

function cacheKey(url: string, body: string): string {
  let canonicalBody: string;
  try {
    canonicalBody = JSON.stringify(JSON.parse(body));
  } catch {
    throw new Error('OSV cache received an invalid query body.');
  }
  return `${url}\n${canonicalBody}`;
}

function loadEntries(cachePath: string): Map<string, OsvCacheEntry> {
  if (!fs.existsSync(cachePath)) return new Map();
  const stat = fs.lstatSync(cachePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_CACHE_FILE_BYTES) {
    throw new Error('OSV cache must be a regular file no larger than 32 MiB.');
  }
  let parsed: OsvCacheFile;
  try {
    parsed = JSON.parse(fs.readFileSync(cachePath, 'utf8')) as OsvCacheFile;
  } catch {
    throw new Error('OSV cache file contains invalid JSON.');
  }
  if (!parsed || parsed.version !== CACHE_VERSION || !parsed.entries || typeof parsed.entries !== 'object' || Array.isArray(parsed.entries)) {
    throw new Error('OSV cache file has an unsupported or invalid format.');
  }
  const entries = new Map<string, OsvCacheEntry>();
  for (const [key, value] of Object.entries(parsed.entries)) {
    if (
      key.length > 1_000_000 ||
      !value ||
      typeof value.savedAt !== 'string' ||
      !Number.isFinite(Date.parse(value.savedAt)) ||
      typeof value.response !== 'string' ||
      Buffer.byteLength(value.response, 'utf8') > MAX_CACHED_RESPONSE_BYTES
    ) {
      throw new Error('OSV cache contains a malformed or oversized entry.');
    }
    let response: unknown;
    try {
      response = JSON.parse(value.response);
    } catch {
      throw new Error('OSV cache contains a malformed response entry.');
    }
    if (!response || typeof response !== 'object' || !Array.isArray((response as { results?: unknown }).results)) {
      throw new Error('OSV cache entry does not contain OSV query results.');
    }
    entries.set(key, value);
  }
  return entries;
}

function writeEntries(cachePath: string, entries: Map<string, OsvCacheEntry>): void {
  const ordered = Array.from(entries.entries()).sort((left, right) =>
    Date.parse(right[1].savedAt) - Date.parse(left[1].savedAt)
  ).slice(0, MAX_CACHE_ENTRIES);
  const data = JSON.stringify({
    version: CACHE_VERSION,
    entries: Object.fromEntries(ordered)
  } satisfies OsvCacheFile);
  if (Buffer.byteLength(data, 'utf8') > MAX_CACHE_FILE_BYTES) {
    throw new Error('OSV cache reached its 32 MiB size limit; remove old entries or choose a new cache file.');
  }
  const temporaryPath = `${cachePath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temporaryPath, data, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(temporaryPath, cachePath);
  } finally {
    if (fs.existsSync(temporaryPath)) fs.unlinkSync(temporaryPath);
  }
}

export interface OsvCacheOptions {
  cacheFile: string;
  offline?: boolean;
  maxAgeDays?: number;
  fetchFn?: typeof fetch;
  now?: () => Date;
}

export function createOsvCachedFetch(options: OsvCacheOptions): typeof fetch {
  const cachePath = path.resolve(options.cacheFile);
  const offline = Boolean(options.offline);
  const maxAgeDays = options.maxAgeDays ?? 30;
  if (!Number.isFinite(maxAgeDays) || maxAgeDays < 0 || maxAgeDays > 3650) {
    throw new Error('OSV cache maximum age must be between 0 and 3650 days.');
  }
  if (fs.existsSync(cachePath)) {
    const stat = fs.lstatSync(cachePath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error('OSV cache path must refer to a regular file, not a symbolic link or directory.');
    }
  } else if (offline) {
    throw new Error(`Offline OSV cache file does not exist: ${cachePath}`);
  }
  const entries = loadEntries(cachePath);
  const networkFetch = options.fetchFn ?? fetch.bind(globalThis);

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : undefined;
    const url = input instanceof Request
      ? input.url
      : input instanceof URL
        ? input.href
        : input;
    const method = (init?.method ?? request?.method ?? 'GET').toUpperCase();
    const body = typeof init?.body === 'string'
      ? init.body
      : request && method === 'POST'
        ? await request.clone().text()
        : '';
    if (method !== 'POST' || !String(url).includes('/v1/querybatch')) {
      if (offline) throw new Error('Offline OSV cache only supports cached advisory query-batch requests.');
      return networkFetch(input, init);
    }

    const key = cacheKey(String(url), body);
    if (offline) {
      const entry = entries.get(key);
      if (!entry) throw new Error('No matching OSV query is present in the offline cache.');
      const ageMs = (options.now?.() ?? new Date()).getTime() - Date.parse(entry.savedAt);
      if (ageMs < 0 || ageMs > maxAgeDays * 24 * 60 * 60 * 1000) {
        throw new Error(`Cached OSV query is older than the configured maximum of ${maxAgeDays} days.`);
      }
      return new Response(entry.response, {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'x-veylix-cache-age-seconds': String(Math.floor(ageMs / 1000))
        }
      });
    }

    const response = await networkFetch(input, init);
    if (!response.ok) return response;
    const payload = await response.clone().text();
    if (Buffer.byteLength(payload, 'utf8') > MAX_CACHED_RESPONSE_BYTES) {
      return response;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      return response;
    }
    if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as { results?: unknown }).results)) {
      return response;
    }
    entries.set(key, { savedAt: (options.now?.() ?? new Date()).toISOString(), response: payload });
    writeEntries(cachePath, entries);
    return response;
  };
}
