import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_SCAN_REQUEST_BYTES } from '../limits.js';
import { handleApiRequest } from './api-handler.js';

const MAX_CONCURRENT_SCANS = 4;
let activeScanRequests = 0;
const staticRoot = resolve(fileURLToPath(new URL('../../dist/', import.meta.url)));
const staticRootPrefix = `${staticRoot}${sep}`;
const contentTypes: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.woff2': 'font/woff2'
};
const spaRoutes = new Set([
  '/',
  '/new-scan',
  '/scans',
  '/dependencies',
  '/advisories',
  '/settings',
  '/about',
  '/privacy',
  '/terms',
  '/cookies',
  '/support'
]);

const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.osv.dev https://api.deps.dev; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
};

const SCAN_RATE_LIMIT_WINDOW_MS = 60_000;
const SCAN_RATE_LIMIT_MAX_REQUESTS = 20;
const scanRateLimitStore = new Map<string, { count: number; windowStart: number }>();

export function resetScanRateLimitState(): void {
  scanRateLimitStore.clear();
}

export function getClientIp(request: import('node:http').IncomingMessage): string {
  const trustProxyHeaders = ['1', 'true', 'yes', 'on'].includes(
    process.env.TRUST_PROXY_HEADERS?.trim().toLowerCase() ?? ''
  );
  const forwarded = request.headers['x-forwarded-for'];
  if (trustProxyHeaders && typeof forwarded === 'string' && forwarded.trim()) {
    const firstForwarded = forwarded.split(',')[0]?.trim();
    if (firstForwarded) return firstForwarded;
  }
  return request.socket?.remoteAddress ?? 'unknown';
}

export function evaluateScanRateLimit(
  request: import('node:http').IncomingMessage,
  pathname: string
): { allowed: boolean; retryAfterMs: number } {
  if (request.method !== 'POST') {
    return { allowed: true, retryAfterMs: 0 };
  }
  const isScanPath = pathname === '/api/scan' || pathname === '/api/scan/' ||
    pathname === '/api/scan-github' || pathname === '/api/scan-github/';
  if (!isScanPath) {
    return { allowed: true, retryAfterMs: 0 };
  }

  const clientKey = getClientIp(request);
  const now = Date.now();
  const existing = scanRateLimitStore.get(clientKey);
  if (!existing || now - existing.windowStart > SCAN_RATE_LIMIT_WINDOW_MS) {
    scanRateLimitStore.set(clientKey, { count: 1, windowStart: now });
    return { allowed: true, retryAfterMs: 0 };
  }

  if (existing.count >= SCAN_RATE_LIMIT_MAX_REQUESTS) {
    const retryAfterMs = Math.max(1000, SCAN_RATE_LIMIT_WINDOW_MS - (now - existing.windowStart));
    return { allowed: false, retryAfterMs };
  }

  existing.count += 1;
  return { allowed: true, retryAfterMs: 0 };
}

function sendJson(response: import('node:http').ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    ...securityHeaders,
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8'
  });
  response.end(JSON.stringify(body));
}

function isMissingPath(error: unknown): boolean {
  return Boolean(
    error &&
    typeof error === 'object' &&
    'code' in error &&
    (error.code === 'ENOENT' || error.code === 'ENOTDIR')
  );
}

async function statIfExists(path: string): Promise<Awaited<ReturnType<typeof stat>> | undefined> {
  try {
    return await stat(path);
  } catch (error) {
    if (isMissingPath(error)) return undefined;
    throw error;
  }
}

async function handleApi(
  request: import('node:http').IncomingMessage,
  response: import('node:http').ServerResponse,
  pathname: string
): Promise<void> {
  if (
    request.method === 'POST' &&
    (pathname === '/api/scan' || pathname === '/api/scan/' ||
      pathname === '/api/scan-github' || pathname === '/api/scan-github/')
  ) {
    const contentType = request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
    if (contentType !== 'application/json') {
      request.resume();
      sendJson(response, 415, { success: false, error: 'Content-Type must be application/json.' });
      return;
    }
  }

  if (request.method === 'POST' && request.headers['content-length']) {
    const contentLength = Number(request.headers['content-length']);
    if (Number.isFinite(contentLength) && contentLength > MAX_SCAN_REQUEST_BYTES) {
      request.resume();
      sendJson(response, 413, { success: false, error: 'Serialized scan request exceeds the 21 MiB limit.' });
      return;
    }
  }

  let bodyText: string | undefined;
  if (request.method === 'POST') {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let tooLarge = false;
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buffer.byteLength;
      if (totalBytes > MAX_SCAN_REQUEST_BYTES) {
        tooLarge = true;
        chunks.length = 0;
      } else if (!tooLarge) {
        chunks.push(buffer);
      }
    }
    if (tooLarge) {
      sendJson(response, 413, { success: false, error: 'Serialized scan request exceeds the 21 MiB limit.' });
      return;
    }
    bodyText = Buffer.concat(chunks, totalBytes).toString('utf8');
  }

  const result = await handleApiRequest(request.method ?? 'GET', pathname, bodyText);
  response.writeHead(result.status, { ...securityHeaders, ...result.headers });
  response.end(result.body);
}

async function handleStatic(
  request: import('node:http').IncomingMessage,
  response: import('node:http').ServerResponse,
  pathname: string
): Promise<void> {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { ...securityHeaders, Allow: 'GET, HEAD' });
    response.end();
    return;
  }

  let requestedPath: string;
  try {
    requestedPath = decodeURIComponent(pathname);
  } catch {
    response.writeHead(400, securityHeaders);
    response.end('Bad request');
    return;
  }
  if (requestedPath.includes('\0')) {
    response.writeHead(400, securityHeaders);
    response.end('Bad request');
    return;
  }

  const candidate = resolve(staticRoot, `.${requestedPath}`);
  if (candidate !== staticRoot && !candidate.startsWith(staticRootPrefix)) {
    response.writeHead(403, securityHeaders);
    response.end('Forbidden');
    return;
  }

  let filePath = candidate;
  let fileStat = await statIfExists(filePath);
  if (!fileStat?.isFile()) {
    if (requestedPath.startsWith('/assets/') || extname(requestedPath)) {
      response.writeHead(404, securityHeaders);
      response.end('Not found');
      return;
    }
    filePath = resolve(staticRoot, 'index.html');
    fileStat = await statIfExists(filePath);
    if (!fileStat) {
      sendJson(response, 503, { error: 'Production web assets are unavailable. Run npm run build first.' });
      return;
    }
  }

  const headers = {
    ...securityHeaders,
    'Content-Type': contentTypes[extname(filePath).toLowerCase()] ?? 'application/octet-stream',
    'Content-Length': String(fileStat.size),
    'Cache-Control': filePath.includes(`${sep}assets${sep}`)
      ? 'public, max-age=31536000, immutable'
      : filePath.endsWith(`${sep}index.html`) ? 'no-cache' : 'public, max-age=3600'
  };
  const isSpaRoute = spaRoutes.has(requestedPath) ||
    /^\/scans\/[A-Za-z0-9_-]{1,100}$/.test(requestedPath);
  response.writeHead(filePath.endsWith(`${sep}index.html`) && !isSpaRoute ? 404 : 200, headers);
  if (request.method === 'HEAD') {
    response.end();
    return;
  }
  response.end(await readFile(filePath));
}

const parsedPort = process.env.PORT === undefined ? 3000 : Number(process.env.PORT);
if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}
const host = process.env.HOST?.trim() || '127.0.0.1';

const server = createServer((request, response) => {
  void (async () => {
    try {
      const url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);
      if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
        const isScanPost = request.method === 'POST' &&
          (url.pathname === '/api/scan' || url.pathname === '/api/scan/' ||
            url.pathname === '/api/scan-github' || url.pathname === '/api/scan-github/');
        if (isScanPost && activeScanRequests >= MAX_CONCURRENT_SCANS) {
          request.resume();
          response.writeHead(503, {
            ...securityHeaders,
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json; charset=utf-8',
            'Retry-After': '10'
          });
          response.end(JSON.stringify({
            success: false,
            error: 'Scan capacity is temporarily full. Please retry shortly.'
          }));
          return;
        }
        if (isScanPost) activeScanRequests++;
        try {
          await handleApi(request, response, url.pathname);
        } finally {
          if (isScanPost) activeScanRequests--;
        }
      } else {
        await handleStatic(request, response, url.pathname);
      }
    } catch (error) {
      console.error('Production request failed:', error);
      if (!response.headersSent) {
        sendJson(response, 500, { success: false, error: 'The request could not be completed.' });
      } else {
        response.destroy();
      }
    }
  })();
});

server.headersTimeout = 10_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 100;

server.listen(parsedPort, host, () => {
  console.info(`Veylix production server listening on http://${host}:${parsedPort}`);
});
