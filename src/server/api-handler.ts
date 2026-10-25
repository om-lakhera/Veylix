/**
 * Universal API Request Handler for Veylix
 * 
 * Works across Vite dev server, Node http, and Cloudflare Workers (Web standard Request/Response).
 */

import { ScanService, FileScanPayload, GitHubScanPayload } from './scan-service.js';
import { MAX_SCAN_REQUEST_BYTES } from '../limits.js';

const scanService = new ScanService();

export async function handleApiRequest(
  method: string,
  pathname: string,
  bodyText?: string,
  service: ScanService = scanService
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  };

  // Health endpoint
  if (method === 'GET' && (pathname === '/api/health' || pathname === '/api/health/')) {
    return {
      status: 200,
      headers,
      body: JSON.stringify({
        status: 'ok',
        version: '0.1.0',
        timestamp: new Date().toISOString(),
        engine: 'Veylix TypeScript Engine',
        supportedEcosystems: ['npm', 'pypi']
      })
    };
  }

  const isFileScan = pathname === '/api/scan' || pathname === '/api/scan/';
  const isGitHubScan = pathname === '/api/scan-github' || pathname === '/api/scan-github/';
  if (!isFileScan && !isGitHubScan) {
    return {
      status: 404,
      headers,
      body: JSON.stringify({ success: false, error: 'API endpoint not found.' })
    };
  }

  if (method !== 'POST') {
    return {
      status: 405,
      headers: { ...headers, Allow: 'POST' },
      body: JSON.stringify({ success: false, error: 'Method not allowed.' })
    };
  }

  if (!bodyText || bodyText.trim().length === 0) {
    return {
      status: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'Empty request body.' })
    };
  }
  if (new TextEncoder().encode(bodyText).byteLength > MAX_SCAN_REQUEST_BYTES) {
    return {
      status: 413,
      headers,
      body: JSON.stringify({ success: false, error: 'Serialized scan request exceeds the 21 MiB limit.' })
    };
  }

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(bodyText);
  } catch {
    return {
      status: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'Request body must contain valid JSON.' })
    };
  }
  if (!parsedBody || typeof parsedBody !== 'object' || Array.isArray(parsedBody)) {
    return {
      status: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'Request body must be a JSON object.' })
    };
  }

  // File scan endpoint
  if (isFileScan) {
    const result = await service.scanFiles(parsedBody as FileScanPayload);
    return {
      status: result.success ? 200 : 400,
      headers,
      body: JSON.stringify(result)
    };
  }

  // GitHub scan endpoint
  const result = await service.scanGitHub(parsedBody as GitHubScanPayload);
  return {
    status: result.success ? 200 : 400,
    headers,
    body: JSON.stringify(result)
  };
}

/**
 * Standard Web Fetch API Handler (for Cloudflare Workers or Node 18+ Fetch)
 */
export async function handleFetch(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method;
  const pathname = url.pathname;

  let bodyText: string | undefined;
  if (method === 'POST') {
    const reader = request.body?.getReader();
    if (reader) {
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_SCAN_REQUEST_BYTES) {
          await reader.cancel();
          const headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer'
          };
          return new Response(JSON.stringify({
            success: false,
            error: 'Serialized scan request exceeds the 21 MiB limit.'
          }), { status: 413, headers });
        }
        chunks.push(value);
      }
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      bodyText = new TextDecoder().decode(bytes);
    } else {
      bodyText = '';
    }
  }

  const { status, headers, body } = await handleApiRequest(method, pathname, bodyText);
  return new Response(body, { status, headers });
}
