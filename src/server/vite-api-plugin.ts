import type { Plugin } from 'vite';
import { handleApiRequest } from './api-handler.js';
import { MAX_SCAN_REQUEST_BYTES } from '../limits.js';

async function handleViteApiRequest(
  req: import('node:http').IncomingMessage,
  res: import('node:http').ServerResponse,
  next: (error?: Error) => void,
  fallbackPort: number
): Promise<void> {
  if (!req.url?.startsWith('/api/')) {
    next();
    return;
  }

  try {
    const pathname = new URL(req.url, `http://localhost:${fallbackPort}`).pathname;
    let bodyText = '';
    let tooLarge = false;
    if (req.method === 'POST') {
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      for await (const chunk of req) {
        if (tooLarge) continue;
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buffer.byteLength;
        if (totalBytes > MAX_SCAN_REQUEST_BYTES) {
          tooLarge = true;
          chunks.length = 0;
        } else {
          chunks.push(buffer);
        }
      }
      if (!tooLarge) bodyText = Buffer.concat(chunks, totalBytes).toString('utf8');
    }

    const result = tooLarge
      ? {
          status: 413,
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
          body: JSON.stringify({ success: false, error: 'Serialized scan request exceeds the 21 MiB limit.' })
        }
      : await handleApiRequest(req.method || 'GET', pathname, bodyText);
    res.writeHead(result.status, result.headers);
    res.end(result.body);
  } catch {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(500, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ success: false, error: 'The scan service encountered an unexpected error.' }));
  }
}

export function veylixApiPlugin(): Plugin {
  return {
    name: 'veylix-api-plugin',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        await handleViteApiRequest(req, res, next, 5173);
      });
    },
    configurePreviewServer(server) {
      server.middlewares.use(async (req, res, next) => {
        await handleViteApiRequest(req, res, next, 4173);
      });
    }
  };
}
