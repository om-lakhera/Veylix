import { describe, it, expect, vi } from 'vitest';
import { handleApiRequest } from '../src/server/api-handler.js';

describe('Universal API Handler', () => {
  it('returns health metadata on GET /api/health', async () => {
    const res = await handleApiRequest('GET', '/api/health');
    expect(res.status).toBe(200);
    const json = JSON.parse(res.body);
    expect(json.status).toBe('ok');
    expect(json.budget).toBeUndefined();
    expect(json.supportedEcosystems).toEqual(['npm', 'pypi']);
  });

  it('does not enable cross-origin preflight access', async () => {
    const res = await handleApiRequest('OPTIONS', '/api/scan');
    expect(res.status).toBe(405);
    expect(res.headers.Allow).toBe('POST');
    expect(res.headers['Access-Control-Allow-Origin']).toBeUndefined();
  });

  it('returns 400 on empty POST /api/scan body', async () => {
    const res = await handleApiRequest('POST', '/api/scan', '');
    expect(res.status).toBe(400);
    const json = JSON.parse(res.body);
    expect(json.success).toBe(false);
  });

  it('returns 404 on unknown endpoint', async () => {
    const res = await handleApiRequest('GET', '/api/unknown');
    expect(res.status).toBe(404);
  });

  it('rejects oversized serialized request bodies', async () => {
    const body = JSON.stringify({ repoUrl: 'x'.repeat(21 * 1024 * 1024) });
    const res = await handleApiRequest('POST', '/api/scan-github', body);
    expect(res.status).toBe(413);
    expect(JSON.parse(res.body).success).toBe(false);
  });

  it('handles POST /api/scan-github with invalid URL gracefully', async () => {
    const res = await handleApiRequest('POST', '/api/scan-github', JSON.stringify({ repoUrl: '' }));
    expect(res.status).toBe(400);
    const json = JSON.parse(res.body);
    expect(json.success).toBe(false);
    expect(json.error).toBeDefined();
  });

  it('rejects unsupported scan fields with a safe response', async () => {
    const res = await handleApiRequest(
      'POST',
      '/api/scan',
      JSON.stringify({ requirementsTxt: 'requests==2.28.1\n', privateField: 'do not echo' })
    );

    expect(res.status).toBe(400);
    expect(res.body).not.toContain('do not echo');
    expect(JSON.parse(res.body).error).toBe('The request contains an unsupported field.');
  });
});
