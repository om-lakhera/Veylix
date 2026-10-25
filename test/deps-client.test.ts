import { describe, it, expect, vi } from 'vitest';
import { DepsDevClient } from '../src/deps-client.js';

describe('DepsDevClient (Maintenance & OpenSSF Scorecard)', () => {
  it('correctly fetches version and project Scorecard data from deps.dev', async () => {
    const mockFetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/purl/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            version: {
              publishedAt: '2023-01-15T12:00:00Z',
              isDeprecated: false,
              relatedProjects: [
                {
                  projectKey: { id: 'github.com/psf/requests' },
                  relationType: 'SOURCE_REPO'
                }
              ]
            }
          })
        });
      }
      if (url.includes('/projects/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            starsCount: 50000,
            openIssuesCount: 120,
            scorecard: {
              overallScore: 8.24,
              checks: [
                { name: 'Maintained', score: 10 },
                { name: 'Code-Review', score: 8 }
              ]
            }
          })
        });
      }
      return Promise.reject(new Error(`Unhandled URL: ${url}`));
    });

    const client = new DepsDevClient({ fetchFn: mockFetch });
    const health = await client.getPackageHealth('requests', '2.28.1', 'pypi');

    expect(health.status).toBe('ACTIVE');
    expect(health.scorecardScore).toBe(8.2);
    expect(health.maintainedScore).toBe(10);
    expect(health.sourceRepo).toBe('github.com/psf/requests');
    expect(health.starsCount).toBe(50000);
    expect(health.signals.some((s) => s.includes('Scorecard rating: 8.2/10'))).toBe(true);

    // Verify in-memory cache: second lookup should NOT trigger mockFetch
    const callCountBefore = mockFetch.mock.calls.length;
    const cachedHealth = await client.getPackageHealth('requests', '2.28.1', 'pypi');
    expect(mockFetch.mock.calls.length).toBe(callCountBefore);
    expect(cachedHealth).toEqual(health);
  });

  it('flags deprecated packages as MAINTENANCE_RISK', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        version: {
          publishedAt: '2020-01-01T00:00:00Z',
          isDeprecated: true,
          deprecatedReason: 'Please use package-v2 instead'
        }
      })
    });

    const client = new DepsDevClient({ fetchFn: mockFetch });
    const health = await client.getPackageHealth('old-pkg', '1.0.0', 'npm');

    expect(health.status).toBe('MAINTENANCE_RISK');
    expect(health.isDeprecated).toBe(true);
    expect(health.deprecatedReason).toBe('Please use package-v2 instead');
    expect(health.signals[0]).toContain('flagged as deprecated');
  });

  it('flags unmaintained packages (Scorecard Maintained <= 2) as MAINTENANCE_RISK', async () => {
    const mockFetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/purl/')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            version: {
              publishedAt: '2021-05-01T00:00:00Z',
              relatedProjects: [{ projectKey: { id: 'github.com/abandoned/lib' }, relationType: 'SOURCE_REPO' }]
            }
          })
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({
          scorecard: {
            overallScore: 2.1,
            checks: [{ name: 'Maintained', score: 1 }]
          }
        })
      });
    });

    const client = new DepsDevClient({ fetchFn: mockFetch });
    const health = await client.getPackageHealth('abandoned-lib', '1.0.0', 'npm');

    expect(health.status).toBe('MAINTENANCE_RISK');
    expect(health.maintainedScore).toBe(1);
    expect(health.signals.some((s) => s.includes('Low OpenSSF maintenance vitality score (1/10)'))).toBe(true);
  });

  it('handles HTTP 429 rate limit gracefully without throwing', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      statusText: 'Too Many Requests'
    });

    const client = new DepsDevClient({ fetchFn: mockFetch });
    const health = await client.getPackageHealth('popular-pkg', '1.0.0', 'npm');

    expect(health.status).toBe('DATA_UNAVAILABLE');
    expect(health.signals[0]).toContain('deps.dev rate limited (HTTP 429)');
  });

  it('handles missing package (404) gracefully returning UNKNOWN status', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found'
    });

    const client = new DepsDevClient({ fetchFn: mockFetch });
    const health = await client.getPackageHealth('unregistered-pkg', '0.0.1', 'npm');

    expect(health.status).toBe('UNKNOWN');
    expect(health.signals[0]).toContain('not indexed in deps.dev');
  });

  it('handles network timeouts gracefully without breaking execution', async () => {
    const mockFetch = vi.fn().mockImplementation((_url, options) => {
      return new Promise((_, reject) => {
        options.signal.addEventListener('abort', () => {
          const abortErr = new Error('The operation was aborted');
          abortErr.name = 'AbortError';
          reject(abortErr);
        });
      });
    });

    const client = new DepsDevClient({ timeoutMs: 20, fetchFn: mockFetch });
    const health = await client.getPackageHealth('timeout-pkg', '1.0.0', 'pypi');

    expect(health.status).toBe('DATA_UNAVAILABLE');
    expect(health.signals[0]).toContain('temporarily unavailable');
  });

  it('constructs correctly encoded PURL for scoped npm packages (e.g. @types/node)', async () => {
    let capturedUrl = '';
    const mockFetch = vi.fn().mockImplementation((url: string) => {
      capturedUrl = url;
      return Promise.resolve({
        ok: false,
        status: 404,
        statusText: 'Not Found'
      });
    });

    const client = new DepsDevClient({ fetchFn: mockFetch });
    // @types/node scoped package: '@' must be encoded in the PURL name, then the whole PURL is URL-encoded
    await client.getPackageHealth('@types/node', '22.0.0', 'npm');

    // The raw PURL should be: pkg:npm/%40types/node@22.0.0
    // After full URL-encoding: pkg%3Anpm%2F%2540types%2Fnode%4022.0.0
    // This matches the deps.dev API requirement for scoped packages
    expect(capturedUrl).toContain('%2540types%2Fnode');
    expect(capturedUrl).not.toContain('%252F'); // must NOT double-encode the namespace '/'
    expect(capturedUrl).toContain('https://api.deps.dev/v3alpha/purl/');
  });
});
