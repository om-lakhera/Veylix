import { describe, it, expect, vi } from 'vitest';
import { OSVClient } from '../src/osv-client.js';
import { PackageIdentifier } from '../src/types.js';

describe('OSVClient & Advisory Transformer', () => {
  const samplePackages: PackageIdentifier[] = [
    {
      name: 'lodash',
      version: '4.17.15',
      ecosystem: 'npm',
      isDirect: true,
      isDev: false,
      dependencyPaths: ['lodash']
    },
    {
      name: 'safe-pkg',
      version: '1.0.0',
      ecosystem: 'npm',
      isDirect: true,
      isDev: false,
      dependencyPaths: ['safe-pkg']
    }
  ];

  it('correctly batches queries and parses successful response', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        results: [
          {
            vulns: [
              {
                id: 'GHSA-p6mc-m468-83gw',
                summary: 'Prototype Pollution in lodash',
                aliases: ['CVE-2020-8203'],
                database_specific: { severity: 'HIGH' },
                affected: [
                  {
                    package: { name: 'lodash', ecosystem: 'npm' },
                    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }]
                  }
                ]
              }
            ]
          },
          { vulns: [] }
        ]
      })
    });

    const client = new OSVClient({ fetchFn: mockFetch });
    const response = await client.queryBatch(samplePackages);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(response.results.length).toBe(2);
    expect(response.results[0]?.vulns?.length).toBe(1);
    expect(response.results[1]?.vulns?.length).toBe(0);
  });

  it('correctly transforms advisory into grounded VulnerabilityFinding with action recommendation', () => {
    const advisory = {
      id: 'GHSA-p6mc-m468-83gw',
      summary: 'Prototype Pollution in lodash',
      aliases: ['CVE-2020-8203'],
      database_specific: { severity: 'HIGH' },
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }]
        }
      ]
    };

    const finding = OSVClient.transformAdvisory(advisory, 'lodash', '4.17.15');

    expect(finding.advisoryId).toBe('GHSA-p6mc-m468-83gw');
    expect(finding.aliases).toContain('CVE-2020-8203');
    expect(finding.severityLevel).toBe('HIGH');
    expect(finding.fixedVersion).toBe('4.17.19');
    expect(finding.affectedVersionRange).toBe('>= 0, < 4.17.19');
    expect(finding.actionableRecommendation).toBe(
      'Upgrade lodash from version 4.17.15 to 4.17.19 or later to patch this vulnerability.'
    );
  });

  it('handles advisory with no fixed version without inventing a patch', () => {
    const advisory = {
      id: 'GHSA-no-fix-recorded',
      summary: 'Vulnerability with no fixed version yet',
      database_specific: { severity: 'LOW' }
    };

    const finding = OSVClient.transformAdvisory(advisory, 'test-lib', '1.0.0');

    expect(finding.fixedVersion).toBeUndefined();
    expect(finding.severityLevel).toBe('LOW');
    expect(finding.actionableRecommendation).toContain('No fixed version is currently recorded');
  });

  it('handles HTTP 429 rate limit with descriptive error', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      json: async () => ({ message: 'Rate limit exceeded' }),
      text: async () => 'Rate limit exceeded'
    });

    const client = new OSVClient({ fetchFn: mockFetch });
    await expect(client.queryBatch(samplePackages)).rejects.toThrow(
      'OSV API rate limit encountered (HTTP 429)'
    );
  });

  it('handles HTTP 500 server error with descriptive error', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ error: 'Internal server error' }),
      text: async () => 'Internal server error'
    });

    const client = new OSVClient({ fetchFn: mockFetch });
    await expect(client.queryBatch(samplePackages)).rejects.toThrow(
      'OSV API server error (HTTP 500)'
    );
  });

  it('handles request timeout gracefully', async () => {
    const mockFetch = vi.fn().mockImplementation((_url, options) => {
      return new Promise((_, reject) => {
        options.signal.addEventListener('abort', () => {
          const abortErr = new Error('The operation was aborted');
          abortErr.name = 'AbortError';
          reject(abortErr);
        });
      });
    });

    const client = new OSVClient({ timeoutMs: 20, fetchFn: mockFetch });
    await expect(client.queryBatch(samplePackages)).rejects.toThrow(
      'OSV API request timed out after 20ms.'
    );
  });

  it('handles malformed / invalid response from OSV API', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ invalidFormat: true })
    });

    const client = new OSVClient({ fetchFn: mockFetch });
    await expect(client.queryBatch(samplePackages)).rejects.toThrow(
      'OSV API response missing "results" array.'
    );
  });
});
