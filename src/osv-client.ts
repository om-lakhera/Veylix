import {
  OSVBatchRequest,
  OSVBatchResponse,
  OSVAdvisory,
  VulnerabilityFinding,
  PackageIdentifier
} from './types.js';

export interface OSVClientOptions {
  apiUrl?: string;
  vulnApiUrl?: string;
  timeoutMs?: number; // default 10,000ms
  fetchFn?: typeof fetch;
  hydrateAdvisories?: boolean; // When true, fetches full details for matching vuln IDs
}

const DEFAULT_OSV_URL = 'https://api.osv.dev/v1/querybatch';
const DEFAULT_VULN_URL = 'https://api.osv.dev/v1/vulns';
const DEFAULT_TIMEOUT_MS = 10000;

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
}

export function parseSemver(v: string): ParsedSemver | null {
  if (!v || typeof v !== 'string') return null;
  const clean = v.trim().replace(/^[v=]/, '');
  const match = clean.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/);
  if (!match) return null;
  return {
    major: parseInt(match[1]!, 10),
    minor: parseInt(match[2]!, 10),
    patch: parseInt(match[3]!, 10),
    prerelease: match[4]
  };
}

export function compareSemver(v1: string, v2: string): number | null {
  const s1 = parseSemver(v1);
  const s2 = parseSemver(v2);
  if (!s1 || !s2) return null;
  if (s1.major !== s2.major) return s1.major - s2.major;
  if (s1.minor !== s2.minor) return s1.minor - s2.minor;
  if (s1.patch !== s2.patch) return s1.patch - s2.patch;
  if (s1.prerelease && !s2.prerelease) return -1;
  if (!s1.prerelease && s2.prerelease) return 1;
  return 0;
}

export class OSVClient {
  private apiUrl: string;
  private vulnApiUrl: string;
  private timeoutMs: number;
  private fetchFn: typeof fetch;
  private hydrate: boolean;
  private advisoryCache = new Map<string, OSVAdvisory>();

  constructor(options: OSVClientOptions = {}) {
    this.apiUrl = options.apiUrl || DEFAULT_OSV_URL;
    this.vulnApiUrl = options.vulnApiUrl || DEFAULT_VULN_URL;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchFn = options.fetchFn || fetch.bind(globalThis);
    this.hydrate = Boolean(options.hydrateAdvisories);
  }

  /**
   * Fetches full advisory details for a given advisory ID.
   * Utilizes in-memory caching to avoid duplicate requests for identical advisories across packages.
   */
  async getAdvisoryDetails(advisoryId: string): Promise<OSVAdvisory | null> {
    if (this.advisoryCache.has(advisoryId)) {
      return this.advisoryCache.get(advisoryId)!;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(`${this.vulnApiUrl}/${encodeURIComponent(advisoryId)}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      });

      if (!response.ok) {
        return null;
      }

      const advisory = await response.json() as OSVAdvisory;
      if (advisory && typeof advisory === 'object' && advisory.id) {
        this.advisoryCache.set(advisoryId, advisory);
        return advisory;
      }
      return null;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Queries OSV batch API for a list of packages.
   * Chunks queries in batches of up to 1,000 to respect OSV maximum payload limits.
   */
  async queryBatch(packages: PackageIdentifier[]): Promise<OSVBatchResponse> {
    if (packages.length === 0) {
      return { results: [] };
    }

    const CHUNK_SIZE = 1000;
    const allResults: OSVBatchResponse['results'] = [];

    for (let i = 0; i < packages.length; i += CHUNK_SIZE) {
      const chunk = packages.slice(i, i + CHUNK_SIZE);
      const batchRequest: OSVBatchRequest = {
        queries: chunk.map((pkg) => ({
          package: {
            name: pkg.name,
            ecosystem: pkg.ecosystem === 'pypi' ? 'PyPI' : 'npm'
          },
          version: pkg.version
        }))
      };

      const result = await this.executeSingleBatch(batchRequest);

      // If hydrate is enabled, fetch full details for all unique vuln IDs concurrently
      if (this.hydrate) {
        const uniqueVulnIds = new Set<string>();
        for (const item of result.results) {
          if (Array.isArray(item.vulns)) {
            for (const v of item.vulns) {
              if (v.id) uniqueVulnIds.add(v.id);
            }
          }
        }

        // Fetch details concurrently with cache
        await Promise.all(Array.from(uniqueVulnIds).map((id) => this.getAdvisoryDetails(id)));

        // Replace compact vuln items with enriched advisory details if available
        for (const item of result.results) {
          if (Array.isArray(item.vulns)) {
            item.vulns = item.vulns.map((v) => {
              const full = this.advisoryCache.get(v.id);
              return full || v;
            });
          }
        }
      }

      allResults.push(...result.results);
    }

    return { results: allResults };
  }

  private async executeSingleBatch(requestBody: OSVBatchRequest): Promise<OSVBatchResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(requestBody),
        signal: controller.signal
      });

      if (!response.ok) {
        if (response.status === 429) {
          throw new Error('OSV API rate limit encountered (HTTP 429). Please retry later.');
        }
        if (response.status >= 500) {
          throw new Error(`OSV API server error (HTTP ${response.status}). Please retry later.`);
        }
        throw new Error(`OSV API request failed with HTTP ${response.status}.`);
      }

      const data = await response.json() as any;

      if (!data || typeof data !== 'object') {
        throw new Error('OSV API returned invalid non-object response.');
      }

      if (!Array.isArray(data.results)) {
        throw new Error('OSV API response missing "results" array.');
      }

      return data as OSVBatchResponse;
    } catch (err: any) {
      if (err.name === 'AbortError') {
        throw new Error(`OSV API request timed out after ${this.timeoutMs}ms.`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Transforms an OSV raw advisory into a clean, actionable VulnerabilityFinding
   * grounded strictly in returned data.
   */
  static transformAdvisory(
    advisory: OSVAdvisory,
    targetPackageName: string,
    targetVersion: string,
    targetEcosystem?: PackageIdentifier['ecosystem']
  ): VulnerabilityFinding {
    const advisoryId = advisory.id;
    const aliases = advisory.aliases || [];
    const summary = advisory.summary || advisory.details?.slice(0, 200) || 'Security advisory published for this package.';
    const details = advisory.details;
    const published = advisory.published;

    // 1. Determine severity level
    let severityLevel: VulnerabilityFinding['severityLevel'] = 'UNKNOWN';
    let cvssScore: string | undefined;

    // Check database_specific.severity and ecosystem_specific.severity (GHSA format: "CRITICAL", "HIGH", "MODERATE" / "MEDIUM", "LOW")
    const rawSev =
      advisory.database_specific?.severity ||
      (advisory as any).ecosystem_specific?.severity;

    if (typeof rawSev === 'string') {
      const normalized = rawSev.toUpperCase();
      if (normalized === 'CRITICAL') severityLevel = 'CRITICAL';
      else if (normalized === 'HIGH') severityLevel = 'HIGH';
      else if (normalized === 'MODERATE' || normalized === 'MEDIUM') severityLevel = 'MODERATE';
      else if (normalized === 'LOW') severityLevel = 'LOW';
    }

    // Check severities array for CVSS
    const severities = advisory.severities || advisory.severity;
    if (Array.isArray(severities) && severities.length > 0) {
      const cvss = severities[0];
      if (cvss && typeof cvss.score === 'string') {
        cvssScore = cvss.score;
        // If severityLevel is still UNKNOWN, derive from CVSS string or numerical score if present
        if (severityLevel === 'UNKNOWN') {
          const numericMatch = cvss.score.match(/^(\d+(\.\d+)?)$/);
          if (numericMatch) {
            const scoreNum = parseFloat(numericMatch[1]!);
            if (scoreNum >= 9.0) severityLevel = 'CRITICAL';
            else if (scoreNum >= 7.0) severityLevel = 'HIGH';
            else if (scoreNum >= 4.0) severityLevel = 'MODERATE';
            else severityLevel = 'LOW';
          }
        }
      }
    }

    // 2. Extract fixed version & affected version ranges from affected entries
    let fixedVersion: string | undefined;
    const rangeDescriptions: string[] = [];
    const candidateFixes: string[] = [];

    if (Array.isArray(advisory.affected)) {
      for (const aff of advisory.affected) {
        if (
          !aff?.package ||
          typeof aff.package.name !== 'string' ||
          typeof aff.package.ecosystem !== 'string' ||
          aff.package.name.toLowerCase() !== targetPackageName.toLowerCase() ||
          (targetEcosystem !== undefined &&
            aff.package.ecosystem.toLowerCase() !== targetEcosystem.toLowerCase())
        ) {
          continue;
        }

        if (Array.isArray(aff.ranges)) {
          for (const range of aff.ranges) {
            if (Array.isArray(range.events)) {
              let currentIntroduced: string | undefined;

              for (const evt of range.events) {
                if (evt.introduced !== undefined) {
                  currentIntroduced = evt.introduced;
                } else if (evt.fixed !== undefined) {
                  candidateFixes.push(evt.fixed);
                  if (currentIntroduced !== undefined) {
                    rangeDescriptions.push(`>= ${currentIntroduced}, < ${evt.fixed}`);
                    currentIntroduced = undefined;
                  } else {
                    rangeDescriptions.push(`< ${evt.fixed}`);
                  }
                } else if (evt.last_affected !== undefined) {
                  if (currentIntroduced !== undefined) {
                    rangeDescriptions.push(`>= ${currentIntroduced}, <= ${evt.last_affected}`);
                    currentIntroduced = undefined;
                  } else {
                    rangeDescriptions.push(`<= ${evt.last_affected}`);
                  }
                }
              }

              // If an introduced version was not closed by fixed/last_affected
              if (currentIntroduced !== undefined) {
                rangeDescriptions.push(`>= ${currentIntroduced}`);
              }
            }
          }
        }
      }
    }

    // Select the best candidate fix for targetVersion:
    // Look for candidate fixes that are strictly greater than targetVersion (> targetVersion).
    // Among those greater versions, select the lowest one (the nearest safe upgrade path).
    if (candidateFixes.length > 0) {
      const parsedTarget = parseSemver(targetVersion);

      if (parsedTarget) {
        const validUpgrades = candidateFixes
          .filter((fix) => {
            const cmp = compareSemver(fix, targetVersion);
            return cmp !== null && cmp > 0;
          })
          .sort((a, b) => {
            const cmp = compareSemver(a, b);
            return cmp ?? 0;
          });

        if (validUpgrades.length > 0) {
          fixedVersion = validUpgrades[0];
        }
      } else {
        // Fallback for non-semver versions (e.g. git hashes): use first recorded candidate fix
        fixedVersion = candidateFixes[0];
      }
    }

    // 3. Grounded Actionable Recommendation
    let actionableRecommendation = '';
    if (fixedVersion) {
      actionableRecommendation = `Upgrade ${targetPackageName} from version ${targetVersion} to ${fixedVersion} or later to patch this vulnerability.`;
    } else {
      actionableRecommendation = `No fixed version is currently recorded in advisory ${advisoryId}. Review the advisory details, assess mitigation workarounds, or consider an alternative package.`;
    }

    return {
      advisoryId,
      aliases,
      severityLevel,
      cvssScore,
      summary,
      details,
      fixedVersion,
      published,
      affectedVersionRange: rangeDescriptions.length > 0 ? rangeDescriptions.join('; ') : undefined,
      actionableRecommendation
    };
  }
}
