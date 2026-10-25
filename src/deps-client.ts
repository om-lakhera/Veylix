import { MaintenanceHealthEstimate, SupportedEcosystem } from './types.js';

export interface DepsDevClientOptions {
  apiUrl?: string;
  timeoutMs?: number; // default 5,000ms
  fetchFn?: typeof fetch;
}

const DEFAULT_DEPS_API_URL = 'https://api.deps.dev/v3alpha';
const DEFAULT_TIMEOUT_MS = 5000;

export class DepsDevClient {
  private apiUrl: string;
  private timeoutMs: number;
  private fetchFn: typeof fetch;
  private healthCache = new Map<string, MaintenanceHealthEstimate>();

  constructor(options: DepsDevClientOptions = {}) {
    this.apiUrl = options.apiUrl || DEFAULT_DEPS_API_URL;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchFn = options.fetchFn || fetch.bind(globalThis);
  }

  /**
   * Fetches maintenance vitality signals from deps.dev and OpenSSF Scorecard.
   * Degrades gracefully on network errors, timeouts, or 404/429 statuses without throwing.
   */
  async getPackageHealth(
    name: string,
    version: string,
    ecosystem: SupportedEcosystem
  ): Promise<MaintenanceHealthEstimate> {
    const cacheKey = `${ecosystem}:${name.toLowerCase()}@${version}`;
    if (this.healthCache.has(cacheKey)) {
      return this.healthCache.get(cacheKey)!;
    }

    const system = ecosystem === 'npm' ? 'npm' : 'pypi';
    // Build a PURL (Package URL) for the deps.dev API.
    // Per the PURL spec and deps.dev documentation, scoped npm packages like '@types/node'
    // use a namespace+name structure: pkg:npm/%40types/node@version.
    // Only the '@' in the scope is encoded; the '/' between namespace and name is kept literal.
    // The entire PURL is then fully percent-encoded for the URL path parameter.
    const purlName = ecosystem === 'npm' && name.startsWith('@')
      ? name.toLowerCase().replace('@', '%40')  // encode @ but keep the / separator
      : name.toLowerCase();
    const purl = `pkg:${system}/${purlName}@${version}`;
    const encodedPurl = encodeURIComponent(purl);

    try {
      // 1. Fetch version metadata
      const versionData = await this.fetchJson(`${this.apiUrl}/purl/${encodedPurl}`);

      if (!versionData || !versionData.version) {
        const unknownResult: MaintenanceHealthEstimate = {
          scorecardScore: null,
          maintainedScore: null,
          status: 'UNKNOWN',
          signals: ['Package version not indexed in deps.dev']
        };
        this.healthCache.set(cacheKey, unknownResult);
        return unknownResult;
      }

      const ver = versionData.version;
      const publishedAt = ver.publishedAt;
      const isDeprecated = Boolean(ver.isDeprecated);
      const deprecatedReason = ver.deprecatedReason || undefined;

      let daysSinceRelease: number | undefined;
      if (publishedAt) {
        const pubTime = new Date(publishedAt).getTime();
        if (!isNaN(pubTime)) {
          daysSinceRelease = Math.max(0, Math.floor((Date.now() - pubTime) / (1000 * 60 * 60 * 24)));
        }
      }

      // Find source repository link
      let sourceRepo: string | undefined;
      if (Array.isArray(ver.relatedProjects)) {
        const sourceProj = ver.relatedProjects.find((rp: any) => rp.relationType === 'SOURCE_REPO');
        if (sourceProj?.projectKey?.id) {
          sourceRepo = sourceProj.projectKey.id;
        }
      }

      // 2. Fetch project metadata (OpenSSF Scorecard) if source repo is known
      let scorecardScore: number | null = null;
      let maintainedScore: number | null = null;
      let starsCount: number | undefined;
      let openIssuesCount: number | undefined;

      if (sourceRepo) {
        const projectData = await this.fetchJson(`${this.apiUrl}/projects/${encodeURIComponent(sourceRepo)}`);
        if (projectData && typeof projectData === 'object') {
          starsCount = typeof projectData.starsCount === 'number' ? projectData.starsCount : undefined;
          openIssuesCount = typeof projectData.openIssuesCount === 'number' ? projectData.openIssuesCount : undefined;

          if (projectData.scorecard && typeof projectData.scorecard === 'object') {
            if (typeof projectData.scorecard.overallScore === 'number') {
              scorecardScore = Math.round(projectData.scorecard.overallScore * 10) / 10;
            }

            if (Array.isArray(projectData.scorecard.checks)) {
              const maintainedCheck = projectData.scorecard.checks.find(
                (c: any) => c.name?.toLowerCase() === 'maintained'
              );
              if (maintainedCheck && typeof maintainedCheck.score === 'number' && maintainedCheck.score >= 0) {
                maintainedScore = maintainedCheck.score;
              }
            }
          }
        }
      }

      // 3. Formulate empirical signals and status
      const signals: string[] = [];
      let status: MaintenanceHealthEstimate['status'] = 'UNKNOWN';

      if (isDeprecated) {
        status = 'MAINTENANCE_RISK';
        signals.push(`Package is flagged as deprecated${deprecatedReason ? `: "${deprecatedReason}"` : ''}.`);
      }

      if (maintainedScore !== null) {
        if (maintainedScore <= 2) {
          status = 'MAINTENANCE_RISK';
          signals.push(`Low OpenSSF maintenance vitality score (${maintainedScore}/10).`);
        } else if (maintainedScore >= 8) {
          signals.push(`High OpenSSF maintenance vitality score (${maintainedScore}/10).`);
        }
      }

      if (daysSinceRelease !== undefined) {
        if (daysSinceRelease > 730) {
          const years = Math.round((daysSinceRelease / 365) * 10) / 10;
          signals.push(`Version published ${years} years ago (${daysSinceRelease} days).`);
          if (maintainedScore === null || maintainedScore < 4) {
            status = 'MAINTENANCE_RISK';
          }
        } else if (daysSinceRelease <= 90) {
          signals.push(`Recent version published within last 90 days.`);
        }
      }

      if (scorecardScore !== null) {
        signals.push(`Overall OpenSSF Scorecard rating: ${scorecardScore}/10.`);
        if (status !== 'MAINTENANCE_RISK') {
          status = 'ACTIVE';
        }
      } else if (status !== 'MAINTENANCE_RISK') {
        status = publishedAt ? 'ACTIVE' : 'UNKNOWN';
      }

      const estimate: MaintenanceHealthEstimate = {
        scorecardScore,
        maintainedScore,
        publishedAt,
        daysSinceRelease,
        isDeprecated,
        deprecatedReason,
        sourceRepo,
        starsCount,
        openIssuesCount,
        status,
        signals
      };

      this.healthCache.set(cacheKey, estimate);
      return estimate;
    } catch (err: any) {
      const isRateLimit = err?.message?.includes('429');
      const unavailableResult: MaintenanceHealthEstimate = {
        scorecardScore: null,
        maintainedScore: null,
        status: 'DATA_UNAVAILABLE',
        signals: [isRateLimit ? 'deps.dev rate limited (HTTP 429)' : 'deps.dev service temporarily unavailable']
      };
      return unavailableResult;
    }
  }

  private async fetchJson(url: string): Promise<any> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      });

      if (!response.ok) {
        if (response.status === 404) return null;
        if (response.status === 429) throw new Error('HTTP 429: Too Many Requests');
        return null;
      }

      return await response.json();
    } finally {
      clearTimeout(timer);
    }
  }
}
