const WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 20;
const MAX_CLIENT_ENTRIES = 10_000;

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const entries = new Map<string, RateLimitEntry>();
let lastPrunedAt = 0;

export function resetScanRateLimitState(): void {
  entries.clear();
  lastPrunedAt = 0;
}

export function evaluateScanRateLimit(
  clientKey: string,
  now = Date.now()
): { allowed: boolean; retryAfterMs: number } {
  const existing = entries.get(clientKey);
  if (existing && now - existing.windowStart < WINDOW_MS) {
    if (existing.count >= MAX_REQUESTS_PER_WINDOW) {
      return {
        allowed: false,
        retryAfterMs: Math.max(1000, WINDOW_MS - (now - existing.windowStart))
      };
    }
    existing.count += 1;
    return { allowed: true, retryAfterMs: 0 };
  }

  if (now - lastPrunedAt >= WINDOW_MS) {
    for (const [key, entry] of entries) {
      if (now - entry.windowStart >= WINDOW_MS) entries.delete(key);
    }
    lastPrunedAt = now;
  }

  if (entries.size >= MAX_CLIENT_ENTRIES) {
    return { allowed: false, retryAfterMs: WINDOW_MS };
  }

  entries.set(clientKey, { count: 1, windowStart: now });
  return { allowed: true, retryAfterMs: 0 };
}
