import { afterEach, describe, expect, it } from 'vitest';
import { evaluateScanRateLimit, resetScanRateLimitState } from '../src/server/scan-rate-limiter.js';

describe('scan rate limiter', () => {
  afterEach(() => resetScanRateLimitState());

  it('allows 20 scans per network peer in a minute and returns a retry duration afterward', () => {
    const now = 1_000_000;
    for (let request = 0; request < 20; request += 1) {
      expect(evaluateScanRateLimit('peer-a', now).allowed).toBe(true);
    }

    expect(evaluateScanRateLimit('peer-a', now)).toEqual({
      allowed: false,
      retryAfterMs: 60_000
    });
  });

  it('starts a new window after the prior window expires', () => {
    const now = 1_000_000;
    for (let request = 0; request < 20; request += 1) {
      evaluateScanRateLimit('peer-a', now);
    }

    expect(evaluateScanRateLimit('peer-a', now + 60_000).allowed).toBe(true);
  });

  it('keeps request buckets separate by network peer', () => {
    for (let request = 0; request < 20; request += 1) {
      evaluateScanRateLimit('peer-a', 1_000_000);
    }

    expect(evaluateScanRateLimit('peer-b', 1_000_000).allowed).toBe(true);
  });
});
