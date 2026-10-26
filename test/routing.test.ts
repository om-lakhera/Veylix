import { describe, expect, it } from 'vitest';
import { pathForRoute, resolveRoute } from '../src/web/routing.js';

describe('public page routes', () => {
  it.each([
    ['/', 'dashboard'],
    ['/new-scan', 'new-scan'],
    ['/scans', 'history'],
    ['/dependencies', 'dependencies'],
    ['/advisories', 'advisories'],
    ['/settings', 'about'],
    ['/faq', 'faq'],
    ['/documentation', 'documentation'],
    ['/privacy', 'privacy'],
    ['/terms', 'terms'],
    ['/cookies', 'cookies'],
    ['/support', 'support']
  ])('resolves %s to %s', (path, page) => {
    expect(resolveRoute(path).page).toBe(page);
  });

  it('routes valid local scan identifiers to private report details', () => {
    expect(resolveRoute('/scans/scan_123_ab')).toEqual({
      page: 'results',
      scanId: 'scan_123_ab'
    });
  });

  it('returns the custom not-found route for unknown paths', () => {
    expect(resolveRoute('/unknown-page')).toEqual({ page: 'not-found' });
  });

  it('builds report links only for valid local scan identifiers', () => {
    expect(pathForRoute('results', 'scan_123_ab')).toBe('/scans/scan_123_ab');
    expect(pathForRoute('results', '../private')).toBe('/scans');
  });
});
