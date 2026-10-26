import { ActiveTab, AppRoute } from './types.js';

const routePaths: Partial<Record<ActiveTab, string>> = {
  dashboard: '/',
  'new-scan': '/new-scan',
  history: '/scans',
  dependencies: '/dependencies',
  advisories: '/advisories',
  about: '/settings',
  faq: '/faq',
  documentation: '/documentation',
  privacy: '/privacy',
  terms: '/terms',
  cookies: '/cookies',
  support: '/support'
};

export function resolveRoute(pathname: string): AppRoute {
  const path = pathname.replace(/\/+$/, '') || '/';
  const scanMatch = path.match(/^\/scans\/([A-Za-z0-9_-]{1,100})$/);
  if (scanMatch) return { page: 'results', scanId: scanMatch[1] };

  const page = Object.entries(routePaths).find(([, routePath]) => routePath === path)?.[0] as ActiveTab | undefined;
  if (page) return { page };
  if (path === '/about') return { page: 'about' };
  return { page: 'not-found' };
}

export function pathForRoute(page: ActiveTab, scanId?: string): string {
  if (page === 'results') {
    if (scanId && /^[A-Za-z0-9_-]{1,100}$/.test(scanId)) {
      return `/scans/${encodeURIComponent(scanId)}`;
    }
    return '/scans';
  }
  return routePaths[page] ?? '/not-found';
}
