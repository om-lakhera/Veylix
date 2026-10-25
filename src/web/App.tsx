import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { ActiveTab, AppRoute, ScanHistoryItem, ScanTargetInfo } from './types.js';
import { AnalysisReport } from '../types.js';
import { loadScanHistory, saveScanToHistory } from './services/storage.js';
import { pathForRoute, resolveRoute } from './routing.js';
import { Header } from './components/Header.js';
import { Footer } from './components/Footer.js';
import { DashboardView } from './views/DashboardView.js';
import { NewScanView } from './views/NewScanView.js';
import { ScanResultsView } from './views/ScanResultsView.js';
import { ScanHistoryView } from './views/ScanHistoryView.js';
import { SettingsAboutView } from './views/SettingsAboutView.js';
import { InsightsView } from './views/InsightsView.js';
import { PolicyView, StoragePreferencesDialog } from './views/PolicyView.js';

const routeMetadata: Record<ActiveTab, { title: string; description: string; noindex?: boolean }> = {
  dashboard: { title: 'Security Overview', description: 'Review saved dependency scan activity and start a vulnerability or maintenance scan with Veylix.' },
  'new-scan': { title: 'New Dependency Scan', description: 'Scan supported npm and Python dependency files or a public GitHub repository.' },
  history: { title: 'Scan History', description: 'Browse dependency scan reports saved locally in this browser.', noindex: true },
  results: { title: 'Scan Details', description: 'Review the findings and resolved dependencies in a saved Veylix scan report.', noindex: true },
  dependencies: { title: 'Dependencies', description: 'Review resolved dependencies from a saved Veylix scan report.', noindex: true },
  advisories: { title: 'Advisories', description: 'Review vulnerability advisories returned for a saved Veylix scan report.', noindex: true },
  about: { title: 'Settings & About', description: 'Manage local scan history and review Veylix scan behavior.', noindex: true },
  privacy: { title: 'Privacy Policy', description: 'Learn how Veylix processes dependency scans and browser-local scan history.', noindex: true },
  terms: { title: 'Terms of Service', description: 'Review draft terms and limitations for the Veylix dependency scanner.', noindex: true },
  cookies: { title: 'Cookie Policy', description: 'Understand Veylix cookie behavior and browser-local scan history storage.' },
  support: { title: 'Contact & Support', description: 'Find the currently available Veylix project support channel.' },
  'not-found': { title: 'Page Not Found', description: 'The requested Veylix page could not be found.', noindex: true }
};

const siteBaseUrl = (() => {
  const configuredUrl = import.meta.env.VITE_SITE_URL?.trim();
  if (!configuredUrl) return undefined;
  try {
    const url = new URL(configuredUrl);
    if (
      url.protocol !== 'https:' ||
      !url.hostname.includes('.') ||
      url.username ||
      url.password ||
      (url.pathname !== '/' && url.pathname !== '') ||
      url.search ||
      url.hash
    ) {
      throw new Error('VITE_SITE_URL must be an HTTPS site origin without a path, query, or fragment.');
    }
    return new URL('/', url.origin);
  } catch (error) {
    console.error(
      error instanceof Error
        ? error.message
        : 'VITE_SITE_URL must be a valid HTTPS site origin.'
    );
    return undefined;
  }
})();

function setMeta(attribute: 'name' | 'property', key: string, content: string): void {
  const selector = `meta[${attribute}="${key}"]`;
  let element = document.head.querySelector<HTMLMetaElement>(selector);
  if (!element) {
    element = document.createElement('meta');
    element.setAttribute(attribute, key);
    document.head.appendChild(element);
  }
  element.content = content;
}

function updateDocumentMetadata(route: AppRoute): void {
  const metadata = routeMetadata[route.page];
  const title = `${metadata.title} | Veylix`;
  document.title = title;

  setMeta('name', 'description', metadata.description);
  setMeta('property', 'og:title', title);
  setMeta('property', 'og:description', metadata.description);
  setMeta('property', 'og:type', 'website');
  setMeta('name', 'twitter:title', title);
  setMeta('name', 'twitter:description', metadata.description);

  const canonical = document.head.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  if (siteBaseUrl && !metadata.noindex) {
    const canonicalUrl = new URL(window.location.pathname, siteBaseUrl);
    const canonicalElement = canonical ?? document.createElement('link');
    canonicalElement.rel = 'canonical';
    canonicalElement.href = canonicalUrl.href;
    if (!canonical) document.head.appendChild(canonicalElement);

    setMeta('property', 'og:url', canonicalUrl.href);
    setMeta('property', 'og:image', new URL('/veylix-logo-horizontal.svg', siteBaseUrl).href);
    setMeta('property', 'og:image:alt', 'Veylix — Scan. Secure. Stay Ahead.');
    setMeta('name', 'twitter:image', new URL('/veylix-logo-horizontal.svg', siteBaseUrl).href);
  } else {
    canonical?.remove();
    document.head.querySelector('meta[property="og:url"]')?.remove();
    document.head.querySelector('meta[property="og:image"]')?.remove();
    document.head.querySelector('meta[property="og:image:alt"]')?.remove();
    document.head.querySelector('meta[name="twitter:image"]')?.remove();
  }
  setMeta('name', 'robots', metadata.noindex ? 'noindex, nofollow, noarchive' : 'index, follow');
}

export const App: React.FC = () => {
  const [route, setRoute] = useState<AppRoute>(() => resolveRoute(window.location.pathname));
  const [history, setHistory] = useState<ScanHistoryItem[]>(() => loadScanHistory());
  const [transientScan, setTransientScan] = useState<{ id: string; target: ScanTargetInfo; report: AnalysisReport } | null>(null);
  const [storageWarning, setStorageWarning] = useState('');
  const [preferencesOpen, setPreferencesOpen] = useState(false);

  useEffect(() => {
    const handlePopState = () => setRoute(resolveRoute(window.location.pathname));
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  useEffect(() => {
    updateDocumentMetadata(route);
    window.scrollTo(0, 0);
  }, [route]);

  const navigate = useCallback((page: ActiveTab, scanId?: string) => {
    const path = pathForRoute(page, scanId);
    if (window.location.pathname !== path) window.history.pushState(null, '', path);
    setRoute(resolveRoute(path));
  }, []);

  const handleScanComplete = (target: ScanTargetInfo, report: AnalysisReport) => {
    const saved = saveScanToHistory(target, report);
    setHistory((prev) => [saved, ...prev.filter((p) => p.id !== saved.id)]);
    setTransientScan({ id: saved.id, target, report });
    const wasPersisted = loadScanHistory().some((item) => item.id === saved.id);
    setStorageWarning(wasPersisted
      ? ''
      : 'This scan completed, but browser storage is unavailable. The report will not be retained after you leave or reload this page.');
    navigate('results', saved.id);
  };

  const handleSelectHistoryItem = (item: ScanHistoryItem) => {
    navigate('results', item.id);
  };

  const activeScan = useMemo(() => {
    if (route.page !== 'results' || !route.scanId) return null;
    const stored = history.find((item) => item.id === route.scanId);
    if (stored) return { target: stored.target, report: stored.report };
    if (transientScan?.id === route.scanId) {
      return { target: transientScan.target, report: transientScan.report };
    }
    return null;
  }, [history, route, transientScan]);

  return (
    <div className="app-container">
      <Header
        activeTab={route.page}
        onTabChange={(tab) => tab === 'results' ? navigate('results', history[0]?.id) : navigate(tab)}
        hasActiveResult={history.length > 0 || Boolean(transientScan)}
        historyCount={history.length}
      />

      <main className="main-content">
        {storageWarning && (
          <div className="alert alert-warning storage-warning" role="status">
            {storageWarning}
          </div>
        )}
        {route.page === 'dashboard' && (
          <DashboardView
            history={history}
            onNavigate={navigate}
            onSelectScan={handleSelectHistoryItem}
          />
        )}

        {route.page === 'new-scan' && (
          <NewScanView onScanComplete={handleScanComplete} />
        )}

        {route.page === 'results' && activeScan && (
          <ScanResultsView
            target={activeScan.target}
            report={activeScan.report}
            onNewScan={() => navigate('new-scan')}
          />
        )}

        {route.page === 'results' && !activeScan && (
          <div className="page-not-found animate-in">
            <h1>Scan report unavailable</h1>
            <p>This scan may have been deleted or is not available in this browser. Scan reports are stored locally and are not shared between browsers.</p>
            <button className="btn btn-primary" onClick={() => navigate('history')}>Return to scan history</button>
          </div>
        )}

        {route.page === 'history' && (
          <ScanHistoryView
            history={history}
            onSelectScan={handleSelectHistoryItem}
            onHistoryUpdate={(items) => setHistory(items)}
            onNewScan={() => navigate('new-scan')}
          />
        )}

        {(route.page === 'dependencies' || route.page === 'advisories') && (
          <InsightsView
            history={history}
            mode={route.page}
            onSelectScan={handleSelectHistoryItem}
          />
        )}

        {route.page === 'about' && (
          <SettingsAboutView
            onHistoryCleared={() => {
              setHistory([]);
              setTransientScan(null);
              setStorageWarning('');
              navigate('about');
            }}
            onOpenPreferences={() => setPreferencesOpen(true)}
          />
        )}

        {(route.page === 'privacy' || route.page === 'terms' || route.page === 'cookies' || route.page === 'support') && (
          <PolicyView page={route.page} />
        )}

        {route.page === 'not-found' && (
          <div className="page-not-found animate-in">
            <p className="overview-eyebrow">404 · Not found</p>
            <h1>This page isn't here</h1>
            <p>The address may be invalid, or this page may have moved.</p>
            <button className="btn btn-primary" onClick={() => navigate('dashboard')}>Back to overview</button>
          </div>
        )}
      </main>

      <Footer onOpenPreferences={() => setPreferencesOpen(true)} />
      <StoragePreferencesDialog open={preferencesOpen} onClose={() => setPreferencesOpen(false)} />
    </div>
  );
};
