import React from 'react';
import { clearAllScanHistory } from '../services/storage.js';

interface SettingsAboutViewProps {
  onHistoryCleared: () => void;
  onOpenPreferences: () => void;
}

export const SettingsAboutView: React.FC<SettingsAboutViewProps> = ({
  onHistoryCleared,
  onOpenPreferences
}) => {
  const handleClearHistory = () => {
    if (!confirm('Clear all saved scan history from this browser?')) return;
    const cleared = clearAllScanHistory();
    if (cleared) {
      onHistoryCleared();
      alert('Saved scan history was cleared.');
    } else {
      alert('Browser storage could not be cleared. Please clear this site’s data in your browser settings.');
    }
  };

  return (
    <div className="settings-page animate-in">
      <div className="settings-heading">
        <img src="/veylix-icon.svg" alt="" />
        <div>
          <p className="overview-eyebrow">Veylix</p>
          <h1>Settings & About</h1>
          <p>Scan. Secure. Stay Ahead. Dependency analysis powered by your lockfiles and public package-advisory data.</p>
        </div>
      </div>

      <section className="card card-elevated settings-section">
        <h2>Scan behavior</h2>
        <ul>
          <li>Supported manifests: npm <code>package-lock.json</code> (lockfile versions 1–3), Python <code>requirements.txt</code>, and Poetry <code>poetry.lock</code>. Companion <code>package.json</code> and <code>pyproject.toml</code> files are optional where supported.</li>
          <li>Local-file scans use the same-origin API when available and can fall back to the browser engine if the API cannot be reached. Public GitHub scans require the server API.</li>
          <li>Resolved package versions are queried against OSV. Optional maintenance checks use deps.dev and are limited to at most 30 direct dependencies per scan.</li>
          <li>Scan results depend on the input files and data available from external services. An empty advisory list is not a guarantee that a project is secure.</li>
        </ul>
      </section>

      <section className="card card-elevated settings-section">
        <h2>Data and storage</h2>
        <ul>
          <li>Successful reports are stored in this browser’s local storage, up to 25 scans, until deleted or browser storage is cleared.</li>
          <li>Uploaded manifest text is processed in memory by the API or browser engine. The API does not intentionally save the uploaded contents or scan history.</li>
          <li>Scans may contact GitHub for public manifests, OSV for vulnerability matching, and deps.dev when maintenance checks are enabled. Hosting-provider operational logs depend on the deployment configuration.</li>
        </ul>
        <div className="settings-actions">
          <button className="btn btn-secondary" type="button" onClick={handleClearHistory}>Clear saved scan history</button>
          <button className="btn btn-secondary" type="button" onClick={onOpenPreferences}>Cookie & storage preferences</button>
        </div>
      </section>

      <section className="card card-elevated settings-section">
        <h2>Deployment status</h2>
        <p>The Vite development and preview servers include the scan API. A production deployment must run the included Node server or mount the API handler in its serverless runtime; a static-only host does not provide GitHub scan APIs.</p>
        <p>No API keys or environment variables are required by the current OSV, deps.dev, or public GitHub integrations. Hosting, domain, and service usage may have costs or limits; this project does not guarantee a $0 operating cost.</p>
        <a href="/privacy">Review privacy details</a>
      </section>
    </div>
  );
};
