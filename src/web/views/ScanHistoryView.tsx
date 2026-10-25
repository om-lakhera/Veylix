import React from 'react';
import { ScanHistoryItem } from '../types.js';
import { clearAllScanHistory, deleteScanFromHistory, downloadJsonFile } from '../services/storage.js';

interface ScanHistoryViewProps {
  history: ScanHistoryItem[];
  onSelectScan: (item: ScanHistoryItem) => void;
  onHistoryUpdate: (items: ScanHistoryItem[]) => void;
  onNewScan: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  history,
  onSelectScan,
  onHistoryUpdate,
  onNewScan
}) => {
  const [storageError, setStorageError] = React.useState('');

  const handleDelete = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const result = deleteScanFromHistory(id);
    if (!result.success) {
      setStorageError('Could not delete this scan from browser storage. Check your browser storage settings and try again.');
      return;
    }
    setStorageError('');
    onHistoryUpdate(result.items);
  };

  const handleClearAll = () => {
    if (confirm('Clear all saved scan history from your browser local storage?')) {
      const cleared = clearAllScanHistory();
      if (!cleared) {
        setStorageError('Could not clear scan history from browser storage. Check your browser storage settings and try again.');
        return;
      }
      setStorageError('');
      onHistoryUpdate([]);
    }
  };

  const handleExportAll = () => {
    downloadJsonFile(`veylix_scan_history_${Date.now()}.json`, history);
  };

  return (
    <div className="animate-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '28px' }}>
        <div>
          <h1 style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '6px' }}>
            Scan History
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem' }}>
            Saved in this browser only. Reports are not synced between browsers or devices.
          </p>
        </div>

        <div className="header-actions">
          {history.length > 0 && (
            <>
              <button className="btn btn-secondary btn-sm" onClick={handleExportAll}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                  <polyline points="7 10 12 15 17 10"/>
                  <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Export JSON
              </button>
              <button className="btn btn-ghost btn-sm" style={{ color: 'var(--severity-critical)' }} onClick={handleClearAll}>
                Clear History
              </button>
            </>
          )}
          <button className="btn btn-primary btn-sm" onClick={onNewScan}>
            + New Scan
          </button>
        </div>
      </div>

      {storageError && <div className="alert alert-error" role="alert">{storageError}</div>}

      <div className="alert alert-info" style={{ marginBottom: '24px' }}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="16" x2="12" y2="12"/>
          <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
        <div>
          <strong>Privacy & Storage Notice:</strong> Scan reports are stored in this browser's <code>localStorage</code>. Storage can be unavailable, cleared, or evicted; reports are not backed up on a server.
        </div>
      </div>

      {history.length === 0 ? (
        <div className="card card-elevated" style={{ textAlign: 'center', padding: '64px 24px' }}>
          <div style={{ width: '56px', height: '56px', borderRadius: '50%', backgroundColor: 'var(--bg-surface)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px auto' }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--text-muted)' }}>
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12 6 12 12 16 14"/>
            </svg>
          </div>
          <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '8px' }}>No Saved Scans Found</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem', marginBottom: '24px', maxWidth: '440px', margin: '0 auto 24px auto' }}>
            Whenever you run an analysis on local dependency files or a public GitHub repository, results will appear here.
          </p>
          <button className="btn btn-primary" onClick={onNewScan}>
            Start New Scan
          </button>
        </div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Target / Repo</th>
                <th>Ecosystem</th>
                <th>Packages</th>
                <th>Vulnerabilities</th>
                <th>Risk Score</th>
                <th>Timestamp</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item) => (
                <tr key={item.id}>
                  <td>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{item.target.name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {item.target.type === 'github-repo' ? 'Public GitHub Repository' : 'Manual File Upload'} • {item.manifestType}
                    </div>
                  </td>
                  <td>
                    <span className={`badge ${item.ecosystem === 'npm' ? 'badge-eco-npm' : 'badge-eco-pypi'}`}>
                      {item.ecosystem}
                    </span>
                  </td>
                  <td>{item.totalPackages}</td>
                  <td>
                    {item.vulnerabilityCount > 0 ? (
                      <span style={{ color: 'var(--severity-critical)', fontWeight: 700 }}>
                        {item.vulnerabilityCount} advisory
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>0 advisories returned</span>
                    )}
                  </td>
                  <td>
                    <span className={`badge ${
                      item.riskTier === 'CRITICAL' ? 'badge-critical' :
                      item.riskTier === 'HIGH' ? 'badge-high' :
                      item.riskTier === 'MODERATE' ? 'badge-moderate' : 'badge-low'
                    }`}>
                      {item.riskTier} ({item.riskScore})
                    </span>
                  </td>
                  <td style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    {new Date(item.timestamp).toLocaleString()}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={(e) => { e.stopPropagation(); onSelectScan(item); }}
                      >
                        Open Report
                      </button>
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ color: 'var(--severity-critical)' }}
                        onClick={(e) => handleDelete(item.id, e)}
                        aria-label={`Delete scan ${item.target.name}`}
                      >
                        ✕
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
