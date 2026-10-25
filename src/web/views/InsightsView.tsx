import React, { useMemo, useState } from 'react';
import { ScanHistoryItem } from '../types.js';

interface InsightsViewProps {
  history: ScanHistoryItem[];
  mode: 'dependencies' | 'advisories';
  onSelectScan: (item: ScanHistoryItem) => void;
}

const formatScan = (scan: ScanHistoryItem) =>
  `${scan.target.name} · ${new Date(scan.timestamp).toLocaleString()}`;

export const InsightsView: React.FC<InsightsViewProps> = ({ history, mode, onSelectScan }) => {
  const [selectedId, setSelectedId] = useState(history[0]?.id ?? '');
  const scan = history.find((item) => item.id === selectedId) ?? history[0];
  const packages = useMemo(() => scan?.report.packages ?? [], [scan]);
  const advisories = useMemo(
    () => packages.flatMap((pkg) => pkg.vulnerabilities.map((finding) => ({ pkg, finding }))),
    [packages]
  );
  const isDependencies = mode === 'dependencies';

  return (
    <section className="insights-page animate-in">
      <div className="insights-header">
        <div>
          <p className="overview-eyebrow">Scan-scoped data</p>
          <h1>{isDependencies ? 'Dependencies' : 'Advisories'}</h1>
          <p>
            {isDependencies
              ? 'Resolved packages retained in your saved scan reports.'
              : 'Vulnerability advisories returned for the selected saved scan.'}
          </p>
        </div>
        {history.length > 0 && (
          <label className="scan-picker">
            <span>Scan report</span>
            <select
              className="input-text"
              value={scan?.id ?? ''}
              onChange={(event) => setSelectedId(event.target.value)}
            >
              {history.map((item) => (
                <option key={item.id} value={item.id}>{formatScan(item)}</option>
              ))}
            </select>
          </label>
        )}
      </div>

      {!scan ? (
        <div className="card card-elevated insights-empty">
          <h2>No saved scan data</h2>
          <p>Run a dependency scan to see {isDependencies ? 'the resolved package inventory' : 'advisories returned for that scan'} here.</p>
        </div>
      ) : (
        <>
          <div className="insights-scan-meta">
            <span>{scan.ecosystem}</span>
            <span>{scan.totalPackages} resolved packages</span>
            <span>{scan.target.scannedFiles.join(', ')}</span>
            <button className="text-link" onClick={() => onSelectScan(scan)}>Open full report →</button>
          </div>

          {isDependencies ? (
            packages.length === 0 ? (
              <div className="card card-elevated insights-empty">
                <h2>No resolved packages</h2>
                <p>The selected report contains no resolved package entries. This is not a claim that unlisted dependencies are safe.</p>
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr><th scope="col">Package</th><th scope="col">Version</th><th scope="col">Ecosystem</th><th scope="col">Scope</th><th scope="col">Advisories</th><th scope="col">Maintenance</th></tr>
                  </thead>
                  <tbody>
                    {packages.map((pkg) => (
                      <tr key={`${pkg.name}@${pkg.version}`}>
                        <td className="pkg-name-cell">{pkg.name}</td>
                        <td><code>{pkg.version}</code></td>
                        <td>{pkg.ecosystem}</td>
                        <td><span className="badge badge-neutral">{pkg.isDirect ? 'Direct' : 'Transitive'}{pkg.isDev ? ' · Dev' : ''}</span></td>
                        <td>{pkg.vulnerabilities.length === 0
                          ? <span>No matching advisories returned</span>
                          : <button className="text-link" onClick={() => onSelectScan(scan)}>{pkg.vulnerabilities.length} advisory{pkg.vulnerabilities.length === 1 ? '' : 'ies'} · open report</button>}
                        </td>
                        <td>{pkg.maintenanceHealth?.status ?? 'Not checked'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          ) : (
            advisories.length === 0 ? (
              <div className="card card-elevated insights-empty">
                <h2>No advisories returned for this scan</h2>
                <p>This means the scan did not return matching OSV advisories for the resolved package versions; it is not a guarantee that the project is vulnerability-free.</p>
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr><th scope="col">Advisory</th><th scope="col">Package</th><th scope="col">Severity</th><th scope="col">Installed</th><th scope="col">Affected range</th><th scope="col">Fixed version</th></tr>
                  </thead>
                  <tbody>
                    {advisories.map(({ pkg, finding }) => (
                      <tr key={`${pkg.name}@${pkg.version}-${finding.advisoryId}`}>
                        <td>
                          <a href={`https://osv.dev/vulnerability/${encodeURIComponent(finding.advisoryId)}`} target="_blank" rel="noopener noreferrer">
                            {finding.advisoryId} <span aria-label="opens OSV in a new tab">↗</span>
                          </a>
                          <p className="advisory-summary">{finding.summary}</p>
                        </td>
                        <td>{pkg.name}</td>
                        <td><span className={`badge ${finding.severityLevel === 'CRITICAL' ? 'badge-critical' : finding.severityLevel === 'HIGH' ? 'badge-high' : finding.severityLevel === 'MODERATE' ? 'badge-moderate' : finding.severityLevel === 'LOW' ? 'badge-low' : 'badge-neutral'}`}>{finding.severityLevel}</span></td>
                        <td><code>{pkg.version}</code></td>
                        <td>{finding.affectedVersionRange ?? 'Not provided'}</td>
                        <td>{finding.fixedVersion ? <code>{finding.fixedVersion}</code> : 'Not provided'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}
        </>
      )}
    </section>
  );
};
