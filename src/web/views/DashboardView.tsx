import React from 'react';
import { ActiveTab, ScanHistoryItem } from '../types.js';

interface DashboardViewProps {
  history: ScanHistoryItem[];
  onNavigate: (tab: ActiveTab) => void;
  onSelectScan: (item: ScanHistoryItem) => void;
}

const severityItems = [
  { key: 'critical', label: 'Critical', className: 'severity-critical' },
  { key: 'high', label: 'High', className: 'severity-high' },
  { key: 'moderate', label: 'Moderate', className: 'severity-moderate' },
  { key: 'low', label: 'Low', className: 'severity-low' }
] as const;

const severityPriority = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  LOW: 1,
  UNKNOWN: 0
} as const;

const formatDate = (timestamp: string) =>
  new Date(timestamp).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short'
  });

export const DashboardView: React.FC<DashboardViewProps> = ({
  history,
  onNavigate,
  onSelectScan
}) => {
  const latestScan = history[0];
  const summary = latestScan?.report.summary;
  const findings = latestScan?.report.packages.flatMap((pkg) =>
    pkg.vulnerabilities.map((finding) => ({ pkg, finding }))
  ).sort((a, b) => severityPriority[b.finding.severityLevel] - severityPriority[a.finding.severityLevel]) ?? [];
  const maintenanceRisks = latestScan?.report.maintenanceRiskPackages ?? [];
  const hasPreviousScan = Boolean(latestScan);

  const nextSteps = hasPreviousScan
    ? findings.length > 0
      ? findings.slice(0, 3).map(({ pkg, finding }) => ({
          title: `${pkg.name}@${pkg.version}`,
          detail: finding.actionableRecommendation
        }))
      : maintenanceRisks.length > 0
        ? [{
            title: `Review ${maintenanceRisks.length} maintenance risk${maintenanceRisks.length === 1 ? '' : 's'}`,
            detail: 'Open scan results to review the package health signals.'
          }]
        : [{
            title: 'Review the analyzed packages',
            detail: 'No findings were detected in the files analyzed. Review the full report for coverage details.'
          }]
    : [
        { title: 'Choose a dependency file or repository to analyze', detail: '' },
        { title: 'Run your first scan', detail: '' },
        { title: 'Review findings and recommended fixes', detail: '' }
      ];

  return (
    <div className="overview-page animate-in">
      <div className="overview-heading">
        <div>
          <p className="overview-eyebrow">Veylix · Dependency security</p>
          <h1>Security Overview</h1>
        </div>
        <p className="overview-intro">
          Monitor dependency vulnerabilities, maintenance risks, and recommended fixes across your projects.
        </p>
      </div>

      <div className="overview-grid">
        <aside className="overview-column overview-column-left">
          <button
            className="project-summary"
            type="button"
            onClick={() => onNavigate('history')}
            aria-label={`Open scan history. ${history.length} saved scans.`}
          >
            <img src="/veylix-icon.svg" alt="" />
            <span>
              <strong>All projects</strong>
              <small>{history.length === 0 ? 'No scans yet' : `${history.length} saved scan${history.length === 1 ? '' : 's'}`}</small>
            </span>
            <span className="project-summary-count">{history.length}</span>
          </button>

          <section className="findings-count" aria-label="Findings in the latest scan">
            <strong>{summary ? summary.totalAdvisoriesCount : '—'}</strong>
            <span>Findings to review</span>
          </section>

          <section className="severity-card">
            <div className="overview-card-heading">
              <h2>Severity breakdown</h2>
              <span className="severity-card-label">Latest scan</span>
            </div>
            <div className="severity-grid">
              {severityItems.map(({ key, label, className }) => (
                <div className="severity-item" key={key}>
                  <strong className={className}>
                    {summary ? summary.severityCounts[key] : '—'}
                  </strong>
                  <span className={className}>
                    <i aria-hidden="true" />
                    {label}
                  </span>
                </div>
              ))}
            </div>
            {summary && summary.severityCounts.unknown > 0 && (
              <p className="severity-unknown">
                {summary.severityCounts.unknown}{summary.severityCounts.unknown === 1 ? ' advisory' : ' advisories'} with unknown severity
              </p>
            )}
          </section>
        </aside>

        <section className="overview-column overview-column-center" aria-label="Scan activity">
          <div className="overview-column-title">
            <h2>Scan activity</h2>
            <span>Latest scan and findings</span>
          </div>

          <article className="overview-card latest-scan-card">
            <div className="overview-card-heading">
              <h3>
                <span className="card-heading-icon" aria-hidden="true">◷</span>
                Latest scan
              </h3>
              <span className={`scan-status ${hasPreviousScan ? 'scan-status-complete' : ''}`}>
                {hasPreviousScan ? 'Completed' : 'No scans yet'}
              </span>
            </div>

            {latestScan ? (
              <>
                <button
                  type="button"
                  className="latest-scan-target"
                  onClick={() => onSelectScan(latestScan)}
                  title="Open the latest scan report"
                >
                  {latestScan.target.name}
                  {latestScan.target.branch && <span> · {latestScan.target.branch}</span>}
                </button>
                <div className="latest-scan-metrics">
                  <div>
                    <span>Scanned</span>
                    <strong>{latestScan.totalPackages} dependencies</strong>
                  </div>
                  <div>
                    <span>Files analyzed</span>
                    <strong>{latestScan.target.scannedFiles.length}</strong>
                  </div>
                  <div>
                    <span>Ecosystem</span>
                    <strong>{latestScan.ecosystem}</strong>
                  </div>
                  <div>
                    <span>Last run</span>
                    <strong>{formatDate(latestScan.timestamp)}</strong>
                  </div>
                </div>
                <div className="analyzed-files">
                  <span>Analyzed files</span>
                  <div>
                    {latestScan.target.scannedFiles.map((file) => (
                      <code key={file}>{file}</code>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div className="latest-scan-metrics latest-scan-metrics-empty">
                <div><span>Scanned</span><strong>—</strong></div>
                <div><span>Files analyzed</span><strong>—</strong></div>
                <div><span>Ecosystem</span><strong>—</strong></div>
              </div>
            )}

            <div className="latest-scan-footer">
              <span>{latestScan ? 'Ready to scan another project?' : 'Ready to scan?'}</span>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate('new-scan')}>
                {latestScan ? 'Run another scan' : 'Upload dependencies'}
              </button>
            </div>
          </article>

          <article className="overview-card onboarding-card">
            <span className="onboarding-label">{hasPreviousScan ? 'Keep your projects covered' : 'Get started'}</span>
            <h2>{hasPreviousScan ? 'Scan another project' : 'Ready to secure your dependencies?'}</h2>
            <p>
              {hasPreviousScan
                ? 'Check another dependency manifest or public GitHub repository for known vulnerabilities and maintenance risks.'
                : 'Start a scan to discover known vulnerabilities and review dependency maintenance health.'}
            </p>
            <div className="onboarding-checks">
              <div><span>Checks</span><strong>Known vulnerabilities</strong></div>
              <div><span>Reviews</span><strong>Maintenance health</strong></div>
              <div><span>Returns</span><strong>Recommended fixes</strong></div>
            </div>
            <div className="onboarding-actions">
              <button className="btn btn-primary btn-sm" onClick={() => onNavigate('new-scan')}>
                <span aria-hidden="true">＋</span> New scan
              </button>
              <button className="btn btn-quiet btn-sm" onClick={() => onNavigate('new-scan')}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5"/>
                  <path d="M9 18c-4.51 2-5-2-7-2"/>
                </svg>
                Scan a public GitHub repository
              </button>
            </div>
          </article>

          <article className="overview-card finding-preview-card">
            <div className="overview-card-heading">
              <h2>
                <span className="preview-warning" aria-hidden="true">△</span>
                Finding preview
              </h2>
              {latestScan && (
                <button className="text-link" onClick={() => onSelectScan(latestScan)}>
                  View report
                </button>
              )}
            </div>
            <p className="preview-caption">
              {latestScan ? `From ${latestScan.target.name}` : 'After your first scan'}
            </p>
            {findings.length > 0 ? (
              <div className="finding-preview-list">
                {findings.slice(0, 3).map(({ pkg, finding }) => (
                  <button
                    className="finding-preview-row"
                    type="button"
                    key={`${pkg.name}@${pkg.version}-${finding.advisoryId}`}
                    onClick={() => {
                      if (latestScan) onSelectScan(latestScan);
                    }}
                  >
                    <span>
                      <strong>{pkg.name}<small>@{pkg.version}</small></strong>
                      <small>{finding.advisoryId}</small>
                      <small className="finding-preview-fix">
                        {finding.fixedVersion ? `Fixed in ${finding.fixedVersion}` : 'No fix known'}
                      </small>
                    </span>
                    <span className={`finding-severity ${finding.severityLevel.toLowerCase()}`}>
                      {finding.severityLevel}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <div className="finding-preview-empty">
                <div><span>Package</span><strong>—</strong></div>
                <div><span>Advisory</span><strong>—</strong></div>
                <div><span>Fixed in</span><strong>—</strong></div>
                <p>
                  {latestScan
                    ? 'No findings detected in the files analyzed.'
                    : 'Findings appear here once a scan has results.'}
                </p>
              </div>
            )}
          </article>
        </section>

        <aside className="overview-column overview-column-right">
          <section className="next-steps">
            <div className="next-steps-heading">
              <span className="next-steps-indicator" aria-hidden="true" />
              <h2>{hasPreviousScan && findings.length > 0 ? 'Recommended fixes' : 'Next steps'}</h2>
            </div>
            <ol>
              {nextSteps.map((step, index) => (
                <li key={`${step.title}-${index}`}>
                  <span className="step-number">{index + 1}</span>
                  <div>
                    <strong>{step.title}</strong>
                    {step.detail && <p>{step.detail}</p>}
                  </div>
                </li>
              ))}
            </ol>
            {hasPreviousScan && (
              <button className="text-link next-steps-link" onClick={() => onSelectScan(latestScan)}>
                Open latest report <span aria-hidden="true">→</span>
              </button>
            )}
          </section>

          <button
            className="dependency-upload-card"
            type="button"
            onClick={() => onNavigate('new-scan')}
          >
            <span className="upload-card-label">Upload dependencies</span>
            <strong>Drop a dependency file to scan</strong>
            <span className="upload-card-icon" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 16V4m-4 4 4-4 4 4"/>
                <path d="M20 16.5v2A1.5 1.5 0 0 1 18.5 20h-13A1.5 1.5 0 0 1 4 18.5v-2"/>
              </svg>
            </span>
          </button>
        </aside>
      </div>
    </div>
  );
};
