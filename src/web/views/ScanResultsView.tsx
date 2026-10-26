import React, { useState, useMemo } from 'react';
import { AnalysisReport, AnalyzedPackage, VulnerabilityFinding } from '../../types.js';
import { ScanTargetInfo, calculateRiskScore } from '../types.js';
import { downloadJsonFile } from '../services/storage.js';
import { copyUpgradeCommand, generateUpgradeCommand } from '../services/remediation.js';
import { buildDependencyGraph } from '../services/dependency-graph.js';

interface ScanResultsViewProps {
  target: ScanTargetInfo;
  report: AnalysisReport;
  onNewScan: () => void;
}

type SeverityFilter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'MAINTENANCE_ONLY';
type DependencyScopeFilter = 'ALL' | 'DIRECT' | 'TRANSITIVE';
type SortOption = 'SEVERITY' | 'PACKAGE_NAME' | 'FIX_AVAILABLE';

const CopyUpgradeCommand: React.FC<{ command: string }> = ({ command }) => {
  const [status, setStatus] = useState('');

  const copyCommand = async () => {
    const result = await copyUpgradeCommand(command, navigator.clipboard);
    if (result === 'unavailable') {
      setStatus('Copy is unavailable in this browser context. Select and copy the command manually.');
      return;
    }
    if (result === 'copied') {
      setStatus('Command copied.');
    } else {
      setStatus('Could not copy the command. Select and copy it manually.');
    }
  };

  return (
    <div className="upgrade-command">
      <code>{command}</code>
      <button className="btn btn-secondary btn-sm" type="button" onClick={copyCommand}>
        Copy command
      </button>
      <span className="copy-status" role="status" aria-live="polite">{status}</span>
    </div>
  );
};

export const ScanResultsView: React.FC<ScanResultsViewProps> = ({
  target,
  report,
  onNewScan
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [scopeFilter, setScopeFilter] = useState<DependencyScopeFilter>('ALL');
  const [sortOption, setSortOption] = useState<SortOption>('SEVERITY');
  const [expandedPkgKeys, setExpandedPkgKeys] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'maintenance' | 'recommendations' | 'dependencies' | 'all-packages'>('vulnerabilities');

  const risk = calculateRiskScore(report);
  const { summary } = report;
  const dependencyGraph = useMemo(() => buildDependencyGraph(report), [report]);

  const toggleExpand = (key: string) => {
    setExpandedPkgKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  // Filtered & sorted vulnerability list
  const filteredPackages = useMemo(() => {
    return report.packages.filter((pkg) => {
      // 1. Search Query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const nameMatches = pkg.name.toLowerCase().includes(query);
        const vulnMatches = pkg.vulnerabilities.some(
          (v) =>
            v.advisoryId.toLowerCase().includes(query) ||
            v.summary.toLowerCase().includes(query) ||
            v.aliases.some((a) => a.toLowerCase().includes(query))
        );
        if (!nameMatches && !vulnMatches) return false;
      }

      // 2. Scope Filter
      if (scopeFilter === 'DIRECT' && !pkg.isDirect) return false;
      if (scopeFilter === 'TRANSITIVE' && pkg.isDirect) return false;

      // 3. Severity / Category Filter
      if (severityFilter === 'MAINTENANCE_ONLY') {
        return pkg.maintenanceHealth?.status === 'MAINTENANCE_RISK';
      }

      if (severityFilter !== 'ALL') {
        const hasMatchingVuln = pkg.vulnerabilities.some((v) => v.severityLevel === severityFilter);
        if (!hasMatchingVuln) return false;
      }

      return true;
    }).sort((a, b) => {
      if (sortOption === 'PACKAGE_NAME') {
        return a.name.localeCompare(b.name);
      }

      if (sortOption === 'FIX_AVAILABLE') {
        const aHasFix = a.vulnerabilities.some((v) => Boolean(v.fixedVersion));
        const bHasFix = b.vulnerabilities.some((v) => Boolean(v.fixedVersion));
        if (aHasFix && !bHasFix) return -1;
        if (!aHasFix && bHasFix) return 1;
      }

      // Default: Highest severity first
      const getWeight = (pkg: AnalyzedPackage) => {
        if (pkg.vulnerabilities.some((v) => v.severityLevel === 'CRITICAL')) return 4;
        if (pkg.vulnerabilities.some((v) => v.severityLevel === 'HIGH')) return 3;
        if (pkg.vulnerabilities.some((v) => v.severityLevel === 'MODERATE')) return 2;
        if (pkg.vulnerabilities.some((v) => v.severityLevel === 'LOW')) return 1;
        if (pkg.maintenanceHealth?.status === 'MAINTENANCE_RISK') return 0.5;
        return 0;
      };

      return getWeight(b) - getWeight(a);
    });
  }, [report.packages, searchQuery, scopeFilter, severityFilter, sortOption]);

  // Packages with vulnerabilities
  const vulnerableList = useMemo(() => {
    return filteredPackages.filter((p) => p.hasVulnerability);
  }, [filteredPackages]);

  // Maintenance risk packages
  const maintenanceRiskList = useMemo(() => {
    return report.packages.filter((p) => p.maintenanceHealth?.status === 'MAINTENANCE_RISK');
  }, [report.packages]);

  // Handle Export JSON
  const handleExportJson = () => {
    const filename = `veylix_report_${target.name.replace(/[^a-zA-Z0-9_-]/g, '_')}_${Date.now()}.json`;
    downloadJsonFile(filename, report);
  };

  // Handle Print
  const handlePrintReport = () => {
    window.print();
  };

  return (
    <div className="animate-in">
      {/* Target & Action Bar */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <span className={`badge ${summary.ecosystem === 'npm' ? 'badge-eco-npm' : 'badge-eco-pypi'}`}>
              {summary.ecosystem.toUpperCase()}
            </span>
            <span className="badge badge-neutral">
              {summary.manifestType} {summary.lockfileVersion ? `(v${summary.lockfileVersion})` : ''}
            </span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Scanned in {summary.scanDurationMs}ms • {new Date(summary.timestamp).toLocaleString()}
            </span>
          </div>
          <h1 style={{ fontSize: '2rem', fontWeight: 800, letterSpacing: '-0.03em' }}>
            {target.name} {target.branch ? `(${target.branch})` : ''}
          </h1>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Files analyzed: {target.scannedFiles.join(', ')}
          </div>
        </div>

        <div className="header-actions">
          <button className="btn btn-secondary btn-sm" onClick={handleExportJson}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            Export JSON
          </button>
          <button className="btn btn-secondary btn-sm" onClick={handlePrintReport}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 6 2 18 2 18 9"/>
              <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>
              <rect width="12" height="8" x="6" y="14"/>
            </svg>
            Print / PDF
          </button>
          <button className="btn btn-primary btn-sm" onClick={onNewScan}>
            New Scan
          </button>
        </div>
      </div>

      {/* Warnings Banner if any */}
      {report.warnings.length > 0 && (
        <div className="alert alert-warning" style={{ marginBottom: '24px' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: '2px' }}>
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <div>
            <div style={{ fontWeight: 700, marginBottom: '4px' }}>Parser Notices & Warnings:</div>
            <ul style={{ paddingLeft: '18px', fontSize: '0.88rem' }}>
              {report.warnings.map((w, idx) => (
                <li key={idx}>{w}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Executive Risk Score Card */}
      <div className="risk-score-card" style={{ boxShadow: 'var(--shadow-md)' }}>
        <div className="risk-score-left">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className={`risk-score-pill ${risk.badgeClass}`}>
              ● {risk.label}
            </span>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Deterministic Veylix Risk Prioritization
            </span>
          </div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800 }}>
            {summary.vulnerablePackagesCount === 0 && (summary.maintenanceRisksCount || 0) === 0
              ? 'Zero Known Advisories Detected'
              : `${summary.totalAdvisoriesCount} Security Vulnerabilit${summary.totalAdvisoriesCount === 1 ? 'y' : 'ies'} Found`}
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem', maxWidth: '680px' }}>
            {summary.vulnerablePackagesCount === 0
              ? 'No matching vulnerability records found in Google OSV for these resolved dependency versions.'
              : `${summary.vulnerablePackagesCount} of ${summary.totalUniquePackages} unique packages have active security advisories. Follow the prioritized actions below.`}
          </p>
        </div>

        <div className="risk-score-circle" style={{ borderColor: risk.colorVar }}>
          <span className="risk-score-number" style={{ color: risk.colorVar }}>{risk.score}</span>
          <span className="risk-score-max">/ 100 RISK</span>
        </div>
      </div>

      {/* Stats Breakdown Bar */}
      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-label">Unique Packages</span>
          <span className="stat-value">{summary.totalUniquePackages}</span>
          <span className="stat-hint">{summary.directDependenciesCount} direct / {summary.totalDependenciesResolved} total</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Critical Severity</span>
          <span className="stat-value" style={{ color: summary.severityCounts.critical > 0 ? 'var(--severity-critical)' : 'inherit' }}>
            {summary.severityCounts.critical}
          </span>
          <span className="stat-hint">CVSS ≥ 9.0</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">High Severity</span>
          <span className="stat-value" style={{ color: summary.severityCounts.high > 0 ? 'var(--severity-high)' : 'inherit' }}>
            {summary.severityCounts.high}
          </span>
          <span className="stat-hint">CVSS 7.0 - 8.9</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Moderate / Low</span>
          <span className="stat-value">
            {summary.severityCounts.moderate + summary.severityCounts.low}
          </span>
          <span className="stat-hint">{summary.severityCounts.moderate} mod / {summary.severityCounts.low} low</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">Maintenance Risks</span>
          <span className="stat-value" style={{ color: (summary.maintenanceRisksCount || 0) > 0 ? 'var(--severity-high)' : 'inherit' }}>
            {summary.maintenanceRisksCount ?? 'N/A'}
          </span>
          <span className="stat-hint">{summary.deprecatedPackagesCount ? `${summary.deprecatedPackagesCount} deprecated` : 'OpenSSF checks'}</span>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="tab-group" style={{ marginBottom: '20px' }}>
        <button
          className={`tab-btn ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
          onClick={() => setActiveTab('vulnerabilities')}
        >
          Security Vulnerabilities ({report.vulnerablePackages.length})
        </button>

        <button
          className={`tab-btn ${activeTab === 'recommendations' ? 'active' : ''}`}
          onClick={() => setActiveTab('recommendations')}
        >
          Actionable Next Steps
        </button>

        <button
          className={`tab-btn ${activeTab === 'maintenance' ? 'active' : ''}`}
          onClick={() => setActiveTab('maintenance')}
        >
          Maintenance Health ({maintenanceRiskList.length} risks)
        </button>

        <button
          className={`tab-btn ${activeTab === 'dependencies' ? 'active' : ''}`}
          onClick={() => setActiveTab('dependencies')}
        >
          Dependency Explorer
        </button>

        <button
          className={`tab-btn ${activeTab === 'all-packages' ? 'active' : ''}`}
          onClick={() => setActiveTab('all-packages')}
        >
          All Scanned Packages ({report.packages.length})
        </button>
      </div>

      {/* TAB 1: SECURITY VULNERABILITIES */}
      {activeTab === 'vulnerabilities' && (
        <div>
          {/* Search & Filter Toolbar */}
          <div className="filter-toolbar">
            <div className="filter-left">
              <div className="search-input-wrap">
                <input
                  type="text"
                  className="input-text input-sm"
                  style={{ padding: '8px 12px', fontSize: '0.85rem' }}
                  placeholder="Filter by package, CVE, or keyword..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>

              <div className="filter-pills">
                <button
                  className={`pill-filter-btn ${severityFilter === 'ALL' ? 'active' : ''}`}
                  onClick={() => setSeverityFilter('ALL')}
                >
                  All ({summary.totalAdvisoriesCount})
                </button>
                <button
                  className={`pill-filter-btn ${severityFilter === 'CRITICAL' ? 'active' : ''}`}
                  onClick={() => setSeverityFilter('CRITICAL')}
                >
                  Critical ({summary.severityCounts.critical})
                </button>
                <button
                  className={`pill-filter-btn ${severityFilter === 'HIGH' ? 'active' : ''}`}
                  onClick={() => setSeverityFilter('HIGH')}
                >
                  High ({summary.severityCounts.high})
                </button>
                <button
                  className={`pill-filter-btn ${severityFilter === 'MODERATE' ? 'active' : ''}`}
                  onClick={() => setSeverityFilter('MODERATE')}
                >
                  Moderate ({summary.severityCounts.moderate})
                </button>
                <button
                  className={`pill-filter-btn ${severityFilter === 'LOW' ? 'active' : ''}`}
                  onClick={() => setSeverityFilter('LOW')}
                >
                  Low ({summary.severityCounts.low})
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <select
                className="input-text"
                style={{ padding: '6px 10px', fontSize: '0.82rem', width: 'auto' }}
                value={scopeFilter}
                onChange={(e) => setScopeFilter(e.target.value as DependencyScopeFilter)}
              >
                <option value="ALL">All Scopes</option>
                <option value="DIRECT">Direct Only</option>
                <option value="TRANSITIVE">Transitive Only</option>
              </select>

              <select
                className="input-text"
                style={{ padding: '6px 10px', fontSize: '0.82rem', width: 'auto' }}
                value={sortOption}
                onChange={(e) => setSortOption(e.target.value as SortOption)}
              >
                <option value="SEVERITY">Highest Severity</option>
                <option value="PACKAGE_NAME">Package Name</option>
                <option value="FIX_AVAILABLE">Fix Available First</option>
              </select>
            </div>
          </div>

          {vulnerableList.length === 0 ? (
            <div className="card card-elevated" style={{ textAlign: 'center', padding: '52px 24px' }}>
              <div style={{ width: '48px', height: '48px', borderRadius: '50%', backgroundColor: 'rgba(52, 211, 153, 0.12)', color: 'var(--severity-low)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px auto' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
              </div>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '6px' }}>
                {report.vulnerablePackages.length === 0 ? 'No Vulnerabilities Detected' : 'No Matches for Current Filters'}
              </h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', maxWidth: '440px', margin: '0 auto' }}>
                {report.vulnerablePackages.length === 0
                  ? 'All analyzed packages resolved cleanly with zero known OSV vulnerability advisories.'
                  : 'Try clearing your search keyword or switching severity filters.'}
              </p>
            </div>
          ) : (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Severity</th>
                    <th>Advisory ID & Summary</th>
                    <th>Installed</th>
                    <th>Fixed Version</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerableList.map((pkg) => {
                    const key = `${pkg.name}@${pkg.version}`;
                    const isExpanded = expandedPkgKeys.has(key);

                    return (
                      <React.Fragment key={key}>
                        <tr>
                          <td>
                            <div className="pkg-name-cell">{pkg.name}</div>
                            <div style={{ display: 'flex', gap: '6px', marginTop: '4px' }}>
                              <span className="pkg-version-tag">{pkg.version}</span>
                              <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
                                {pkg.isDirect ? 'Direct' : 'Transitive'}
                              </span>
                            </div>
                          </td>

                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              {pkg.vulnerabilities.map((v) => (
                                <span
                                  key={v.advisoryId}
                                  className={`badge ${
                                    v.severityLevel === 'CRITICAL' ? 'badge-critical' :
                                    v.severityLevel === 'HIGH' ? 'badge-high' :
                                    v.severityLevel === 'MODERATE' ? 'badge-moderate' : 'badge-low'
                                  }`}
                                >
                                  {v.severityLevel}
                                </span>
                              ))}
                            </div>
                          </td>

                          <td>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                              {pkg.vulnerabilities.map((v) => (
                                <div key={v.advisoryId}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                                    <a
                                      href={`https://osv.dev/vulnerability/${v.advisoryId}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}
                                    >
                                      {v.advisoryId} ↗
                                    </a>
                                    {v.aliases.length > 0 && (
                                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                        ({v.aliases.join(', ')})
                                      </span>
                                    )}
                                  </div>
                                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                    {v.summary}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </td>

                          <td style={{ fontFamily: 'var(--font-mono)' }}>
                            {pkg.version}
                          </td>

                          <td>
                            {pkg.vulnerabilities.map((v) => (
                              <div key={v.advisoryId} style={{ marginBottom: '6px' }}>
                                {v.fixedVersion ? (
                                  <span className="badge badge-low" style={{ fontFamily: 'var(--font-mono)' }}>
                                    ≥ {v.fixedVersion}
                                  </span>
                                ) : (
                                  <span className="badge badge-neutral">No fix known</span>
                                )}
                              </div>
                            ))}
                          </td>

                          <td>
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => toggleExpand(key)}
                            >
                              {isExpanded ? 'Hide Details' : 'View Details'}
                            </button>
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr className="table-expand-row">
                            <td colSpan={6}>
                              <div className="expand-details-box">
                                <h4 style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                                  Detailed Advisory & Dependency Chain: {pkg.name}@{pkg.version}
                                </h4>

                                {pkg.dependencyPaths.length > 0 && (
                                  <div>
                                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)' }}>
                                      Dependency Path:
                                    </span>
                                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                                      {pkg.dependencyPaths.join(' | ')}
                                    </div>
                                  </div>
                                )}

                                {pkg.vulnerabilities.map((v) => (
                                  <div
                                    key={v.advisoryId}
                                    style={{
                                      padding: '12px 14px',
                                      backgroundColor: 'var(--bg-surface)',
                                      borderRadius: 'var(--radius-sm)',
                                      border: '1px solid var(--border-subtle)',
                                      display: 'flex',
                                      flexDirection: 'column',
                                      gap: '8px'
                                    }}
                                  >
                                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                                        {v.advisoryId}
                                      </span>
                                      {v.cvssScore && (
                                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                                          Score: {v.cvssScore}
                                        </span>
                                      )}
                                    </div>

                                    {v.affectedVersionRange && (
                                      <div style={{ fontSize: '0.82rem' }}>
                                        <span style={{ color: 'var(--text-muted)' }}>Affected Ranges: </span>
                                        <code>{v.affectedVersionRange}</code>
                                      </div>
                                    )}

                                    <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                                      {v.details || v.summary}
                                    </div>

                                    <div style={{ fontSize: '0.85rem', color: 'var(--brand-primary)', fontWeight: 600, marginTop: '4px' }}>
                                      Action: {v.actionableRecommendation}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: ACTIONABLE RECOMMENDATIONS */}
      {activeTab === 'recommendations' && (
        <div className="card card-elevated">
          <div className="card-header">
            <h3 className="card-title">Prioritized Remediation Checklist</h3>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Deterministic upgrade guidance grounded in official advisory data
            </span>
          </div>

          {vulnerableList.length === 0 && maintenanceRiskList.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '36px 20px', color: 'var(--text-secondary)' }}>
              No critical remediation required. Your dependency manifest has no active vulnerability advisories.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Critical / High CVEs */}
              {vulnerableList.map((pkg) => {
                const fixCandidates = pkg.vulnerabilities.filter((finding) => Boolean(finding.fixedVersion));
                const fixCandidate = fixCandidates.find((finding) =>
                  Boolean(generateUpgradeCommand(pkg.ecosystem, pkg.name, finding.fixedVersion).command)
                ) ?? fixCandidates[0];
                const upgrade = generateUpgradeCommand(pkg.ecosystem, pkg.name, fixCandidate?.fixedVersion);
                return (
                  <div
                    key={`${pkg.name}@${pkg.version}`}
                    style={{
                      padding: '16px',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'var(--bg-surface)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="pkg-name-cell">{pkg.name}</span>
                        <span className="pkg-version-tag">current: {pkg.version}</span>
                        <span className="badge badge-neutral">{pkg.isDirect ? 'Direct' : 'Transitive'}</span>
                      </div>
                      <span className={`badge ${
                        pkg.vulnerabilities.some((v) => v.severityLevel === 'CRITICAL') ? 'badge-critical' :
                        pkg.vulnerabilities.some((v) => v.severityLevel === 'HIGH') ? 'badge-high' : 'badge-moderate'
                      }`}>
                        {pkg.vulnerabilities.length} Advisory{pkg.vulnerabilities.length === 1 ? '' : 'ies'}
                      </span>
                    </div>

                    <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
                      {pkg.vulnerabilities.map((v) => `${v.advisoryId}: ${v.actionableRecommendation}`).join(' ')}
                    </p>

                    {fixCandidate?.fixedVersion && upgrade.command ? (
                      <div>
                        <p className="remediation-note">
                          OSV records <code>{fixCandidate.fixedVersion}</code> as a fixed version for advisory{' '}
                          <code>{fixCandidate.advisoryId}</code>. Review and test this exact-version suggestion. It does
                          not imply that all advisories or dependency paths for this package are resolved.
                        </p>
                        <CopyUpgradeCommand command={upgrade.command} />
                      </div>
                    ) : fixCandidate?.fixedVersion ? (
                      <p className="remediation-note" role="status">
                        A fixed version is recorded, but no safe command can be generated: {upgrade.reason}
                      </p>
                    ) : (
                      <div className="remediation-note" role="status">
                        No verified fixed version was found in the returned advisory data. Review the advisory and
                        assess mitigations; Veylix will not guess an upgrade target.
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Deprecated or unmaintained packages */}
              {maintenanceRiskList.map((pkg) => (
                <div
                  key={`maint_${pkg.name}@${pkg.version}`}
                  style={{
                    padding: '16px',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="pkg-name-cell">{pkg.name}</span>
                      <span className="pkg-version-tag">{pkg.version}</span>
                    </div>
                    <span className="badge badge-high">Maintenance Risk</span>
                  </div>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {pkg.maintenanceHealth?.signals.join(' • ')}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'dependencies' && (
        <section className="card card-elevated dependency-explorer" aria-labelledby="dependency-explorer-title">
          <div className="card-header">
            <div>
              <h2 className="card-title" id="dependency-explorer-title">Dependency relationships</h2>
              <p className="dependency-explorer-intro">
                Relationships are shown only when a lockfile path names each package with an exact version.
                Package scope labels alone are not used to infer parent-child edges.
              </p>
            </div>
          </div>

          {dependencyGraph.truncated && (
            <p className="alert alert-warning" role="status">
              The explorer reached its processing limit. Displayed paths may be incomplete.
            </p>
          )}

          {!dependencyGraph.available ? (
            <div className="dependency-graph-unavailable" role="status">
              <h3>No reliable parent-child paths available</h3>
              <p>
                This scan contains package inventory data, but its parser did not provide version-qualified
                dependency paths that can be safely reconstructed as relationships. Direct/transitive labels
                remain parser metadata and are not expanded into a graph here.
              </p>
              {dependencyGraph.nodes.some((node) => node.isVulnerable && node.isDirect) && (
                <ul>
                  {dependencyGraph.nodes.filter((node) => node.isVulnerable && node.isDirect).map((node) => (
                    <li key={node.id}>Direct vulnerable dependency: <code>{node.name}@{node.version}</code></li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <>
              {dependencyGraph.cycleDetected && (
                <p className="alert alert-warning" role="status">
                  A cycle was present in the relationship data. Traversal stopped at visited nodes.
                </p>
              )}
              <h3 className="dependency-section-title">Verified parent-child relationships</h3>
              <div className="table-container">
                <table className="data-table">
                  <thead><tr><th scope="col">Parent</th><th scope="col">Dependency</th><th scope="col">Status</th></tr></thead>
                  <tbody>
                    {dependencyGraph.edges.map((edge) => {
                      const parent = dependencyGraph.nodes.find((node) => node.id === edge.from);
                      const child = dependencyGraph.nodes.find((node) => node.id === edge.to);
                      if (!parent || !child) return null;
                      return (
                        <tr key={`${edge.from}->${edge.to}`}>
                          <td><code>{parent.name}@{parent.version}</code></td>
                          <td><code>{child.name}@{child.version}</code></td>
                          <td>{child.isVulnerable ? <span className="badge badge-critical">Vulnerable</span> : 'Resolved package'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <h3 className="dependency-section-title">Paths to vulnerable dependencies</h3>
              {dependencyGraph.vulnerablePaths.length === 0 ? (
                <p>No direct-to-vulnerable paths were reconstructed from the available exact-version paths.</p>
              ) : (
                <ul className="vulnerability-path-list">
                  {dependencyGraph.vulnerablePaths.map((path, index) => (
                    <li key={`${path.map((node) => node.id).join('>')}-${index}`}>
                      <ol aria-label={`Vulnerability path ${index + 1}`}>
                        {path.map((node) => (
                          <li key={node.id}>
                            <code>{node.name}@{node.version}</code>
                            <span className="badge badge-neutral">{node.isDirect ? 'Direct' : 'Transitive'}</span>
                            {node.isVulnerable && <span className="badge badge-critical">Vulnerable</span>}
                          </li>
                        ))}
                      </ol>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </section>
      )}

      {/* TAB 3: MAINTENANCE HEALTH */}
      {activeTab === 'maintenance' && (
        <div className="card card-elevated">
          <div className="card-header">
            <div>
              <h3 className="card-title">OpenSSF Scorecard & deps.dev Vitality Indicators</h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Evaluates project maintenance vitality independently from security advisories.
              </p>
            </div>
            <span className="badge badge-neutral">Max 30 Direct Dependencies</span>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <div className="alert alert-info">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="16" x2="12" y2="12"/>
                <line x1="12" y1="8" x2="12.01" y2="8"/>
              </svg>
              <div>
                <strong>Transparency Note:</strong> A status of <code>DATA_UNAVAILABLE</code> or <code>UNKNOWN</code> indicates that the open-source registry or OpenSSF has not computed a Scorecard for this package yet. Veylix strictly separates missing telemetry from verified healthy indicators.
              </div>
            </div>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Status</th>
                  <th>Scorecard</th>
                  <th>Maintained Score</th>
                  <th>Deprecated?</th>
                  <th>Signals & Evidence</th>
                </tr>
              </thead>
              <tbody>
                {report.packages
                  .filter((p) => p.isDirect || p.maintenanceHealth)
                  .map((pkg) => {
                    const health = pkg.maintenanceHealth;
                    return (
                      <tr key={`${pkg.name}@${pkg.version}`}>
                        <td>
                          <div className="pkg-name-cell">{pkg.name}</div>
                          <span className="pkg-version-tag">{pkg.version}</span>
                        </td>
                        <td>
                          {health?.status === 'ACTIVE' && (
                            <span className="badge badge-low">Active</span>
                          )}
                          {health?.status === 'MAINTENANCE_RISK' && (
                            <span className="badge badge-critical">Maintenance Risk</span>
                          )}
                          {health?.status === 'DATA_UNAVAILABLE' && (
                            <span className="badge badge-neutral">Unavailable</span>
                          )}
                          {(!health || health?.status === 'UNKNOWN') && (
                            <span className="badge badge-neutral">Unknown</span>
                          )}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>
                          {health?.scorecardScore !== null && health?.scorecardScore !== undefined
                            ? `${health.scorecardScore.toFixed(1)} / 10`
                            : '—'}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>
                          {health?.maintainedScore !== null && health?.maintainedScore !== undefined
                            ? `${health.maintainedScore.toFixed(1)} / 10`
                            : '—'}
                        </td>
                        <td>
                          {health?.isDeprecated ? (
                            <span className="badge badge-critical">Yes</span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>No</span>
                          )}
                        </td>
                        <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                          {health?.signals && health.signals.length > 0
                            ? health.signals.join(' • ')
                            : 'Direct dependency evaluated'}
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: ALL PACKAGES */}
      {activeTab === 'all-packages' && (
        <div className="card card-elevated">
          <div className="card-header">
            <h3 className="card-title">Full Dependency Inventory ({report.packages.length} packages)</h3>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Resolved from {summary.manifestType}
            </span>
          </div>

          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Package Name</th>
                  <th>Version</th>
                  <th>Scope</th>
                  <th>Vulnerabilities</th>
                  <th>Maintenance</th>
                </tr>
              </thead>
              <tbody>
                {report.packages.map((pkg) => (
                  <tr key={`${pkg.name}@${pkg.version}`}>
                    <td className="pkg-name-cell">{pkg.name}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{pkg.version}</td>
                    <td>
                      <span className="badge badge-neutral">
                        {pkg.isDirect ? 'Direct' : 'Transitive'}
                      </span>
                    </td>
                    <td>
                      {pkg.hasVulnerability ? (
                        <span style={{ color: 'var(--severity-critical)', fontWeight: 700 }}>
                          {pkg.vulnerabilities.length} advisory
                        </span>
                      ) : (
                        <span style={{ color: 'var(--severity-low)' }}>0 clean</span>
                      )}
                    </td>
                    <td>
                      {pkg.maintenanceHealth ? (
                        <span className={`badge ${pkg.maintenanceHealth.status === 'MAINTENANCE_RISK' ? 'badge-critical' : 'badge-neutral'}`}>
                          {pkg.maintenanceHealth.status}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
