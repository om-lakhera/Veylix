import React from 'react';
import { ActiveTab } from '../types.js';

interface HeaderProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  hasActiveResult: boolean;
  historyCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onTabChange,
  hasActiveResult,
  historyCount
}) => {
  return (
    <header className="top-navbar">
      <div className="top-navbar-inner">
        <button
          className="brand-section"
          type="button"
          onClick={() => onTabChange('dashboard')}
          title="Veylix — Scan. Secure. Stay Ahead."
          aria-label="Veylix overview"
        >
          <img
            src="/veylix-logo-horizontal.svg"
            alt="Veylix — Scan. Secure. Stay Ahead."
            className="brand-logo-img"
          />
          <span className="brand-badge">Free & Open</span>
        </button>

        <nav className="nav-links" aria-label="Main Navigation">
          <button
            className={`nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => onTabChange('dashboard')}
            aria-current={activeTab === 'dashboard' ? 'page' : undefined}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect width="7" height="9" x="3" y="3" rx="1"/>
              <rect width="7" height="5" x="14" y="3" rx="1"/>
              <rect width="7" height="9" x="14" y="12" rx="1"/>
              <rect width="7" height="5" x="3" y="16" rx="1"/>
            </svg>
            Overview
          </button>

          <button
            className={`nav-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => onTabChange('history')}
            aria-current={activeTab === 'history' ? 'page' : undefined}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12 6 12 12 16 14"/>
            </svg>
            Scans
            {historyCount > 0 && <span className="nav-counter">{historyCount}</span>}
          </button>

          <button
            className={`nav-btn ${activeTab === 'dependencies' ? 'active' : ''}`}
            onClick={() => onTabChange('dependencies')}
            aria-current={activeTab === 'dependencies' ? 'page' : undefined}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
              <polyline points="14 2 14 8 20 8"/>
              <path d="M8 13h8M8 17h5"/>
            </svg>
            Dependencies
          </button>

          <button
            className={`nav-btn ${activeTab === 'advisories' ? 'active' : ''}`}
            onClick={() => onTabChange('advisories')}
            aria-current={activeTab === 'advisories' ? 'page' : undefined}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 9v4"/>
              <path d="M12 17h.01"/>
              <path d="m10.3 3.86-8 14A2 2 0 0 0 4.03 21h15.94a2 2 0 0 0 1.73-3.14l-8-14a2 2 0 0 0-3.46 0Z"/>
            </svg>
            Advisories
          </button>

          <button
            className={`nav-btn ${activeTab === 'new-scan' ? 'active' : ''}`}
            onClick={() => onTabChange('new-scan')}
            aria-current={activeTab === 'new-scan' ? 'page' : undefined}
          >
            New Scan
          </button>

          {hasActiveResult && (
            <button
              className={`nav-btn ${activeTab === 'results' ? 'active' : ''}`}
              onClick={() => onTabChange('results')}
              aria-current={activeTab === 'results' ? 'page' : undefined}
            >
              Latest report
            </button>
          )}

          <button
            className={`nav-btn ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => onTabChange('about')}
            aria-current={activeTab === 'about' ? 'page' : undefined}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <path d="M12 16v-4"/>
              <path d="M12 8h.01"/>
            </svg>
            Settings
          </button>
        </nav>

        <div className="header-actions">
          <button
            className="btn btn-primary btn-sm"
            onClick={() => onTabChange('new-scan')}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M5 12h14"/>
              <path d="M12 5v14"/>
            </svg>
            New Scan
          </button>
        </div>
      </div>
    </header>
  );
};
