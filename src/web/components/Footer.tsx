import React from 'react';

interface FooterProps {
  onOpenPreferences: () => void;
}

export const Footer: React.FC<FooterProps> = ({ onOpenPreferences }) => {
  return (
    <footer className="app-footer">
      <div className="app-footer-inner">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <img src="/veylix-icon.svg" alt="Veylix Icon" style={{ width: '20px', height: '20px' }} />
          <span style={{ fontWeight: 650, color: 'var(--text-primary)' }}>Veylix</span>
          <span style={{ color: 'var(--text-muted)' }}>— Scan. Secure. Stay Ahead.</span>
        </div>
        <div style={{ display: 'flex', gap: '14px', alignItems: 'center', flexWrap: 'wrap' }}>
          <a href="/settings">About & Settings</a>
          <a href="/privacy">Privacy</a>
          <a href="/terms">Terms</a>
          <a href="/cookies">Cookies & Storage</a>
          <a href="/support">Support</a>
          <button className="footer-preferences" type="button" onClick={onOpenPreferences}>
            Cookie & Storage Preferences
          </button>
        </div>
      </div>
    </footer>
  );
};
