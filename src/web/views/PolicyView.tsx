import React from 'react';
import { ActiveTab } from '../types.js';

interface PolicyViewProps {
  page: Extract<ActiveTab, 'privacy' | 'terms' | 'cookies' | 'support'>;
}

const pageCopy = {
  privacy: {
    title: 'Privacy Policy',
    intro: 'This draft describes the behavior visible in this Veylix build. The operator identity, jurisdiction, and private privacy contact are not configured; hosting log settings and retention have not been verified. The service owner must complete and review these details before public launch.'
  },
  terms: {
    title: 'Terms of Service',
    intro: 'Draft terms for review by the service operator and qualified legal counsel. No operator identity, governing jurisdiction, or effective date is configured in this repository.'
  },
  cookies: {
    title: 'Cookie Policy',
    intro: 'This application does not currently integrate analytics, advertising, or other optional tracking cookies. Browser storage is used for scan reports and is described below.'
  },
  support: {
    title: 'Contact & Support',
    intro: 'No dedicated support address or contact endpoint is configured. The source repository is the only support channel currently discoverable from this build.'
  }
} as const;

export const PolicyView: React.FC<PolicyViewProps> = ({ page }) => (
  <article className="policy-page animate-in">
    <p className="overview-eyebrow">Veylix · Information</p>
    <h1>{pageCopy[page].title}</h1>
    <p className="policy-intro">{pageCopy[page].intro}</p>

    {page === 'privacy' && (
      <>
        <section><h2>Information processed for a scan</h2>
          <p>When you upload a dependency manifest, its text is sent to Veylix's same-origin scan API when that API is reachable. If the API cannot be reached or returns 404, the file-scan client can run the existing engine in your browser instead. The parser extracts package names and versions; those identifiers and versions are sent to the OSV vulnerability API. Maintenance checks are enabled by default in the scan form and can be turned off; when enabled, package identifiers are also used to request package-health data from deps.dev. Manifest text itself is not sent to OSV or deps.dev.</p>
          <p>For GitHub scans, the repository reference you submit is sent to Veylix's API. The server fetches supported manifests from GitHub's raw-content host, then queries OSV and, optionally, deps.dev. Only public GitHub repositories are supported; do not submit private repository URLs or files containing secrets.</p>
        </section>
        <section><h2>Browser storage and deletion</h2>
          <p>Successful scan reports are saved in this browser's local storage. History keeps at most 25 reports; when full, saving another report removes the oldest one. Reports include scan time, target/repository name, selected manifest names, package names and versions, and findings. You can delete entries in Scan History, clear all saved history in Settings, or clear this site's browser data. Browser storage can also be unavailable or evicted.</p>
          <p>A scan made while history storage is unavailable is not retained across reloads. Veylix does not currently provide an account or server-side scan-history service.</p>
        </section>
        <section><h2>External services and operational data</h2>
          <p>Scanning can contact GitHub (public repository manifests), OSV (package vulnerability queries), and deps.dev (optional package-health queries). These services receive the request data needed for their respective lookups and are governed by their own policies. The interface uses system fonts and does not request external font assets.</p>
          <p>The application does not intentionally persist submitted manifests or scan reports on its server and does not log request bodies. The hosting provider and network providers may process request metadata such as IP addresses, request paths, timestamps, and status codes under their own policies. The deployed URL uses Render; the exact production request-log configuration and retention period have not been verified. No server-side deletion process is configured because the application does not intentionally retain scan submissions.</p>
        </section>
        <section><h2>Security, event signals, and contact</h2>
          <p>Production traffic is served over HTTPS. The API enforces request and manifest size limits, limits simultaneous scans and scan request rates per network peer, and restricts GitHub retrieval to supported public manifest files without following redirects. These controls reduce risk but do not guarantee security. The source code is available in the linked project repository.</p>
          <p>The browser emits minimal scan-started, scan-completed, and scan-failed custom events to the current page only. No event listener, analytics provider, persistent identifier, or network destination is configured, so these signals are not stored or transmitted by Veylix.</p>
          <p>You can decline optional maintenance checks, delete locally saved reports, or avoid using the scan service. No analytics or advertising scripts or cookies are installed. No private privacy contact is configured. For non-sensitive concerns, use the public project repository's issue tracker; do not post manifests, repository URLs you wish to keep private, or personal information there. The service owner should provide a private privacy contact before public launch.</p>
        </section>
      </>
    )}

    {page === 'terms' && (
      <>
        <section><h2>Permitted use and authorization</h2>
          <p>Only submit dependency files you are authorized to use and scan. Only request scans of public GitHub repositories and their contents. Do not submit passwords, access tokens, private repository URLs, or other secrets; do not use the service to interfere with third-party systems, evade access controls, or submit unlawful or sensitive material. You are responsible for retaining your own copies of reports you need.</p>
        </section>
        <section><h2>Service limitations</h2>
          <p>Veylix matches resolved package versions against data returned by OSV and optionally obtains package-health signals from deps.dev. Coverage, metadata, severity, affected ranges, and fixes depend on those upstream sources and the files successfully parsed. Missing data is not proof that a package is safe. Services and external APIs may be unavailable, rate limited, or changed.</p>
          <p>Recommendations are informational. Review upstream advisories, test upgrades, and make your own risk and compatibility decisions. Veylix is not a substitute for a security review or professional advice.</p>
        </section>
        <section><h2>Disclaimer and review</h2>
          <p>Veylix is provided for informational dependency analysis. Results may be incomplete, delayed, or inaccurate, and availability is not guaranteed. You remain responsible for reviewing findings, validating upgrades, and deciding what actions to take. This draft is not legal advice and has not been reviewed for any jurisdiction. The operator identity, effective date, contact details, governing law, and any terms required for the service must be supplied by the owner and reviewed by qualified counsel before publication.</p>
        </section>
      </>
    )}

    {page === 'cookies' && (
      <>
        <section><h2>Cookies</h2>
          <p>The current application code does not set cookies and does not include analytics or advertising scripts. Interface fonts use the operating system and do not make third-party font requests.</p>
        </section>
        <section><h2>Browser local storage</h2>
          <p>Scan reports are stored in local storage to support scan history and reopening reports. This storage is essential to the existing client-side feature and is not an optional analytics or marketing preference. You can delete reports in Scan History or Settings, or clear this site's browser data.</p>
          <p>A cookie-preferences dialog is available from the footer. Since no optional tracking categories are configured, it explains the current storage behavior rather than presenting fictitious consent switches. Scan event signals are dispatched only within the current page and are neither stored nor sent to a provider.</p>
        </section>
      </>
    )}

    {page === 'support' && (
      <section><h2>Project channel</h2>
        <p>Repository and issue availability are controlled by the repository owner; do not include private manifests, access tokens, or sensitive scan data in public reports.</p>
        <a className="btn btn-secondary" href="https://github.com/om-lakhera/Veylix" target="_blank" rel="noopener noreferrer">
          View Veylix source repository <span aria-label="opens in a new tab">↗</span>
        </a>
        <p className="policy-note">The repository URL comes from this workspace's configured Git remote. No direct email or support submission endpoint is configured.</p>
      </section>
    )}
  </article>
);

interface StoragePreferencesDialogProps {
  open: boolean;
  onClose: () => void;
}

export const StoragePreferencesDialog: React.FC<StoragePreferencesDialogProps> = ({ open, onClose }) => {
  const dialogRef = React.useRef<HTMLDialogElement>(null);

  React.useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={dialogRef}
      className="preferences-dialog"
      aria-labelledby="preferences-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClose={onClose}
    >
      <div className="preferences-dialog-inner">
        <div className="overview-card-heading">
          <h2 id="preferences-title">Cookie & storage preferences</h2>
          <button className="btn btn-ghost btn-sm" type="button" onClick={onClose} aria-label="Close preferences">Close</button>
        </div>
        <p>This build does not use optional analytics or advertising cookies. No optional categories are enabled.</p>
        <div className="preference-category">
          <strong>Essential browser storage</strong>
          <span>Scan reports in local storage support scan history and reopening reports. Storage can be cleared from Settings or your browser. This feature is not controlled by an optional-cookie toggle.</span>
        </div>
        <a href="/privacy">Read the Privacy Policy</a>
        <div className="preferences-dialog-actions">
          <button className="btn btn-primary btn-sm" type="button" onClick={onClose}>Done</button>
        </div>
      </div>
    </dialog>
  );
};
