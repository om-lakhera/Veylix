import React, { useState, useRef } from 'react';
import { executeFileScan, executeGitHubScan } from '../services/api-client.js';
import { ScanTargetInfo } from '../types.js';
import { AnalysisReport } from '../../types.js';
import { emitScanEvent } from '../services/scan-events.js';
import {
  MAX_MANIFEST_SIZE_BYTES,
  MAX_TOTAL_MANIFEST_SIZE_BYTES
} from '../../limits.js';

interface NewScanViewProps {
  onScanComplete: (target: ScanTargetInfo, report: AnalysisReport) => void;
}

type ScanMode = 'upload' | 'github';

interface StagedFile {
  name: string;
  size: number;
  content: string;
}

export const NewScanView: React.FC<NewScanViewProps> = ({ onScanComplete }) => {
  const [mode, setMode] = useState<ScanMode>('upload');
  const [stagedFiles, setStagedFiles] = useState<StagedFile[]>([]);
  const [githubUrl, setGithubUrl] = useState('');
  const [includeMaintenance, setIncludeMaintenance] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const scanLockRef = useRef(false);

  // File Upload Handlers
  const handleFilesSelected = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setErrorMessage(null);

    const newFiles: StagedFile[] = [];
    const supportedFiles = new Set([
      'package-lock.json',
      'package.json',
      'requirements.txt',
      'poetry.lock',
      'pyproject.toml'
    ]);
    const stagedNames = new Set<string>();
    let aggregateBytes = stagedFiles
      .filter((file) => !Array.from(fileList).some((selected) => selected.name.toLowerCase() === file.name.toLowerCase()))
      .reduce((total, file) => total + file.size, 0);

    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i]!;
      const normalizedName = file.name.toLowerCase();
      if (!supportedFiles.has(normalizedName)) {
        setErrorMessage(`"${file.name}" is not a supported dependency file. Choose package-lock.json, package.json, requirements.txt, poetry.lock, or pyproject.toml.`);
        return;
      }
      if (stagedNames.has(normalizedName)) {
        setErrorMessage(`Select "${file.name}" only once.`);
        return;
      }
      stagedNames.add(normalizedName);
      if (file.size === 0) {
        setErrorMessage(`"${file.name}" is empty.`);
        return;
      }
      if (file.size > MAX_MANIFEST_SIZE_BYTES) {
        setErrorMessage(`"${file.name}" exceeds the 5 MiB per-file limit.`);
        return;
      }
      aggregateBytes += file.size;
      if (aggregateBytes > MAX_TOTAL_MANIFEST_SIZE_BYTES) {
        setErrorMessage('Combined dependency files exceed the 10 MiB scan limit.');
        return;
      }

      try {
        const text = await file.text();
        if (text.trim().length === 0) {
          setErrorMessage(`"${file.name}" is empty.`);
          return;
        }
        if (normalizedName === 'package-lock.json' || normalizedName === 'package.json') {
          let parsed: unknown;
          try {
            parsed = JSON.parse(text);
          } catch {
            setErrorMessage(`"${file.name}" must contain valid JSON.`);
            return;
          }
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            setErrorMessage(`"${file.name}" must contain a JSON object.`);
            return;
          }
          if (
            normalizedName === 'package-lock.json' &&
            ![1, 2, 3].includes((parsed as { lockfileVersion?: number }).lockfileVersion ?? 0)
          ) {
            setErrorMessage('"package-lock.json" must use a supported lockfile version (1, 2, or 3).');
            return;
          }
        }
        newFiles.push({
          name: normalizedName,
          size: file.size,
          content: text
        });
      } catch (err) {
        setErrorMessage(`Failed to read "${file.name}": ${err instanceof Error ? err.message : 'Unknown file error.'}`);
        return;
      }
    }

    setStagedFiles((prev) => {
      // Replace existing file of same name if re-added
      const filtered = prev.filter((p) => !newFiles.some((n) => n.name === p.name));
      return [...filtered, ...newFiles];
    });
  };

  const removeStagedFile = (name: string) => {
    setStagedFiles((prev) => prev.filter((f) => f.name !== name));
  };

  // Sample manifest loaders
  const loadSampleNpm = () => {
    const samplePackageLock = JSON.stringify({
      name: "sample-npm-project",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": {
          name: "sample-npm-project",
          version: "1.0.0",
          dependencies: {
            "lodash": "4.17.15",
            "express": "4.18.2"
          }
        },
        "node_modules/lodash": {
          version: "4.17.15",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
        },
        "node_modules/express": {
          version: "4.18.2",
          resolved: "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
          dependencies: {
            "qs": "6.11.0"
          }
        },
        "node_modules/qs": {
          version: "6.11.0",
          resolved: "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz"
        }
      }
    }, null, 2);

    const samplePackageJson = JSON.stringify({
      name: "sample-npm-project",
      version: "1.0.0",
      dependencies: {
        "lodash": "^4.17.15",
        "express": "^4.18.2"
      }
    }, null, 2);

    setStagedFiles([
      { name: 'package-lock.json', size: samplePackageLock.length, content: samplePackageLock },
      { name: 'package.json', size: samplePackageJson.length, content: samplePackageJson }
    ]);
    setErrorMessage(null);
  };

  const loadSamplePython = () => {
    const sampleReqs = `# Sample Python Requirements
requests==2.20.0
flask==1.0.0
certifi==2022.9.24
urllib3==1.24.1
`;
    setStagedFiles([
      { name: 'requirements.txt', size: sampleReqs.length, content: sampleReqs }
    ]);
    setErrorMessage(null);
  };

  // Run File Scan
  const handleExecuteFileScan = async () => {
    if (scanLockRef.current) return;
    if (stagedFiles.length === 0) {
      setErrorMessage('Please add at least one dependency manifest file before scanning.');
      return;
    }

    setErrorMessage(null);
    scanLockRef.current = true;
    setIsScanning(true);
    const startedAt = performance.now();
    emitScanEvent('scan_started');
    let terminalEventEmitted = false;

    const payload: Record<string, string | undefined> = {};
    for (const f of stagedFiles) {
      if (f.name === 'package-lock.json') payload.packageLockJson = f.content;
      if (f.name === 'package.json') payload.packageJson = f.content;
      if (f.name === 'requirements.txt') payload.requirementsTxt = f.content;
      if (f.name === 'poetry.lock') payload.poetryLock = f.content;
      if (f.name === 'pyproject.toml') payload.pyprojectToml = f.content;
    }

    try {
      const res = await executeFileScan({
        ...payload,
        fetchMaintenanceHealth: includeMaintenance
      });

      if (!res.success || !res.report) {
        emitScanEvent('scan_failed', {
          durationMs: performance.now() - startedAt,
          failureCategory: 'scan_rejected'
        });
        terminalEventEmitted = true;
        setErrorMessage(res.error || 'Scan failed.');
        setIsScanning(false);
        return;
      }

      emitScanEvent('scan_completed', { durationMs: performance.now() - startedAt });
      terminalEventEmitted = true;
      onScanComplete(res.target, res.report);
    } catch (err) {
      if (!terminalEventEmitted) {
        emitScanEvent('scan_failed', {
          durationMs: performance.now() - startedAt,
          failureCategory: 'request_failed'
        });
      }
      setErrorMessage(err instanceof Error ? err.message : 'Unexpected scanning error.');
    } finally {
      scanLockRef.current = false;
      setIsScanning(false);
    }
  };

  // Run GitHub Scan
  const handleExecuteGitHubScan = async () => {
    if (scanLockRef.current) return;
    if (!githubUrl.trim()) {
      setErrorMessage('Please enter a public GitHub repository URL or "owner/repo".');
      return;
    }

    setErrorMessage(null);
    scanLockRef.current = true;
    setIsScanning(true);
    const startedAt = performance.now();
    emitScanEvent('scan_started');
    let terminalEventEmitted = false;

    try {
      const res = await executeGitHubScan({
        repoUrl: githubUrl.trim(),
        fetchMaintenanceHealth: includeMaintenance
      });

      if (!res.success || !res.report) {
        emitScanEvent('scan_failed', {
          durationMs: performance.now() - startedAt,
          failureCategory: 'scan_rejected'
        });
        terminalEventEmitted = true;
        setErrorMessage(res.error || 'Failed to scan repository.');
        setIsScanning(false);
        return;
      }

      emitScanEvent('scan_completed', { durationMs: performance.now() - startedAt });
      terminalEventEmitted = true;
      onScanComplete(res.target, res.report);
    } catch (err) {
      if (!terminalEventEmitted) {
        emitScanEvent('scan_failed', {
          durationMs: performance.now() - startedAt,
          failureCategory: 'request_failed'
        });
      }
      setErrorMessage(err instanceof Error ? err.message : 'Network error scanning GitHub repository.');
    } finally {
      scanLockRef.current = false;
      setIsScanning(false);
    }
  };

  return (
    <div className="animate-in" style={{ maxWidth: '880px', margin: '0 auto' }}>
      {/* Page Header */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '8px' }}>
          <div style={{ width: '44px', height: '44px', borderRadius: '14px', backgroundColor: 'var(--brand-light)', color: 'var(--brand-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <path d="m10 8 4 4-4 4"/>
            </svg>
          </div>
          <div>
            <h1 style={{ fontSize: '1.8rem', fontWeight: 800, letterSpacing: '-0.03em', marginBottom: '2px' }}>
              New Dependency Scan
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem' }}>
              Scan local manifest files or analyze any public GitHub repository. Zero login or API keys required.
            </p>
          </div>
        </div>
      </div>

      {/* Mode Selector Tabs */}
      <div className="tab-group" style={{ marginBottom: '24px' }}>
        <button
          className={`tab-btn ${mode === 'upload' ? 'active' : ''}`}
          onClick={() => { setMode('upload'); setErrorMessage(null); }}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '6px', verticalAlign: '-2px' }}>
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          Upload Files
        </button>
        <button
          className={`tab-btn ${mode === 'github' ? 'active' : ''}`}
          onClick={() => { setMode('github'); setErrorMessage(null); }}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '6px', verticalAlign: '-2px' }}>
            <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/>
            <path d="M9 18c-4.51 2-5-2-7-2"/>
          </svg>
          GitHub Repository
        </button>
      </div>

      {/* Error Alert Banner */}
      {errorMessage && (
        <div className="alert alert-error" role="alert" aria-live="assertive">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: '2px' }}>
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <div>
            <strong>Scan Error:</strong> {errorMessage}
          </div>
        </div>
      )}

      {/* Progress Stepper Banner during Scan */}
      {isScanning && (
        <div className="progress-stepper" role="status" aria-live="polite" aria-busy="true">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <span className="spinner"></span>
            <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: '1rem' }}>Scan in progress</span>
          </div>
          <p>Resolving dependency versions and querying available vulnerability data. This may take a moment.</p>
        </div>
      )}

      {/* Mode A: File Upload */}
      {mode === 'upload' && !isScanning && (
        <div className="card card-elevated">
          <input
            type="file"
            ref={fileInputRef}
            style={{ display: 'none' }}
            multiple
            accept=".json,.txt,.lock,.toml"
            onChange={(e) => {
              void handleFilesSelected(e.currentTarget.files);
              e.currentTarget.value = '';
            }}
          />

          <button
            type="button"
            className={`dropzone ${dragActive ? 'drag-active' : ''}`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragActive(false);
              handleFilesSelected(e.dataTransfer.files);
            }}
          >
            <span className="dropzone-icon" aria-hidden="true">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/>
                <line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
            </span>
            <span className="dropzone-title">Click to upload or drag & drop files</span>
            <span className="dropzone-subtitle">
              Supported: <code>package-lock.json</code>, <code>package.json</code>, <code>requirements.txt</code>, <code>poetry.lock</code>, <code>pyproject.toml</code>
              <br />Maximum 5 MiB per file and 10 MiB total.
            </span>
          </button>

          {/* Sample Loaders */}
          <div className="samples-bar">
            <span className="samples-label">Quick sample data:</span>
            <button className="sample-chip" type="button" onClick={loadSampleNpm}>
              + Sample npm (lodash@4.17.15)
            </button>
            <button className="sample-chip" type="button" onClick={loadSamplePython}>
              + Sample Python (requests@2.20.0)
            </button>
          </div>

          {/* Staged Files Display */}
          {stagedFiles.length > 0 && (
            <div style={{ marginTop: '24px' }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
                Staged Manifests ({stagedFiles.length})
              </div>
              <div className="staged-files-list">
                {stagedFiles.map((file) => (
                  <div key={file.name} className="staged-file-item">
                    <div className="staged-file-info">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--brand-primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
                        <polyline points="14 2 14 8 20 8"/>
                      </svg>
                      <span className="staged-file-name">{file.name}</span>
                      <span className="staged-file-size">({Math.round(file.size / 1024 * 10) / 10} KB)</span>
                    </div>
                    <button
                      className="btn btn-ghost btn-sm"
                      style={{ color: 'var(--severity-critical)' }}
                      onClick={(e) => { e.stopPropagation(); removeStagedFile(file.name); }}
                      title="Remove file"
                    >
                      ✕ Remove
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Options & Action */}
          <div style={{ marginTop: '24px', paddingTop: '20px', borderTop: '1px solid var(--border-subtle)' }}>
            <label className="checkbox-toggle" style={{ marginBottom: '20px' }}>
              <input
                type="checkbox"
                checked={includeMaintenance}
                onChange={(e) => setIncludeMaintenance(e.target.checked)}
              />
              <div className="checkbox-toggle-text">
                <span className="checkbox-toggle-title">Include OpenSSF Scorecard & deps.dev Maintenance Vitality Check</span>
                <span className="checkbox-toggle-desc">
                    Enriches up to 30 direct dependencies with available maintenance activity and deprecation data.
                </span>
              </div>
            </label>

            <button
              className="btn btn-primary"
              style={{ width: '100%', padding: '14px', fontSize: '0.95rem' }}
              disabled={stagedFiles.length === 0}
              onClick={handleExecuteFileScan}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <path d="m10 8 4 4-4 4"/>
              </svg>
              Start Analysis Engine ({stagedFiles.length} file{stagedFiles.length === 1 ? '' : 's'})
            </button>
          </div>
        </div>
      )}

      {/* Mode B: Public GitHub Repo */}
      {mode === 'github' && !isScanning && (
        <div className="card card-elevated">
          <div className="form-group">
            <label className="form-label" htmlFor="github-url-input">
              <span>Public GitHub Repository URL or "owner/repo"</span>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Read-only public inspection</span>
            </label>
            <input
              id="github-url-input"
              className="input-text input-mono"
              placeholder="e.g. expressjs/express or https://github.com/pallets/flask"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleExecuteGitHubScan(); }}
            />
            <span className="input-hint">
              The scan server reads supported manifest files from the public GitHub repository. No GitHub token is required.
            </span>
          </div>

          {/* Sample Repos */}
          <div className="samples-bar" style={{ marginBottom: '20px' }}>
            <span className="samples-label">Popular samples:</span>
            <button className="sample-chip" type="button" onClick={() => setGithubUrl('expressjs/express')}>
              expressjs/express (npm)
            </button>
            <button className="sample-chip" type="button" onClick={() => setGithubUrl('pallets/flask')}>
              pallets/flask (Python)
            </button>
            <button className="sample-chip" type="button" onClick={() => setGithubUrl('psf/requests')}>
              psf/requests (Python)
            </button>
          </div>

          <label className="checkbox-toggle" style={{ marginBottom: '24px' }}>
            <input
              type="checkbox"
              checked={includeMaintenance}
              onChange={(e) => setIncludeMaintenance(e.target.checked)}
            />
            <div className="checkbox-toggle-text">
              <span className="checkbox-toggle-title">Include OpenSSF Scorecard & deps.dev Maintenance Vitality Check</span>
              <span className="checkbox-toggle-desc">
                Retrieves project Scorecard vitality indicators for identified direct dependencies.
              </span>
            </div>
          </label>

          <button
            className="btn btn-primary"
            style={{ width: '100%', padding: '14px', fontSize: '0.95rem' }}
            disabled={!githubUrl.trim()}
            onClick={handleExecuteGitHubScan}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"/>
            </svg>
            Fetch Manifests & Scan Repository
          </button>
        </div>
      )}
    </div>
  );
};
