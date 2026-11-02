import React, { FormEvent, useMemo, useState } from 'react';
import { AnalysisReport } from '../../types.js';
import {
  FindingDisposition,
  isFindingIgnored,
  saveFindingDisposition,
  stableFindingId
} from '../services/finding-dispositions.js';

interface FindingDispositionPanelProps {
  report: AnalysisReport;
  dispositions: FindingDisposition[];
  onChange: (dispositions: FindingDisposition[]) => void;
}

export const FindingDispositionPanel: React.FC<FindingDispositionPanelProps> = ({ report, dispositions, onChange }) => {
  const [status, setStatus] = useState('');
  const [expanded, setExpanded] = useState(false);
  const [visibleCount, setVisibleCount] = useState(100);
  const findingRows = useMemo(
    () => report.vulnerablePackages.flatMap((pkg) =>
      pkg.vulnerabilities.map((finding) => ({
        id: stableFindingId(pkg.ecosystem, pkg.name, finding),
        packageName: pkg.name,
        advisoryId: finding.advisoryId,
        severity: finding.severityLevel
      }))
    ),
    [report.vulnerablePackages]
  );
  const dispositionMap = useMemo(
    () => new Map(dispositions.map((item) => [item.findingId, item])),
    [dispositions]
  );

  const handleSave = (event: FormEvent<HTMLFormElement>, findingId: string): void => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const note = String(formData.get('note') ?? '');
    const ignoreDate = String(formData.get('ignoreUntil') ?? '');
    const result = saveFindingDisposition(findingId, note, ignoreDate || undefined);
    if (!result.success) {
      setStatus(result.error ?? 'Could not save this finding disposition.');
      return;
    }
    onChange(dispositions.filter((item) => item.findingId !== findingId).concat(result.disposition ? [result.disposition] : []));
    setStatus('Annotation saved in this browser.');
  };

  return (
    <section className="card finding-disposition-panel" aria-labelledby="finding-disposition-title">
      <button
        className="finding-disposition-toggle"
        type="button"
        aria-expanded={expanded}
        aria-controls="finding-disposition-content"
        onClick={() => setExpanded((current) => !current)}
      >
        <span>
          <strong id="finding-disposition-title">Finding annotations and expiring ignores</strong>
          <span className="finding-disposition-caption">
            {findingRows.length} findings · browser-local only; original report totals are unchanged
          </span>
        </span>
        <span aria-hidden="true">{expanded ? '−' : '+'}</span>
      </button>
      {expanded && (
        <div id="finding-disposition-content" className="finding-disposition-content">
          <p>
            Add a private review note or temporarily mark a finding ignored. Expired ignores become active again
            automatically. These annotations are not included in exports, API responses, or scan history reports.
          </p>
          {findingRows.length === 0 ? (
            <p>No vulnerability findings in this report.</p>
          ) : findingRows.slice(0, visibleCount).map((finding) => {
            const existing = dispositionMap.get(finding.id);
            const ignored = isFindingIgnored(existing);
            return (
              <form
                className="finding-disposition-row"
                key={finding.id}
                onSubmit={(event) => handleSave(event, finding.id)}
              >
                <div className="finding-disposition-heading">
                  <strong>{finding.packageName}</strong>
                  <code>{finding.advisoryId}</code>
                  <span className={`badge ${finding.severity === 'CRITICAL' ? 'badge-critical' : finding.severity === 'HIGH' ? 'badge-high' : 'badge-moderate'}`}>
                    {finding.severity}
                  </span>
                  {ignored && (
                    <span className="badge badge-neutral">
                      Ignored until {new Date(existing!.ignoredUntil!).toLocaleDateString()}
                    </span>
                  )}
                  {existing?.ignoredUntil && !ignored && (
                    <span className="badge badge-neutral">Ignore expired</span>
                  )}
                </div>
                <label>
                  Review note
                  <textarea name="note" maxLength={1_000} defaultValue={existing?.note ?? ''} rows={2} />
                </label>
                <label>
                  Ignore until (optional)
                  <input
                    name="ignoreUntil"
                    type="date"
                    min={new Date(Date.now() + 86_400_000).toISOString().slice(0, 10)}
                    defaultValue={existing?.ignoredUntil?.slice(0, 10) ?? ''}
                  />
                </label>
                <button className="btn btn-secondary btn-sm" type="submit">Save local disposition</button>
              </form>
            );
          })}
          {findingRows.length > visibleCount && (
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setVisibleCount((count) => count + 100)}>
              Show more findings ({findingRows.length - visibleCount} remaining)
            </button>
          )}
          <span className="copy-status" role="status" aria-live="polite">{status}</span>
        </div>
      )}
    </section>
  );
};
