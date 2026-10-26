export type ScanEventName = 'scan_started' | 'scan_completed' | 'scan_failed';
export type ScanFailureCategory = 'scan_rejected' | 'request_failed';

interface ScanEventDetails {
  name: ScanEventName;
  timestamp: string;
  durationMs?: number;
  failureCategory?: ScanFailureCategory;
}

export function emitScanEvent(
  name: ScanEventName,
  options: { durationMs?: number; failureCategory?: ScanFailureCategory } = {}
): void {
  if (typeof window === 'undefined') return;

  const details: ScanEventDetails = {
    name,
    timestamp: new Date().toISOString(),
    ...(options.durationMs !== undefined ? { durationMs: Math.max(0, Math.round(options.durationMs)) } : {}),
    ...(options.failureCategory ? { failureCategory: options.failureCategory } : {})
  };

  try {
    window.dispatchEvent(new CustomEvent<ScanEventDetails>('veylix:scan-event', { detail: details }));
  } catch {
    // Local event dispatch is optional and must not change scan behavior.
  }
}
