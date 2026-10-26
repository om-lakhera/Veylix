import { afterEach, describe, expect, it, vi } from 'vitest';
import { emitScanEvent } from '../src/web/services/scan-events.js';

describe('local scan event interface', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('dispatches only minimal scan metadata in the current page', () => {
    const dispatchEvent = vi.fn();
    vi.stubGlobal('window', { dispatchEvent });

    emitScanEvent('scan_failed', {
      durationMs: 12.6,
      failureCategory: 'request_failed'
    });

    expect(dispatchEvent).toHaveBeenCalledOnce();
    const event = dispatchEvent.mock.calls[0]?.[0] as CustomEvent<{
      name: string;
      timestamp: string;
      durationMs: number;
      failureCategory: string;
    }>;
    expect(event.type).toBe('veylix:scan-event');
    expect(event.detail).toMatchObject({
      name: 'scan_failed',
      durationMs: 13,
      failureCategory: 'request_failed'
    });
    expect(event.detail.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(Object.keys(event.detail).sort()).toEqual([
      'durationMs',
      'failureCategory',
      'name',
      'timestamp'
    ]);
  });

  it('does not let local event dispatch failures interrupt scans', () => {
    vi.stubGlobal('window', {
      dispatchEvent: () => {
        throw new Error('listener failure');
      }
    });

    expect(() => emitScanEvent('scan_started')).not.toThrow();
  });
});
