import { describe, it, expect } from 'vitest';
import { evaluateThreshold, parseCliArgs, parseThreshold, runCli } from '../src/cli.js';

describe('CLI utilities', () => {
  it('parses supported threshold values', () => {
    expect(parseThreshold('critical')).toBe('critical');
    expect(parseThreshold('HIGH')).toBe('high');
    expect(parseThreshold('medium')).toBe('moderate');
    expect(parseThreshold('none')).toBe('none');
  });

  it('rejects unsupported threshold values', () => {
    expect(() => parseThreshold('urgent')).toThrow('Unsupported threshold');
  });

  it('parses command-line arguments and accepts scan aliases', () => {
    expect(parseCliArgs(['scan', '--file', './package-lock.json', '--ecosystem', 'npm', '--threshold', 'high', '--format', 'json'])).toEqual({
      help: false,
      input: './package-lock.json',
      ecosystem: 'npm',
      threshold: 'high',
      format: 'json'
    });

    expect(parseCliArgs(['--help'])).toEqual({ help: true, threshold: 'none', format: 'text' });
  });

  it('evaluates vulnerability thresholds using server-side severity definitions', () => {
    const report = {
      summary: {
        severityCounts: {
          critical: 1,
          high: 3,
          moderate: 0,
          low: 2,
          unknown: 1
        }
      }
    } as any;

    expect(evaluateThreshold(report, 'critical')).toEqual({
      exceeded: true,
      matchedSeverities: ['critical']
    });
    expect(evaluateThreshold(report, 'high')).toEqual({
      exceeded: true,
      matchedSeverities: ['critical', 'high']
    });
    expect(evaluateThreshold(report, 'low')).toEqual({
      exceeded: true,
      matchedSeverities: ['critical', 'high', 'low', 'unknown']
    });
    expect(evaluateThreshold(report, 'none')).toEqual({
      exceeded: false,
      matchedSeverities: []
    });
  });

  it('prints help and exits without error', async () => {
    let output = '';
    const exitCode = await runCli(['--help'], {
      stdout: { write: (chunk: string) => { output += chunk; } },
      stderr: { write: () => undefined }
    });

    expect(exitCode).toBe(0);
    expect(output).toContain('Veylix CLI');
  });
});
