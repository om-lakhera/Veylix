import { describe, expect, it, vi } from 'vitest';
import { copyUpgradeCommand, generateUpgradeCommand } from '../src/web/services/remediation.js';

describe('verified upgrade command generation', () => {
  it('generates an exact npm command for a validated scoped package and semver', () => {
    expect(generateUpgradeCommand('npm', '@scope/example', '2.3.4-rc.1')).toEqual({
      command: "npm install --save-exact -- '@scope/example@2.3.4-rc.1'"
    });
  });

  it('generates a pinned pip command for a validated package and PEP 440 version', () => {
    expect(generateUpgradeCommand('pypi', 'sample_pkg', '2!1.4.0rc2')).toEqual({
      command: "python -m pip install -- 'sample_pkg==2!1.4.0rc2'"
    });
  });

  it('does not guess a target when no advisory fixed version exists', () => {
    expect(generateUpgradeCommand('npm', 'safe-package')).toEqual({
      reason: 'No verified fixed version is available from the advisory.'
    });
  });

  it('rejects command-injection strings and unsupported version formats', () => {
    expect(generateUpgradeCommand('npm', 'pkg; echo unsafe', '1.2.3').command).toBeUndefined();
    expect(generateUpgradeCommand('pypi', 'pkg', '1.0.0"; whoami').command).toBeUndefined();
    expect(generateUpgradeCommand('npm', 'pkg', ' 1.2.3 ').command).toBeUndefined();
  });

  it('reports clipboard success, failure, and unavailable states', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    expect(await copyUpgradeCommand('npm install', { writeText })).toBe('copied');
    expect(writeText).toHaveBeenCalledWith('npm install');

    expect(await copyUpgradeCommand('npm install', {
      writeText: vi.fn().mockRejectedValue(new Error('blocked'))
    })).toBe('failed');
    expect(await copyUpgradeCommand('npm install', undefined)).toBe('unavailable');
  });
});
