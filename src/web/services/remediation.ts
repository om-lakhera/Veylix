import { SupportedEcosystem } from '../../types.js';

const NPM_PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const NPM_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const PYPI_PACKAGE_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const PYPI_VERSION = /^(?:\d+!)?\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/i;

export interface UpgradeCommand {
  command?: string;
  reason?: string;
}

export type CopyCommandResult = 'copied' | 'unavailable' | 'failed';

export async function copyUpgradeCommand(
  command: string,
  clipboard: Pick<Clipboard, 'writeText'> | undefined
): Promise<CopyCommandResult> {
  if (!clipboard?.writeText) return 'unavailable';
  try {
    await clipboard.writeText(command);
    return 'copied';
  } catch {
    return 'failed';
  }
}

export function generateUpgradeCommand(
  ecosystem: SupportedEcosystem,
  packageName: string,
  verifiedFixedVersion?: string
): UpgradeCommand {
  if (!verifiedFixedVersion) {
    return { reason: 'No verified fixed version is available from the advisory.' };
  }

  const validPackage = ecosystem === 'npm'
    ? NPM_PACKAGE_NAME.test(packageName)
    : PYPI_PACKAGE_NAME.test(packageName);
  if (!validPackage) {
    return { reason: 'The package name is not safe to place in a command.' };
  }

  const version = verifiedFixedVersion;
  if (version !== version.trim()) {
    return { reason: 'The advisory fixed version contains surrounding whitespace and cannot be used safely.' };
  }
  const validVersion = ecosystem === 'npm'
    ? NPM_VERSION.test(version)
    : PYPI_VERSION.test(version);
  if (!validVersion) {
    return { reason: 'The advisory fixed version is not in a supported, safe version format.' };
  }

  if (ecosystem === 'npm') {
    return { command: `npm install --save-exact -- '${packageName}@${version}'` };
  }

  return { command: `python -m pip install -- '${packageName}==${version}'` };
}
