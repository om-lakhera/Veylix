import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  LocalSecurityScanOptions,
  SecurityScanResult,
  scanLocalSecurity
} from './local-security-scanner.js';

const EXCLUDED_DIRS = new Set([
  '.git', '.hg', '.svn', '.next', '.cache', 'node_modules', 'vendor', 'venv', '.venv',
  '__pycache__', 'dist', 'build', 'coverage', '.terraform'
]);

export interface SecurityWatchOptions extends LocalSecurityScanOptions {
  debounceMs?: number;
  maxWatchedDirectories?: number;
  runInitialScan?: boolean;
}

export function watchLocalSecurity(
  targetPath: string,
  options: SecurityWatchOptions,
  onResult: (result: SecurityScanResult) => void,
  onError: (error: Error) => void
): () => void {
  const absoluteTarget = path.resolve(targetPath);
  const targetStat = fs.lstatSync(absoluteTarget);
  if (targetStat.isSymbolicLink() || (!targetStat.isDirectory() && !targetStat.isFile())) {
    throw new Error('Watch target must be a regular file or directory; symbolic links are not followed.');
  }
  const debounceMs = Math.max(50, Math.min(5_000, options.debounceMs ?? 250));
  const maxWatchedDirectories = Math.max(1, Math.min(10_000, options.maxWatchedDirectories ?? 1_000));
  const watcherByDirectory = new Map<string, fs.FSWatcher>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let closed = false;

  const fail = (error: Error): void => {
    if (closed) return;
    onError(error);
    stop();
  };

  const refreshWatchers = (): void => {
    for (const watcher of watcherByDirectory.values()) watcher.close();
    watcherByDirectory.clear();
    const rootDirectory = targetStat.isDirectory() ? absoluteTarget : path.dirname(absoluteTarget);
    const directories = [rootDirectory];
    if (targetStat.isDirectory()) {
      const visit = (directory: string, depth: number): void => {
        if (depth >= (options.maxDepth ?? 24) || directories.length >= maxWatchedDirectories) return;
        const entries = fs.readdirSync(directory, { withFileTypes: true })
          .sort((left, right) => left.name.localeCompare(right.name));
        for (const entry of entries) {
          if (!entry.isDirectory() || entry.isSymbolicLink() || EXCLUDED_DIRS.has(entry.name.toLowerCase())) continue;
          if (directories.length >= maxWatchedDirectories) {
            throw new Error(`Security watch exceeds the directory limit of ${maxWatchedDirectories}.`);
          }
          const nested = path.join(directory, entry.name);
          directories.push(nested);
          visit(nested, depth + 1);
        }
      };
      visit(absoluteTarget, 0);
    }

    for (const directory of directories) {
      const watcher = fs.watch(directory, { persistent: true }, (_eventType, filename) => {
        if (closed) return;
        if (!targetStat.isDirectory() && filename && filename.toString() !== path.basename(absoluteTarget)) return;
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
          timer = undefined;
          try {
            const result = scanLocalSecurity(absoluteTarget, options);
            refreshWatchers();
            onResult(result);
          } catch (error) {
            fail(error instanceof Error ? error : new Error('Security watch scan failed.'));
          }
        }, debounceMs);
      });
      watcher.on('error', (error) => fail(error));
      watcherByDirectory.set(directory, watcher);
    }
  };

  const stop = (): void => {
    if (closed) return;
    closed = true;
    if (timer) clearTimeout(timer);
    for (const watcher of watcherByDirectory.values()) watcher.close();
    watcherByDirectory.clear();
  };

  try {
    refreshWatchers();
    if (options.runInitialScan !== false) onResult(scanLocalSecurity(absoluteTarget, options));
  } catch (error) {
    stop();
    throw error;
  }
  return stop;
}
