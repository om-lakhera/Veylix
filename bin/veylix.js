#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const cliDistPath = path.resolve(projectRoot, 'cli-dist/cli.js');

if (!fs.existsSync(cliDistPath)) {
  const tscPath = path.resolve(projectRoot, 'node_modules/typescript/bin/tsc');
  const compile = spawnSync(process.execPath, [tscPath, '-p', path.resolve(projectRoot, 'tsconfig.cli.json')], {
    cwd: projectRoot,
    stdio: 'inherit'
  });
  if (compile.status !== 0) {
    process.exit(compile.status ?? 2);
  }
}

const result = spawnSync(process.execPath, [cliDistPath, ...process.argv.slice(2)], {
  cwd: projectRoot,
  stdio: 'inherit'
});

process.exit(typeof result.status === 'number' ? result.status : 2);
