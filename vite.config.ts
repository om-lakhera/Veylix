import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { veylixApiPlugin } from './src/server/vite-api-plugin.js';

export default defineConfig({
  plugins: [react(), veylixApiPlugin()],
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['test/live-smoke.test.ts', 'node_modules', 'dist']
  }
});
