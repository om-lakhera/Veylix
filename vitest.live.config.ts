import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/live-smoke.test.ts']
  }
});
