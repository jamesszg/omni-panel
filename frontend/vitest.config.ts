import path from 'node:path';

import react from '@vitejs/plugin-react';
import { storybookTest } from '@storybook/addon-vitest/vitest-plugin';
import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

const dirname = import.meta.dirname;

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(dirname, 'src'),
    },
  },
  test: {
    globals: false,
    // Keep jsdom-heavy form tests within the memory budget of local and CI runners.
    maxWorkers: 2,
    // language-scope.test.ts can take >5s on Windows due to vi.resetModules()
    // + dynamic imports; the default 5000ms is too tight when all projects run.
    testTimeout: 15000,
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['src/test/**/*.test.ts'],
          environment: 'node',
          // msw probes localStorage on load; Node 25+'s file-less one warns per worker.
          execArgv: ['--no-experimental-webstorage'],
          setupFiles: ['./src/test/setup.ts', './src/test/setup.msw.ts'],
        },
      },
      {
        extends: true,
        test: {
          name: 'components',
          include: ['src/test/**/*.test.tsx'],
          environment: 'jsdom',
          setupFiles: ['./src/test/setup.ts', './src/test/setup.components.ts'],
        },
      },
      {
        extends: true,
        optimizeDeps: {
          include: ['aria-query', 'lz-string', 'pretty-format', 'dom-accessibility-api'],
        },
        plugins: [storybookTest({ configDir: path.join(dirname, '.storybook') })],
        test: {
          name: 'storybook',
          browser: {
            enabled: true,
            headless: true,
            provider: playwright({}),
            instances: [{ browser: 'chromium' }],
          },
          // Windows can block [::1]; force Vite + Chromium to use 127.0.0.1.
          server: { host: '127.0.0.1' },
        },
      },
    ],
  },
});
