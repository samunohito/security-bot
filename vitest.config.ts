import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['tests/**/*.test.ts'],
          exclude: ['tests/**/*.integration.test.ts'],
        },
      },
      {
        plugins: [
          cloudflareTest({
            main: './tests/worker.ts',
            miniflare: {
              compatibilityDate: '2026-10-27',
              compatibilityFlags: ['nodejs_compat'],
              d1Databases: ['DB'],
            },
          }),
        ],
        test: {
          name: 'workers',
          include: ['tests/**/*.integration.test.ts'],
          fileParallelism: false,
        },
      },
    ],
  },
});
