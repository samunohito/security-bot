import { defineConfig } from 'vitest/config';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';

const migrations = await readD1Migrations('./migrations');

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
              bindings: { TEST_MIGRATIONS: migrations },
            },
          }),
        ],
        test: {
          name: 'workers',
          setupFiles: ['./tests/setup.ts'],
          include: ['tests/**/*.integration.test.ts'],
          fileParallelism: false,
        },
      },
    ],
  },
});
