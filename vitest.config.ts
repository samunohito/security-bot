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
              /** Workers標準fetchを維持したまま外部通信を遮断し、送信アダプターを検証する。 */
              outboundService: async (request) => {
                const url = new URL(request.url);
                if (
                  url.origin !== 'https://social.example' ||
                  url.pathname !== '/api/notes/create' ||
                  request.method !== 'POST'
                ) {
                  throw new Error('unexpected_external_request');
                }
                if (request.headers.get('Authorization') !== 'Bearer test-token') {
                  return new Response(null, { status: 401 });
                }
                return Response.json({ createdNote: { id: 'native-fetch' } });
              },
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
