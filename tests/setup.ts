import { applyD1Migrations, env, type D1Migration } from 'cloudflare:test';
import { beforeAll } from 'vitest';

beforeAll(async () => {
  const { DB, TEST_MIGRATIONS } = env as unknown as { DB: D1Database; TEST_MIGRATIONS: D1Migration[] };
  await applyD1Migrations(DB, TEST_MIGRATIONS);
});
