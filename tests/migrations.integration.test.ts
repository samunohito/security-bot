import { applyD1Migrations, env, type D1Migration } from 'cloudflare:test';
import { drizzle } from 'drizzle-orm/d1';
import { describe, expect, it } from 'vitest';
import { evidence, quotas, deliveries } from '../src/db/schema';

const { DB: db, TEST_MIGRATIONS: migrations } = env as unknown as {
  DB: D1Database;
  TEST_MIGRATIONS: D1Migration[];
};
const orm = drizzle(db);

describe('generated migrations', () => {
  it('優先度と配信履歴のインデックス列の降順指定を保持する', async () => {
    for (const [name, columns] of [
      [
        'revisions_priority',
        [
          ['eligible', 0],
          ['priority', 0],
          ['event_at', 1],
        ],
      ],
      [
        'deliveries_history',
        [
          ['target_id', 0],
          ['state', 0],
          ['updated_at', 1],
        ],
      ],
    ] as const) {
      const rows = await db.prepare(`PRAGMA index_xinfo('${name}')`).all<{ name: string; desc: number; key: number }>();
      expect(rows.results.filter((row) => row.key === 1).map((row) => [row.name, row.desc])).toEqual(columns);
    }
  });

  it('マイグレーションを再適用しても既存データを保持する', async () => {
    await orm.insert(quotas).values({ target_id: 'repeat', day: '2026-10-27', bucket: 'normal', used: 2 });

    await applyD1Migrations(db, migrations);

    expect(await orm.select().from(quotas)).toContainEqual({
      target_id: 'repeat',
      day: '2026-10-27',
      bucket: 'normal',
      used: 2,
    });
    expect(await db.prepare('SELECT COUNT(*) AS n FROM d1_migrations').first('n')).toBe(migrations.length);
  });

  it('過去の根拠を許容し同じ所属関係に現行版が二つ存在することを拒否する', async () => {
    const row = {
      threat_key: 'CVE-2026-1111',
      id: 'source:1',
      source_version: 'v1',
      modified_at: 1,
      fetched_at: 1,
      data: '{}',
    };
    await orm.insert(evidence).values({ ...row, hash: 'old', current: 0 });
    await orm.insert(evidence).values({ ...row, hash: 'current' });

    await expect(
      orm
        .insert(evidence)
        .values({ ...row, hash: 'duplicate-current' })
        .run(),
    ).rejects.toThrow();
    await expect(
      orm
        .insert(evidence)
        .values({ ...row, hash: 'old', current: 0 })
        .run(),
    ).rejects.toThrow();
    await orm.insert(evidence).values({ ...row, threat_key: 'CVE-2026-2222', hash: 'current' });
  });

  it('負の割当量と割当キーの重複を拒否する', async () => {
    const row = { target_id: 'constraint', day: '2026-10-27', bucket: 'normal' };
    await expect(
      orm
        .insert(quotas)
        .values({ ...row, used: -1 })
        .run(),
    ).rejects.toThrow();
    await orm.insert(quotas).values(row);
    await expect(orm.insert(quotas).values(row).run()).rejects.toThrow();
  });

  it('IDが異なっても投稿先と改訂が同じ配信を重複させない', async () => {
    const row = {
      target_id: 'main',
      revision_id: 'revision',
      urgent: 0,
      available_at: 1,
      created_at: 1,
      updated_at: 1,
    };
    await orm.insert(deliveries).values({ ...row, id: 'first' });
    await expect(
      orm
        .insert(deliveries)
        .values({ ...row, id: 'second' })
        .run(),
    ).rejects.toThrow();
  });
});
