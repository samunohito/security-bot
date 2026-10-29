import { env } from 'cloudflare:test';
import { beforeEach, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config';
import { Store } from '../src/store';

const db = (env as unknown as { DB: D1Database }).DB;
const now = Date.parse('2026-10-29T00:00:00Z');
const config = loadConfig({
  publishing: { mode: 'nvd-high-digest' },
  targets: [{ id: 'main', provider: 'fake', enabled: true }],
});
const store = new Store(db, config);

beforeEach(async () => {
  await db.batch(
    [
      'deliveries',
      'delivery_items',
      'summaries',
      'jobs',
      'publication_observations',
      'threats',
      'revisions',
      'settings',
    ].map((table) => db.prepare(`DELETE FROM ${table}`)),
  );
  await db.batch([
    db.prepare(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<300)
      INSERT INTO revisions(id,threat_key,snapshot,evidence_hash,kind,event_at,priority,urgent,eligible,created_at)
      SELECT 'revision:'||x,'threat:'||x,'{"rejected":false}','hash:'||x,'initial',${now}+x,1,0,1,${now} FROM n
      UNION ALL SELECT 'old:'||x,'threat:'||x,'{"rejected":false}','old-hash:'||x,'initial',${now},1,0,1,${now} FROM n`),
    db.prepare(`INSERT INTO threats(key,revision_id)
      SELECT threat_key,id FROM revisions WHERE id LIKE 'revision:%'`),
    db.prepare(`INSERT INTO publication_observations(threat_key,highest_level,current_level,critical_at,nvd_only)
      SELECT threat_key,3,3,event_at,1 FROM revisions WHERE id LIKE 'revision:%'`),
    db.prepare(`INSERT INTO deliveries(id,target_id,revision_id,state,urgent,available_at,error,created_at,updated_at)
      SELECT 'delivery:'||id,'main',id,CASE id WHEN 'revision:1' THEN 'sent' WHEN 'revision:2' THEN 'unknown' ELSE 'stale' END,
      0,${now},'individual_to_digest',${now},${now} FROM revisions`),
  ]);
});

async function threatScans(sql: string): Promise<string[]> {
  const plan = await db
    .prepare(`EXPLAIN QUERY PLAN ${sql}`)
    .bind(...Array.from({ length: sql.match(/\?/g)?.length ?? 0 }, () => null))
    .all<{ detail: string }>();

  return plan.results.map((step) => step.detail).filter((detail) => /\bSCAN t\b/.test(detail));
}

it('解析候補の選出で脅威表を繰り返し走査せず過去改訂と送信済み・結果不明を除外する', async () => {
  const prepare = vi.spyOn(db, 'prepare');
  let sql: string;
  let revisions: Awaited<ReturnType<Store['currentRevisions']>>;
  try {
    revisions = await store.currentRevisions(50, 'policy');
    sql = prepare.mock.calls.find(([query]) => query.includes('SELECT r.id,r.evidence_hash'))![0];
  } finally {
    prepare.mockRestore();
  }

  expect(revisions.map((revision) => revision.id)).toEqual(
    Array.from({ length: 50 }, (_, index) => `revision:${index + 3}`),
  );
  expect(await threatScans(sql)).toEqual([]);
});

it('方式切替の再調整で脅威表を繰り返し走査せず現在改訂の未送信配信だけを復帰する', async () => {
  const prepare = vi.spyOn(db, 'prepare');
  let sql: string;
  try {
    await store.publications.reconcileDeliveries(now + 1000);
    sql = prepare.mock.calls.find(([query]) => query.includes("WHERE mode='individual' AND state='stale'"))![0];
  } finally {
    prepare.mockRestore();
  }
  const rows = await db.prepare('SELECT state,COUNT(*) AS count FROM deliveries GROUP BY state').all();

  expect(rows.results).toEqual([
    { state: 'ready', count: 298 },
    { state: 'sent', count: 1 },
    { state: 'stale', count: 300 },
    { state: 'unknown', count: 1 },
  ]);
  expect(await threatScans(sql)).toEqual([]);
});
