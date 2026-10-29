import { env } from 'cloudflare:test';
import { beforeEach, expect, it } from 'vitest';
import { Store } from '../src/store';
import { loadConfig } from '../src/config';
import type { SourceItem } from '../src/domain';

const db = (env as unknown as { DB: D1Database }).DB;
const now = Date.parse('2026-10-28T00:00:00Z');
const config = loadConfig({
  publishing: { mode: 'nvd-high-digest' },
  sources: [{ id: 'custom', kind: 'nvd', url: 'https://example.com', pollIntervalSeconds: 7200 }],
});
const item: SourceItem = {
  id: '1',
  sourceId: 'custom',
  url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1111',
  title: 'Acme',
  text: 'Acme issue.',
  cves: ['CVE-2026-1111'],
  publishedAt: now,
  modifiedAt: now,
  fetchedAt: now,
  scores: [{ score: 6, version: '3.1', issuer: 'nvd' }],
  exploited: false,
  urgent: false,
  advisory: false,
  rejected: false,
  affected: 'Acme',
  remediation: null,
};
beforeEach(async () => {
  const tables = await db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT IN ('d1_migrations')",
    )
    .all<{ name: string }>();
  for (const table of tables.results) {
    await db.prepare(`DELETE FROM "${table.name}"`).run();
  }
});
it('スコアだけの昇格を記録しHighからCriticalへ通知方法を変える', async () => {
  const store = new Store(db, config);
  const [id] = await store.ingest(item, now);
  expect(await store.publications.decision((await store.getRevision(id!))!, 'main')).toBeNull();
  const [high] = await store.ingest(
    { ...item, modifiedAt: now + 1000, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] },
    now + 1000,
  );
  expect(await store.publications.decision((await store.getRevision(high!))!, 'main')).toMatchObject({
    route: 'digest',
    eventAt: now + 1000,
    level: 2,
  });
  const [critical] = await store.ingest(
    { ...item, modifiedAt: now + 2000, scores: [{ score: 9, version: '3.1', issuer: 'nvd' }] },
    now + 2000,
  );
  expect(await store.publications.decision((await store.getRevision(critical!))!, 'main')).toMatchObject({
    route: 'individual',
    eventAt: now + 2000,
    level: 3,
  });
});
it('古いHighの初回取得は基準値にし古いMediumからの昇格は拾う', async () => {
  const store = new Store(db, config);
  const [old] = await store.ingest(
    { ...item, publishedAt: now - 864000000, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] },
    now,
  );
  expect(await store.publications.decision((await store.getRevision(old!))!, 'main')).toBeNull();
  const [critical] = await store.ingest(
    {
      ...item,
      publishedAt: now - 864000000,
      modifiedAt: now + 1000,
      scores: [{ score: 9, version: '3.1', issuer: 'nvd' }],
    },
    now + 1000,
  );
  expect(await store.publications.decision((await store.getRevision(critical!))!, 'main')).toMatchObject({
    route: 'individual',
  });
});
it('掲載済みの最大重大度を越えない再昇格を通知しない', async () => {
  const store = new Store(db, config);
  const [id] = await store.ingest({ ...item, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] }, now);
  await store.createDelivery('posted', 'main', id!, false, now);
  await db.prepare("UPDATE deliveries SET state='sending',lease_token='t' WHERE id='posted'").run();
  await store.finishDelivery('posted', { id: 'p', url: 'https://social.example/p' }, now, 't');
  expect(await store.publications.decision((await store.getRevision(id!))!, 'main')).toBeNull();
  expect(await store.publications.decision((await store.getRevision(id!))!, 'other')).toMatchObject({ level: 3 });
});

async function readyDigest() {
  const store = new Store(db, config);
  const [id] = await store.ingest({ ...item, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] }, now);
  const revision = (await store.getRevision(id!))!;
  await store.saveSummary(
    revision,
    { overview: null, impact: null, action: null, uncertainties: [] },
    { valid: true, complete: true, reasons: [] },
    now,
  );
  const target = loadConfig({
    targets: [{ id: 'main', enabled: true, baseUrl: 'https://social.example', tokenSecret: 'TOKEN' }],
  }).targets[0]!;
  await store.syncTargets([target]);
  const member = {
    revision,
    decision: (await store.publications.decision(revision, 'main'))!,
    summary: (await store.getSummary(revision))!.summary,
  };
  const window = { start: now, end: now + 21600000 };
  await store.publications.createWindow('main', window, [{ members: [member], text: '検証済みまとめ' }], now);
  const delivery = (await store.list('deliveries'))[0]!;
  return { store, revision, target, member, window, delivery };
}
it('まとめの整形後にスコアだけでCriticalに昇格しても予約時に拒否する', async () => {
  const { store, target, delivery } = await readyDigest();
  await store.ingest(
    { ...item, modifiedAt: now + 1000, scores: [{ score: 9, version: '3.1', issuer: 'nvd' }] },
    now + 1000,
  );
  expect(await store.reserveDelivery(delivery.id, target, now + 1000)).toBeNull();
  expect(await store.list('targets')).toMatchObject([{ active_delivery: null }]);
});
it('まとめの一項目の根拠が変わったら予約を拒否する', async () => {
  const { store, target, revision, delivery } = await readyDigest();
  await db.prepare('UPDATE revisions SET evidence_hash=? WHERE id=?').bind('changed', revision.id).run();
  expect(await store.reserveDelivery(delivery.id, target, now)).toBeNull();
});
it('まとめの品質が送信前に不合格になったら予約を拒否する', async () => {
  const { store, target, revision, delivery } = await readyDigest();
  await store.saveSummary(
    revision,
    { overview: null, impact: null, action: null, uncertainties: [] },
    { valid: false, complete: true, reasons: ['contradiction'] },
    now,
  );
  expect(await store.reserveDelivery(delivery.id, target, now)).toBeNull();
});
it('同じ期間の作成を繰り返してもまとめと所属を増やさない', async () => {
  const { store, window, member } = await readyDigest();
  await Promise.all(
    [1, 2].map(() => store.publications.createWindow('main', window, [{ members: [member], text: '重複' }], now)),
  );
  expect(await store.list('deliveries')).toHaveLength(1);
  expect(await db.prepare('SELECT COUNT(*) AS n FROM delivery_items').first('n')).toBe(1);
});
it('新方式の導入時には既存のHighを新規掲載イベントにしない', async () => {
  const legacy = new Store(db);
  const [id] = await legacy.ingest({ ...item, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] }, now);
  const store = new Store(db, config);
  await store.publications.initialize(now + 1000);
  expect(await store.publications.decision((await store.getRevision(id!))!, 'main')).toBeNull();
});
it('旧方式でHighを個別掲載していてもスコアだけのCritical昇格を別配信にできる', async () => {
  const legacy = new Store(db);
  const [old] = await legacy.ingest({ ...item, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] }, now);
  await legacy.createDelivery('old-high', 'main', old!, false, now);
  await db.prepare("UPDATE deliveries SET state='sending',lease_token='old' WHERE id='old-high'").run();
  await legacy.finishDelivery('old-high', { id: 'old', url: 'https://social.example/old' }, now, 'old');
  const store = new Store(db, config);
  await store.publications.initialize(now + 1000);
  const [critical] = await store.ingest(
    { ...item, modifiedAt: now + 2000, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] },
    now + 2000,
  );
  expect(critical).not.toBe(old);
  const revision = (await store.getRevision(critical!))!;
  expect(await store.publications.decision(revision, 'main')).toMatchObject({ route: 'individual', level: 3 });
  await store.createDelivery('new-critical', 'main', critical!, false, now + 2000);
  expect((await store.list('deliveries')).map((delivery) => delivery.id)).toContain('new-critical');
});
it('不合格の解析を終えた候補が取得上限を占めず後続Highへ進む', async () => {
  const targetConfig = loadConfig({
    ...config,
    targets: [{ id: 'main', baseUrl: 'https://social.example', tokenSecret: 'TOKEN', enabled: true }],
  });
  const store = new Store(db, targetConfig);
  const [first] = await store.ingest({ ...item, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] }, now);
  const [second] = await store.ingest(
    { ...item, id: '2', cves: ['CVE-2026-2222'], scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] },
    now + 1,
  );
  const revision = (await store.getRevision(first!))!;
  expect(await store.currentRevisions(1, 'policy')).toMatchObject([{ id: first }]);
  await store.saveSummary(
    revision,
    { overview: null, impact: null, action: null, uncertainties: [] },
    { valid: false, complete: false, reasons: ['unsupported_summary'] },
    now,
  );
  const jobId = `analyze:${first}:${revision.evidence_hash}:policy`;
  await store.enqueue(jobId, 'analyze', { revisionId: first }, now);
  await db.prepare("UPDATE jobs SET state='done' WHERE id=?").bind(jobId).run();
  expect(await store.currentRevisions(1, 'policy')).toMatchObject([{ id: second }]);
  expect(await store.currentRevisions(1, 'changed-policy')).toMatchObject([{ id: first }]);
});
it('まとめの作成後に同じ根拠から要約が差し替わったら古い本文を予約しない', async () => {
  const { store, target, revision, delivery } = await readyDigest();
  await store.saveSummary(
    revision,
    { overview: { text: '改訂後の要約', evidence: [] }, impact: null, action: null, uncertainties: [] },
    { valid: true, complete: true, reasons: [] },
    now + 1,
  );
  expect(await store.reserveDelivery(delivery.id, target, now + 1)).toBeNull();
});
it('未掲載の導入時Highが降格後に再昇格したら新しいHigh通知を作る', async () => {
  const legacy = new Store(db);
  await legacy.ingest({ ...item, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] }, now);
  const store = new Store(db, config);
  await store.publications.initialize(now + 1);
  await store.ingest({ ...item, modifiedAt: now + 2 }, now + 2);
  const [id] = await store.ingest(
    { ...item, modifiedAt: now + 3, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] },
    now + 3,
  );
  expect(await store.publications.decision((await store.getRevision(id!))!, 'main')).toMatchObject({
    route: 'digest',
    eventAt: now + 3,
  });
});
it('過去Criticalの時刻が古くても新たなHigh昇格を候補として回復する', async () => {
  const targetConfig = loadConfig({
    ...config,
    targets: [{ id: 'main', baseUrl: 'https://social.example', tokenSecret: 'TOKEN', enabled: true }],
  });
  const store = new Store(db, targetConfig);
  await store.ingest({ ...item, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] }, now);
  await store.skipBefore(now + 10, now + 10);
  await store.ingest({ ...item, modifiedAt: now + 20 }, now + 20);
  const [high] = await store.ingest(
    { ...item, modifiedAt: now + 30, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] },
    now + 30,
  );
  expect(await store.publications.decision((await store.getRevision(high!))!, 'main')).toMatchObject({
    route: 'digest',
    eventAt: now + 30,
  });
  expect(await store.currentRevisions(50, 'policy')).toMatchObject([{ id: high }]);
});
it('同じ更新日時で未掲載Criticalに再昇格しても古いstale配信と衝突しない', async () => {
  const store = new Store(db, config);
  const criticalItem = { ...item, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] };
  const [first] = await store.ingest(criticalItem, now);
  await store.createDelivery('critical-first', 'main', first!, false, now);
  await store.ingest({ ...item, fetchedAt: now + 1000 }, now + 1000);
  expect((await store.getDelivery('critical-first'))?.state).toBe('stale');
  const [again] = await store.ingest({ ...criticalItem, fetchedAt: now + 2000 }, now + 2000);
  const decision = await store.publications.decision((await store.getRevision(again!))!, 'main');
  expect(decision).toMatchObject({ route: 'individual', eventAt: now + 2000 });
  await store.createDelivery('critical-again', 'main', again!, false, now + 2000);
  expect((await store.dueDeliveries(now + 2000)).map((delivery) => delivery.id)).toContain('critical-again');
});
it('まとめ方式を一時的に止めた間の降格も観測して再開後のHigh昇格を拾う', async () => {
  const store = new Store(db, config);
  const older = { ...item, publishedAt: now - 864000000 };
  await store.ingest({ ...older, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] }, now);
  const legacy = new Store(db, { ...config, publishing: { ...config.publishing, mode: 'individual' } });
  await legacy.ingest({ ...older, modifiedAt: now + 1000 }, now + 1000);
  const resumed = new Store(db, config);
  const [high] = await resumed.ingest(
    { ...older, modifiedAt: now + 2000, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] },
    now + 2000,
  );
  expect(await resumed.publications.decision((await resumed.getRevision(high!))!, 'main')).toMatchObject({
    route: 'digest',
    eventAt: now + 2000,
  });
});
it('一時的な個別方式でも掲載済みHighからCriticalへの改訂を別に保つ', async () => {
  const store = new Store(db, config);
  const [high] = await store.ingest({ ...item, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] }, now);
  await store.createDelivery('old-high', 'main', high!, false, now);
  await db.prepare("UPDATE deliveries SET state='sending',lease_token='old' WHERE id='old-high'").run();
  await store.finishDelivery('old-high', { id: 'old', url: 'https://social.example/old' }, now, 'old');
  const legacy = new Store(db, { ...config, publishing: { ...config.publishing, mode: 'individual' } });
  const [critical] = await legacy.ingest(
    { ...item, modifiedAt: now + 1000, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] },
    now + 1000,
  );
  expect(critical).not.toBe(high);
  const resumed = new Store(db, config);
  expect(await resumed.publications.decision((await resumed.getRevision(critical!))!, 'main')).toMatchObject({
    route: 'individual',
    level: 3,
  });
  await resumed.createDelivery('new-critical', 'main', critical!, false, now + 1000);
  expect((await resumed.dueDeliveries(now + 1000)).map((delivery) => delivery.id)).toContain('new-critical');
});
it('非NVDのスコアだけの上下では従来どおり同じ改訂を維持する', async () => {
  const rssConfig = loadConfig({
    ...config,
    sources: [{ id: 'jvn', kind: 'rss', url: 'https://jvn.jp/rss/jvn.rdf', pollIntervalSeconds: 900 }],
  });
  const store = new Store(db, rssConfig);
  const advisory = { ...item, sourceId: 'jvn', advisory: true, scores: [{ score: 8, version: '3.1', issuer: 'JVN' }] };
  const [high] = await store.ingest(advisory, now);
  const [critical] = await store.ingest(
    { ...advisory, modifiedAt: now + 1000, scores: [{ score: 9.8, version: '3.1', issuer: 'JVN' }] },
    now + 1000,
  );
  const [again] = await store.ingest({ ...advisory, modifiedAt: now + 2000 }, now + 2000);
  expect(critical).toBe(high);
  expect(again).toBe(high);
});
it.each([false, true])('一般の緊急通知を悪用確認済みと誤認しない: 旧DB移行=%s', async (migrated) => {
  const mixed = loadConfig({
    ...config,
    sources: [
      ...config.sources,
      { id: 'alert', kind: 'rss', url: 'https://example.com/rss', pollIntervalSeconds: 900 },
    ],
  });
  const store = migrated ? new Store(db) : new Store(db, mixed);
  await store.ingest(item, now);
  const alert = { ...item, sourceId: 'alert', title: '緊急のお知らせ', urgent: true, advisory: true, exploited: false };
  const [id] = await store.ingest(alert, now);
  await store.createDelivery('public-urgent', 'main', id!, true, now);
  await db.prepare("UPDATE deliveries SET state='sending',lease_token='t' WHERE id='public-urgent'").run();
  await store.finishDelivery('public-urgent', { id: 'alert', url: 'https://social.example/alert' }, now, 't');
  if (migrated) {
    await db.prepare("DELETE FROM delivery_items WHERE delivery_id='public-urgent'").run();
  }
  const current = new Store(db, mixed);
  await current.publications.initialize(now + 500);
  await current.ingest({ ...alert, cves: [], modifiedAt: now + 1000 }, now + 1000);
  const [exploited] = await current.ingest(
    { ...item, exploited: true, urgent: true, modifiedAt: now + 2000 },
    now + 2000,
  );
  expect(await current.publications.decision((await current.getRevision(exploited!))!, 'main')).toMatchObject({
    route: 'individual',
    reason: '悪用確認',
  });
});
it('予約を拒否した個別配信の所属版を現在版へ書き換えない', async () => {
  const store = new Store(db, config);
  const [id] = await store.ingest({ ...item, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] }, now);
  const revision = (await store.getRevision(id!))!;
  const target = loadConfig({
    targets: [{ id: 'main', enabled: true, baseUrl: 'https://social.example', tokenSecret: 'TOKEN' }],
  }).targets[0]!;
  await store.syncTargets([target]);
  await store.createDelivery('individual', 'main', id!, false, now);
  await db.prepare('UPDATE revisions SET evidence_hash=? WHERE id=?').bind('changed', id).run();
  expect(await store.reserveDelivery('individual', target, now, revision.evidence_hash)).toBeNull();
  expect((await store.publications.members('individual'))[0]?.evidence_hash).toBe(revision.evidence_hash);
});
it('整形後にcutoffが進んだまとめは登録せず集計窓を閉じない', async () => {
  const { store, window, member } = await readyDigest();
  await store.skipBefore(now + 1000, now + 1000);
  await store.publications.createWindow(
    'race',
    window,
    [{ members: [member], text: 'cutoff以前の整形結果' }],
    now + 2000,
  );
  expect(await db.prepare('SELECT COUNT(*) AS n FROM digest_windows WHERE target_id=?').bind('race').first('n')).toBe(
    0,
  );
  expect((await store.list('deliveries')).filter((delivery) => delivery.target_id === 'race')).toEqual([]);
});
it('非NVDのCVE関連が復旧したらまとめへ退役した同版の個別配信を復帰する', async () => {
  const mixed = loadConfig({
    ...config,
    sources: [
      ...config.sources,
      { id: 'alert', kind: 'rss', url: 'https://example.com/rss', pollIntervalSeconds: 900 },
    ],
    targets: [{ id: 'main', enabled: true, baseUrl: 'https://social.example', tokenSecret: 'TOKEN' }],
  });
  const store = new Store(db, mixed);
  const high = { ...item, scores: [{ score: 8, version: '3.1', issuer: 'nvd' }] };
  await store.ingest(high, now);
  const rss = { ...high, sourceId: 'alert' };
  const [first] = await store.ingest(rss, now);
  await store.createDelivery('individual', 'main', first!, false, now);
  await store.ingest({ ...rss, cves: [], modifiedAt: now + 1000 }, now + 1000);
  await store.publications.reconcileDeliveries(now + 1000);
  expect(await store.getDelivery('individual')).toMatchObject({ state: 'stale', error: 'individual_to_digest' });
  await store.ingest({ ...rss, modifiedAt: now + 2000 }, now + 2000);
  const restored = (await db
    .prepare('SELECT revision_id FROM threats WHERE key=?')
    .bind('CVE-2026-1111')
    .first<{ revision_id: string }>())!.revision_id;
  expect(restored).toBe(first);
  expect(await store.publications.decision((await store.getRevision(restored!))!, 'main')).toMatchObject({
    route: 'individual',
  });
  await store.publications.reconcileDeliveries(now + 2000);
  expect((await store.dueDeliveries(now + 2000)).map((delivery) => delivery.id)).toContain('individual');
});
