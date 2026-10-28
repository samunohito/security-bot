import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Store } from '../src/store';
import { loadConfig } from '../src/config';
import type { SourceItem } from '../src/domain';

const now = Date.parse('2026-10-27T00:00:00Z');
const db = (env as unknown as { DB: D1Database }).DB;
const store = new Store(db);
const target = loadConfig({
  targets: [
    {
      id: 'main',
      baseUrl: 'https://social.example',
      tokenSecret: 'TOKEN',
      enabled: true,
    },
  ],
}).targets[0]!;
const item: SourceItem = {
  sourceId: 'jvn',
  id: '1',
  url: 'https://jvn.jp/1',
  title: 'Flaw',
  text: 'Acme 1.0 is affected; upgrade to 2.0.',
  publishedAt: now,
  modifiedAt: now,
  fetchedAt: now,
  cves: ['CVE-2026-1111'],
  scores: [{ score: 8.1, version: '3.1', issuer: 'JVN' }],
  exploited: false,
  advisory: false,
  urgent: false,
  affected: 'Acme 1.0',
  remediation: 'Upgrade to 2.0',
  rejected: false,
};
beforeEach(async () => {
  await db.batch(
    [
      'source_versions',
      'shortened_summaries',
      'settings',
      'attempts',
      'deliveries',
      'summaries',
      'revisions',
      'evidence',
      'threats',
      'jobs',
      'sources',
      'targets',
      'quotas',
      'budget_reservations',
      'budgets',
    ].map((t) => db.prepare(`DELETE FROM ${t}`)),
  );
});

describe('durable work', () => {
  it('固定境界より古い未実行ジョブと配信だけを終了し履歴と所有権を保持する', async () => {
    const cutoff = now - 6 * 3600000;
    const [oldId] = await store.ingest({ ...item, modifiedAt: cutoff - 1 }, now);
    const [newId] = await store.ingest({ ...item, id: 'new', cves: ['CVE-2026-2222'], modifiedAt: cutoff }, now);
    await store.enqueue('old', 'analyze', { revisionId: oldId }, now);
    await store.enqueue('new', 'analyze', { revisionId: newId }, now);
    await store.enqueue('running', 'analyze', { revisionId: oldId }, now);
    const running = await store.claimJob('running', now);
    await store.enqueue('ingest', 'ingest', { sourceId: 'jvn', item: { ...item, modifiedAt: cutoff - 1 } }, now);
    await store.enqueue('collect', 'collect', { sourceId: 'jvn' }, now);
    for (const state of ['ready', 'held', 'preview', 'sending', 'unknown', 'sent']) {
      await store.createDelivery(state, state, oldId!, false, now, state);
    }
    await store.enqueue('publish', 'publish', { deliveryId: 'ready' }, now);

    const result = await store.skipBefore(cutoff, now);

    expect(result).toMatchObject({ cutoff, jobsSkipped: 3, deliveriesSkipped: 3 });
    expect(await store.getJob('old')).toMatchObject({ state: 'done', error: 'skipped_before_cutoff' });
    expect(await store.getJob('running')).toEqual(running);
    expect((await store.outbox(now)).map((job) => job.id).sort()).toEqual(['collect', 'new']);
    for (const state of ['sending', 'unknown', 'sent']) {
      expect((await store.getDelivery(state))?.state).toBe(state);
    }
    expect((await store.currentRevisions()).map((revision) => revision.id)).toEqual([newId]);
    expect(await store.getRevision(oldId!)).not.toBeNull();
    expect(await store.skipBefore(cutoff - 1, now)).toMatchObject({ cutoff, jobsSkipped: 0 });
  });

  it('足切り後に再投入された古いQueueジョブを取得せず理由付きで終了する', async () => {
    await store.skipBefore(now - 1, now);
    const [id] = await store.ingest({ ...item, modifiedAt: now - 2 }, now);
    await store.enqueue('late', 'analyze', { revisionId: id }, now);

    expect(await store.claimJob('late', now)).toBeNull();
    expect(await store.getJob('late')).toMatchObject({ state: 'done', attempts: 0, error: 'skipped_before_cutoff' });
    await store.createDelivery('late-delivery', 'main', id!, false, now);
    expect(await store.getDelivery('late-delivery')).toBeNull();
  });

  it('足切りした脅威の新しいスコア更新は別改訂として配信対象になる', async () => {
    const [oldId] = await store.ingest({ ...item, modifiedAt: now - 2 }, now);
    await store.createDelivery('old', 'main', oldId!, false, now);
    await store.skipBefore(now - 1, now);

    const [newId] = await store.ingest(
      { ...item, modifiedAt: now, scores: [{ score: 9.8, version: '3.1', issuer: 'JVN' }] },
      now,
    );

    expect(newId).not.toBe(oldId);
    expect((await store.currentRevisions()).map((revision) => revision.id)).toEqual([newId]);
    await store.createDelivery('new', 'main', newId!, false, now);
    expect((await store.getDelivery('new'))?.state).toBe('ready');
    expect((await store.getDelivery('old'))?.state).toBe('stale');
  });

  it('境界保存前に更新済みの根拠は古い改訂作成日時でも対象外にしない', async () => {
    const [id] = await store.ingest({ ...item, modifiedAt: now - 2 }, now);
    await store.ingest({ ...item, modifiedAt: now, scores: [{ score: 9.8, version: '3.1', issuer: 'JVN' }] }, now);
    await store.enqueue('updated', 'analyze', { revisionId: id }, now);

    await store.skipBefore(now - 1, now);

    expect((await store.currentRevisions()).map((revision) => revision.id)).toEqual([id]);
    expect(await store.getJob('updated')).toMatchObject({ state: 'pending' });
  });

  it('取り込みの境界読み取り後に足切りされても新しい更新を再判定する', async () => {
    const [oldId] = await store.ingest({ ...item, modifiedAt: now - 2 }, now);
    await store.createDelivery('old', 'main', oldId!, false, now);
    const spy = vi.spyOn(store, 'eventCutoff').mockImplementationOnce(async () => {
      await new Store(db).skipBefore(now - 1, now);
      return 0;
    });

    const [newId] = await store.ingest({ ...item, modifiedAt: now }, now);

    spy.mockRestore();
    expect(newId).not.toBe(oldId);
    await store.createDelivery('new', 'main', newId!, false, now);
    expect((await store.getDelivery('new'))?.state).toBe('ready');
    expect((await store.getDelivery('old'))?.state).toBe('stale');
  });

  it('境界設定と送信準備が競合しても古い配信の予約を拒否し予算と枠を消費しない', async () => {
    const [id] = await store.ingest({ ...item, modifiedAt: now - 2 }, now);
    await store.syncTargets([target]);
    await store.createDelivery('old', target.id, id!, false, now);
    await store.skipBefore(now - 1, now);
    await db.prepare("UPDATE deliveries SET state='ready' WHERE id='old'").run();

    expect(await store.reserveDelivery('old', target, now, (await store.getRevision(id!))!.evidence_hash)).toBeNull();
    expect((await store.list('targets'))[0]?.active_delivery).toBeNull();
    expect(await store.budgetStatus(now)).toBeNull();
  });

  it.each([NaN, Infinity, -1, now + 1])('不正な境界を保存せず拒否する: %s', async (cutoff) => {
    await expect(store.skipBefore(cutoff, now)).rejects.toThrow('invalid_event_cutoff');
    expect(await store.eventCutoff()).toBe(0);
  });

  it('JSONペイロードとnullのリースを含むジョブ詳細を返しIDが存在しなければnullを返す', async () => {
    const id = "job:'quoted";
    await store.enqueue(id, 'analyze', { revisionId: '日本語' }, now);

    expect(await store.getJob(id)).toMatchObject({
      id,
      payload: JSON.stringify({ revisionId: '日本語' }),
      state: 'pending',
      lease_token: null,
      error: null,
      attempts: 0,
    });
    expect(await store.getJob('missing')).toBeNull();
    expect(await store.getDelivery('missing')).toBeNull();
    expect(await store.getRevision('missing')).toBeNull();
  });

  it('キュー投入時のクラッシュから復旧し再配信による重複を防ぐ', async () => {
    await store.enqueue('one', 'analyze', { revisionId: 'r' }, now);
    await store.enqueue('one', 'analyze', { revisionId: 'r' }, now);

    expect(await store.outbox(now)).toHaveLength(1);
    await store.markDispatched('one', now);
    expect(await store.outbox(now + 120001)).toHaveLength(1);

    const [firstClaim, replayClaim] = await Promise.all([store.claimJob('one', now), store.claimJob('one', now)]);
    expect([firstClaim, replayClaim].filter(Boolean)).toHaveLength(1);
  });

  it('日時やスコアの変動では改訂を作らず情報源の最新の根拠を使う', async () => {
    const first = await store.ingest(item, now);
    await store.ingest({ ...item, fetchedAt: now + 1000 }, now + 1000);

    expect((await db.prepare('SELECT COUNT(*) AS n FROM revisions').first<{ n: number }>())?.n).toBe(1);

    const changed = await store.ingest(
      {
        ...item,
        modifiedAt: now + 2000,
        remediation: 'Upgrade to 3.0',
        text: 'Acme 1.0 is affected; upgrade to 3.0.',
      },
      now + 2000,
    );

    expect(changed[0]).not.toBe(first[0]);
    const snapshot = await store.getRevision(changed[0]!);
    expect(snapshot?.snapshot.evidence[0]?.text).toContain('3.0');
    expect(snapshot?.snapshot.evidence).toHaveLength(1);
    expect(snapshot?.snapshot.evidence[0]?.text).not.toContain('2.0');
  });

  it('新しい改訂を作成すると旧改訂の未送信配信を無効化する', async () => {
    const [oldId] = await store.ingest(item, now);
    await store.createDelivery('old-revision', 'main', oldId!, false, now);

    await store.ingest({ ...item, remediation: 'Upgrade to 3.0', modifiedAt: now + 1 }, now + 1);

    expect(await store.getDelivery('old-revision')).toMatchObject({ state: 'stale', error: 'superseded' });
  });

  it('予算を原子的に予約し結果不明の消費量を保持する', async () => {
    const budget = { maxCalls: 1, neurons: 100, concurrency: 1 };
    const results = await Promise.all([
      store.reserveBudget('a', now, 60, budget),
      store.reserveBudget('b', now, 60, budget),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await store.reserveBudget('c', now + 300000, 60, budget)).toBe(false);
    const winner = results[0] ? 'a' : 'b';
    await store.settleBudget(winner, 30);
    expect((await store.budgetStatus(now))?.neurons).toBe(30);
  });

  it('同じ予約IDで二重に消費計上しない', async () => {
    const budget = { maxCalls: 10, neurons: 1000, concurrency: 2 };
    await store.reserveBudget('same', now, 60, budget);
    await store.reserveBudget('same', now, 60, budget);
    expect((await store.budgetStatus(now))?.calls).toBe(1);
  });

  it('同時送信を防ぎ期限切れの送信中状態をunknownに移して再送しない', async () => {
    await store.syncTargets([target]);
    const [revision] = await store.ingest(item, now);
    await store.createDelivery('d1', target.id, revision!, false, now);
    await store.createDelivery('d2', target.id, revision! + 'other', false, now);

    const [firstReservation, competingReservation] = await Promise.all([
      store.reserveDelivery('d1', target, now),
      store.reserveDelivery('d2', target, now),
    ]);

    expect([firstReservation, competingReservation].filter(Boolean)).toHaveLength(1);
    await store.recover(now + 301000);
    const delivery = await store.getDelivery(firstReservation ? 'd1' : 'd2');

    expect(delivery?.state).toBe('unknown');
    expect(await store.reserveDelivery(delivery!.id, target, now + 400000)).toBeNull();
  });

  it('通常枠と緊急枠を別々に数え投稿先間で割当量を共有しない', async () => {
    const t = { ...target, normalDailyLimit: 1, urgentDailyLimit: 1 };
    await store.syncTargets([t, { ...t, id: 'other' }]);
    await store.createDelivery('normal', t.id, 'r1', false, now);
    expect(await store.reserveDelivery('normal', t, now)).not.toBeNull();
    await store.finishDelivery(
      'normal',
      { id: 'p1', url: 'https://social.example/notes/p1' },
      now,
      (await store.getDelivery('normal'))!.lease_token!,
    );
    await store.createDelivery('normal2', t.id, 'r2', false, now);
    expect(await store.reserveDelivery('normal2', t, now + 3600001)).toBeNull();
    await store.createDelivery('urgent', t.id, 'r3', true, now);
    expect(await store.reserveDelivery('urgent', t, now + 300001)).not.toBeNull();
    await store.createDelivery('independent', 'other', 'r4', false, now);
    expect(await store.reserveDelivery('independent', { ...t, id: 'other' }, now)).not.toBeNull();
  });

  it('同じアカウントでは準備済みの緊急配信を通常配信より優先する', async () => {
    await store.syncTargets([target]);
    await store.createDelivery('normal', target.id, 'r1', false, now);
    await store.createDelivery('urgent', target.id, 'r2', true, now);
    expect(await store.reserveDelivery('normal', target, now)).toBeNull();
    expect(await store.reserveDelivery('urgent', target, now)).not.toBeNull();
  });

  it('独立した緊急枠を使い切った後も通常枠で配信を続ける', async () => {
    const t = { ...target, urgentDailyLimit: 1 };
    await store.syncTargets([t]);
    await store.createDelivery('urgent1', t.id, 'r1', true, now);
    const first = (await store.reserveDelivery('urgent1', t, now))!;
    await store.finishDelivery(
      'urgent1',
      { id: 'first', url: 'https://social.example/notes/first' },
      now,
      first.lease_token!,
    );
    await store.createDelivery('urgent2', t.id, 'r2', true, now + 300001);
    await store.createDelivery('normal', t.id, 'r3', false, now + 300001);
    expect(await store.reserveDelivery('normal', t, now + 300001)).not.toBeNull();
  });

  it('CPU制限で繰り返し強制終了されるジョブを無限に再実行せず停止する', async () => {
    await store.enqueue('killed', 'collect', {}, now);
    for (let i = 0; i < 5; i++) {
      await store.claimJob('killed', now + i * 200000);
      await store.recover(now + i * 200000 + 190000);
    }
    expect((await store.list('jobs'))[0]?.state).toBe('held');
  });

  it('公式の複数CVE記事が単一CVEに訂正されたら対象外のCVEと情報源の所属関係を終了する', async () => {
    await store.ingest({ ...item, cves: ['CVE-2026-1111', 'CVE-2026-2222'] }, now);
    const old = await db
      .prepare('SELECT revision_id FROM threats WHERE key=?')
      .bind('CVE-2026-1111')
      .first<{ revision_id: string }>();
    await store.createDelivery('old', target.id, old!.revision_id, false, now);
    await store.ingest(
      {
        ...item,
        cves: ['CVE-2026-2222'],
        text: 'CVE-2026-2222 only',
        modifiedAt: now + 1000,
        fetchedAt: now + 1000,
      },
      now + 1000,
    );
    expect(
      await db
        .prepare('SELECT COUNT(*) AS n FROM evidence WHERE threat_key=? AND current=1')
        .bind('CVE-2026-1111')
        .first<{ n: number }>(),
    ).toEqual({ n: 0 });
    expect((await store.getDelivery('old'))?.state).toBe('held');
    expect((await store.getRevision(old!.revision_id))?.snapshot.evidence).toHaveLength(0);
    await store.ingest({ ...item, cves: ['CVE-2026-1111', 'CVE-2026-2222'] }, now + 2000);
    expect(
      await db
        .prepare('SELECT COUNT(*) AS n FROM evidence WHERE threat_key=? AND current=1')
        .bind('CVE-2026-1111')
        .first<{ n: number }>(),
    ).toEqual({ n: 0 });
  });

  it('明示的な再試行Bの開始後は期限切れの試行Aによる完了と失敗の更新を拒否する', async () => {
    await store.syncTargets([target]);
    await store.createDelivery('fenced', target.id, 'r', false, now);
    const expiredLease = (await store.reserveDelivery('fenced', target, now))!;
    await store.recover(now + 301000);
    await store.retryDelivery('fenced', now + 302000);
    const retryLease = (await store.reserveDelivery('fenced', target, now + 302000))!;
    expect(expiredLease.lease_token).not.toBe(retryLease.lease_token);
    await store.finishDelivery(
      'fenced',
      { id: 'late-a', url: 'https://social.example/notes/late-a' },
      now + 303000,
      expiredLease.lease_token!,
    );
    await store.deliveryError(
      'fenced',
      'retry',
      'late A failure',
      now + 304000,
      now + 305000,
      expiredLease.lease_token!,
    );
    expect((await store.getDelivery('fenced'))?.state).toBe('sending');
    expect((await store.getDelivery('fenced'))?.lease_token).toBe(retryLease.lease_token);
    expect(
      await db
        .prepare('SELECT used FROM quotas WHERE target_id=? AND bucket=?')
        .bind(target.id, 'normal')
        .first<{ used: number }>(),
    ).toEqual({ used: 2 });
  });

  it('重要な改訂を伴わず根拠が変わった準備済み内容を原子的に拒否する', async () => {
    await store.syncTargets([target]);
    const [id] = await store.ingest(item, now);
    const revision = (await store.getRevision(id!))!;
    await store.createDelivery('changed', target.id, id!, false, now);
    await store.ingest(
      {
        ...item,
        text: 'Corrected description',
        modifiedAt: now + 1000,
        fetchedAt: now + 1000,
      },
      now + 1000,
    );
    expect(await store.reserveDelivery('changed', target, now + 1000, revision.evidence_hash)).toBeNull();
  });

  it('期限切れの収集所有者による完了済みの継続処理の上書きを防ぐ', async () => {
    const source = loadConfig().sources.find((s) => s.id === 'nvd')!;
    await store.syncSources([source], now);
    const id = (await store.outbox(now))[0]!.id;
    const expiredClaim = (await store.claimJob(id, now))!;
    await store.recover(now + 190000);
    const continuationClaim = (await store.claimJob(id, now + 190001))!;
    await store.completeSource(
      source.id,
      { windowStart: now - 86400000, windowEnd: now, startIndex: 50 },
      now + 7200000,
      now + 190001,
      { id: 'page2', payload: { sourceId: source.id } },
      continuationClaim,
    );
    await store.finishJob(continuationClaim);
    const page2 = (await store.claimJob('page2', now + 190002))!;
    await store.completeSource(source.id, { completedThrough: now }, now + 7200000, now + 190002, undefined, page2);
    await store.finishJob(page2);
    await store.completeSource(
      source.id,
      { startIndex: 50 },
      now + 7200000,
      now + 190003,
      { id: 'page2', payload: { sourceId: source.id } },
      expiredClaim,
    );
    await store.sourceError(source.id, 'stale A failure', true, now + 190004, expiredClaim);
    expect(await store.sourceCursor(source.id)).toEqual({
      completedThrough: now,
    });
    expect((await store.sourceState(source.id))?.active_job).toBeNull();
    expect((await store.list('sources'))[0]?.last_error).toBeNull();
  });
});
