import { env } from 'cloudflare:test';
import { beforeEach, expect, it } from 'vitest';
import { z } from 'zod';
import { Bot } from '../src/pipeline';
import { loadConfig } from '../src/config';
import { PublishError } from '../src/social/provider';
import { UrlReferenceProvider } from '../src/social/url-reference';
import type { SourceItem } from '../src/domain';
import { VERIFY_SYSTEM } from '../src/llm/prompts';

const db = (env as unknown as { DB: D1Database }).DB;
const now = Date.parse('2026-10-28T00:00:00Z');
const boundary = now + 3 * 3600000;
const text = 'Acme 1.0 allows remote execution. Upgrade to 2.0.';
const item: SourceItem = {
  id: '1',
  sourceId: 'custom',
  url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1111',
  title: 'Acme',
  text,
  cves: ['CVE-2026-1111'],
  publishedAt: now,
  modifiedAt: now,
  fetchedAt: now,
  scores: [{ score: 8, version: '3.1', issuer: 'nvd' }],
  exploited: false,
  urgent: false,
  advisory: false,
  rejected: false,
  affected: 'Acme 1.0',
  remediation: 'Upgrade to 2.0.',
};
beforeEach(async () => {
  for (const table of [
    'digest_windows',
    'delivery_items',
    'publication_observations',
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
  ]) {
    await db.prepare(`DELETE FROM ${table}`).run();
  }
});
function harness(failure?: 'unknown' | 'second-unknown', maxCharacters = 2000) {
  const sent: string[] = [];
  const config = loadConfig({
    dryRun: false,
    publishing: { mode: 'nvd-high-digest' },
    mode: 'performance',
    sources: [{ id: 'custom', kind: 'nvd', enabled: false, url: 'https://example.com', pollIntervalSeconds: 7200 }],
    targets: [
      {
        id: 'main',
        enabled: true,
        baseUrl: 'https://social.example',
        tokenSecret: 'TOKEN',
        maxCharacters,
        normalIntervalSeconds: 60,
        minimumIntervalSeconds: 60,
        normalDailyLimit: 100,
      },
    ],
  });
  const bot = new Bot({ DB: db, JOBS: { async send() {} } }, config, {
    llm: {
      async generateStructured<T>(request: { system: string; data: unknown }, schema: z.ZodType<T>) {
        const claim = (value: string, quote: string) => ({
          text: value,
          evidence: [{ id: (request.data as { evidence: { id: string }[] }).evidence[0]!.id, quote }],
        });
        return {
          value: schema.parse(
            request.system === VERIFY_SYSTEM
              ? { supported: true, contradictions: [], unsupportedClaims: [] }
              : {
                  overview: claim('Acmeの脆弱性', text),
                  subject: claim('Acme', 'Acme'),
                  impact: claim('Acme 1.0でコード実行', 'Acme 1.0 allows remote execution.'),
                  action: claim('2.0へ更新', 'Upgrade to 2.0.'),
                  actionKind: 'routine_update',
                  uncertainties: [],
                },
          ),
          usage: { inputTokens: 1, outputTokens: 1 },
        };
      },
    },
    social: () => ({
      prepare: (intent) => new UrlReferenceProvider(maxCharacters).prepare(intent),
      async publish(post) {
        sent.push(post.text);
        if (failure === 'unknown' || (failure === 'second-unknown' && sent.length === 2)) {
          throw new PublishError('unknown', 'unknown_test');
        }
        return { id: String(sent.length), url: `https://social.example/notes/${sent.length}` };
      },
    }),
  });
  return { bot, sent };
}
async function drain(bot: Bot, at: number) {
  for (let step = 0; step < 30; step++) {
    const jobs = (
      await db
        .prepare("SELECT id FROM jobs WHERE state IN ('pending','deferred') AND available_at<=?")
        .bind(at)
        .all<{ id: string }>()
    ).results;
    if (!jobs.length) {
      return;
    }
    for (const job of jobs) {
      await bot.runJob(job.id, at);
    }
  }
  throw new Error('jobs_not_drained');
}
it('Highは6時間の区切りまで待ち、掲載後のCriticalを個別通知する', async () => {
  const { bot, sent } = harness();
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  expect(await bot.store.list('summaries'), JSON.stringify(await bot.store.list('jobs'))).toMatchObject([
    { validation: { valid: true } },
  ]);
  expect(sent).toEqual([]);
  await bot.tick(boundary - 1);
  await drain(bot, boundary - 1);
  expect(sent).toEqual([]);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain('NVD Highまとめ');
  expect(sent[0]).toContain('CVE-2026-1111');
  await bot.store.ingest(
    { ...item, modifiedAt: boundary + 60000, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] },
    boundary + 60000,
  );
  await bot.tick(boundary + 60000);
  await drain(bot, boundary + 60000);
  expect(sent).toHaveLength(2);
  expect(sent[1]).toContain('[Critical]');
  expect(sent[1]).toContain('https://social.example/notes/1');
});
it.each([
  { maxCharacters: 400, expectedCounts: [3, 3] },
  { maxCharacters: 2000, expectedCounts: [6] },
])(
  '投稿先の上限 $maxCharacters 文字で項目を分割し、4件を超えても収容する',
  async ({ maxCharacters, expectedCounts }) => {
    const { bot, sent } = harness(undefined, maxCharacters);
    for (let index = 1; index <= 6; index++) {
      await bot.store.ingest({ ...item, id: String(index), cves: [`CVE-2026-${1110 + index}`] }, now);
    }
    await bot.tick(now);
    await drain(bot, now);
    await bot.tick(boundary);
    await drain(bot, boundary);

    const deliveries = await bot.store.list('deliveries');
    const bodies = deliveries.map((delivery) => (JSON.parse(delivery.prepared!) as { text: string }).text);
    expect(bodies.map((body) => body.match(/・CVE-/g)?.length ?? 0).sort()).toEqual(expectedCounts);
    expect(bodies.every((body) => [...body].length <= maxCharacters)).toBe(true);
    expect(bodies.every((body) => !body.includes('[High]') && !body.includes('出典:'))).toBe(true);
    expect(sent[0]).toContain('・CVE-2026-1111｜新規｜CVSS 8\nAcme：Acmeの脆弱性\n影響: Acme 1.0でコード実行\n');
    const members = (
      await Promise.all(deliveries.map((delivery) => bot.store.publications.members(delivery.id)))
    ).flat();
    expect(members.map((member) => member.threat_key).sort()).toEqual([
      'CVE-2026-1111',
      'CVE-2026-1112',
      'CVE-2026-1113',
      'CVE-2026-1114',
      'CVE-2026-1115',
      'CVE-2026-1116',
    ]);
  },
);

it('まとめがunknownになっても次の期間へ自動で載せ直さない', async () => {
  const { bot, sent } = harness('unknown');
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  await bot.tick(boundary + 21600000);
  await drain(bot, boundary + 21600000);
  expect(sent).toHaveLength(1);
  expect((await bot.store.list('deliveries'))[0]?.state).toBe('unknown');
});
it('まとめ待ちのHighがCriticalになったらまとめから除く', async () => {
  const { bot, sent } = harness();
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.store.ingest(
    { ...item, modifiedAt: now + 1000, scores: [{ score: 9, version: '3.1', issuer: 'nvd' }] },
    now + 1000,
  );
  await bot.tick(now + 1000);
  await drain(bot, now + 1000);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain('[Critical]');
});
it('古い未評価CVEの初評価とMediumからHighへの昇格をまとめる', async () => {
  for (const initial of [0, 6]) {
    const { bot, sent } = harness();
    const older = { ...item, publishedAt: now - 864000000, modifiedAt: now - 86400000 };
    await bot.store.ingest(
      { ...older, scores: initial ? [{ score: initial, version: '3.1', issuer: 'nvd' }] : [] },
      now,
    );
    await bot.store.ingest({ ...older, modifiedAt: now + 1000 }, now + 1000);
    await bot.tick(now + 1000);
    await drain(bot, now + 1000);
    await bot.tick(boundary);
    await drain(bot, boundary);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toContain(initial ? 'High昇格' : '初評価');
    for (const table of [
      'digest_windows',
      'delivery_items',
      'publication_observations',
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
    ]) {
      await db.prepare(`DELETE FROM ${table}`).run();
    }
  }
});
it('High掲載後の同じ帯域での変更は再掲載しない', async () => {
  const { bot, sent } = harness();
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  await bot.store.ingest(
    {
      ...item,
      text: `${text} Additional wording.`,
      modifiedAt: boundary + 1000,
      scores: [{ score: 8.8, version: '3.1', issuer: 'nvd' }],
    },
    boundary + 1000,
  );
  await bot.tick(boundary + 21600000);
  await drain(bot, boundary + 21600000);
  expect(sent).toHaveLength(1);
});
it('まとめの品質が不足していた項目は合格後の次の期間で掲載する', async () => {
  const { bot, sent } = harness();
  const [id] = await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  const revision = (await bot.store.getRevision(id!))!;
  const cached = (await bot.store.getSummary(revision))!;
  await bot.store.saveSummary(revision, cached.summary, { valid: true, complete: false, reasons: ['incomplete'] }, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toEqual([]);
  await bot.store.saveSummary(revision, cached.summary, { valid: true, complete: true, reasons: [] }, boundary + 1);
  await bot.tick(boundary + 21600000);
  await drain(bot, boundary + 21600000);
  expect(sent).toHaveLength(1);
});
it('dry-runのまとめは掲載済み扱いせず本文と所属をプレビューできる', async () => {
  const { bot: original, sent } = harness();
  const bot = new Bot(original.env, { ...original.config, dryRun: true }, original.providers);
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toEqual([]);
  const delivery = (await bot.store.list('deliveries'))[0]!;
  expect(delivery.state).toBe('preview');
  expect(await bot.preview(delivery.id)).toMatchObject([{ allowed: true, members: [{ threat_key: 'CVE-2026-1111' }] }]);
  expect(
    await bot.store.publications.decision(
      (await bot.store.getRevision((await bot.store.publications.members(delivery.id))[0]!.revision_id))!,
      'main',
    ),
  ).toMatchObject({ route: 'digest' });
});
it('複数分割の一部がunknownでも成功した分割を再送せず残りを保持する', async () => {
  const { bot, sent } = harness('second-unknown', 200);
  for (let index = 1; index <= 3; index++) {
    await bot.store.ingest({ ...item, id: String(index), cves: [`CVE-2026-${1110 + index}`] }, now);
  }
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  await bot.tick(boundary + 60000);
  await drain(bot, boundary + 60000);
  const deliveries = await bot.store.list('deliveries');
  expect(deliveries.filter((delivery) => delivery.state === 'sent')).toHaveLength(1);
  expect(deliveries.filter((delivery) => delivery.state === 'unknown')).toHaveLength(1);
  expect(deliveries.filter((delivery) => delivery.state === 'ready')).toHaveLength(1);
  const unknown = deliveries.find((delivery) => delivery.state === 'unknown')!;
  await bot.store.finishDelivery(
    unknown.id,
    { id: 'resolved', url: 'https://social.example/notes/resolved' },
    boundary + 60000,
    unknown.lease_token!,
  );
  await bot.tick(boundary + 120000);
  await drain(bot, boundary + 120000);
  expect(sent).toHaveLength(2);
  await bot.tick(boundary + 360000);
  await drain(bot, boundary + 360000);
  expect(sent).toHaveLength(3);
  expect(new Set(sent).size).toBe(3);
  expect((await bot.store.list('deliveries')).every((delivery) => delivery.state === 'sent')).toBe(true);
});
it('同じCVEのまとめ掲載履歴を投稿先ごとに分ける', async () => {
  const { bot: original, sent } = harness();
  const bot = new Bot(
    original.env,
    { ...original.config, targets: [original.config.targets[0]!, { ...original.config.targets[0]!, id: 'other' }] },
    original.providers,
  );
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(2);
  expect((await bot.store.list('deliveries')).map((delivery) => delivery.target_id).sort()).toEqual(['main', 'other']);
});
it('滞留除外の境界より前にHighを掲載していても後日の却下訂正を通知する', async () => {
  const { bot, sent } = harness();
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  await bot.store.skipBefore(boundary + 30000, boundary + 30000);
  await bot.store.ingest({ ...item, rejected: true, modifiedAt: boundary + 60000 }, boundary + 60000);
  await bot.tick(boundary + 60000);
  await drain(bot, boundary + 60000);
  expect(sent).toHaveLength(2);
  expect(sent[1]).toContain('[訂正]');
  expect(sent[1]).toContain('https://social.example/notes/1');
});
it.each(['individual', 'digest'] as const)('送信中に更新された%s候補を確実な未送信失敗後に再開する', async (mode) => {
  const { bot: original, sent } = harness();
  let rejectFirst!: (error: unknown) => void;
  let begin!: () => void;
  const began = new Promise<void>((resolve) => {
    begin = resolve;
  });
  let attempts = 0;
  const bot = new Bot(original.env, original.config, {
    ...original.providers,
    social: (target) => {
      const provider = original.providers.social!(target);
      return {
        prepare: provider.prepare,
        async publish(post) {
          attempts++;
          if (attempts === 1) {
            begin();
            return new Promise<never>((_, reject) => {
              rejectFirst = reject;
            });
          }
          return provider.publish(post);
        },
      };
    },
  });
  const initial = mode === 'individual' ? { ...item, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] } : item;
  await bot.store.ingest(initial, now);
  if (mode === 'digest') {
    await bot.store.ingest({ ...item, id: '2', cves: ['CVE-2026-2222'] }, now);
  }
  await bot.tick(now);
  for (const job of (await bot.store.list('jobs')).filter((job) => job.type === 'analyze')) {
    await bot.runJob(job.id, now);
  }
  const sendingAt = mode === 'digest' ? boundary : now;
  if (mode === 'digest') {
    await bot.tick(boundary);
  }
  const publish = (await bot.store.list('jobs')).find((job) => job.type === 'publish' && job.state === 'pending')!;
  const running = bot.runJob(publish.id, sendingAt);
  await began;
  const [updated] = await bot.store.ingest(
    { ...initial, affected: 'Acme 1.0 revised', modifiedAt: sendingAt + 1000 },
    sendingAt + 1000,
  );
  await bot.store.enqueue('updated-analysis', 'analyze', { revisionId: updated }, sendingAt + 1000);
  await bot.runJob('updated-analysis', sendingAt + 1000);
  const pending = await bot.store.getJob('updated-analysis');
  // 応答待ちを終了してから検証し、失敗時も未解決Promiseをテスト外へ残さない。
  rejectFirst(new PublishError(mode === 'digest' ? 'rejected' : 'retry', 'definite_failure'));
  await running;
  expect(pending?.state).toBe('deferred');
  await bot.tick(sendingAt + 61000);
  await drain(bot, sendingAt + 61000);
  if (mode === 'digest') {
    await bot.tick(boundary + 21600000);
    await drain(bot, boundary + 21600000);
  }
  expect(sent).toHaveLength(1);
  if (mode === 'digest') {
    expect(sent[0]).toContain('CVE-2026-1111');
    expect(sent[0]).toContain('CVE-2026-2222');
  }
  expect((await bot.store.list('deliveries')).some((delivery) => delivery.state === 'sent')).toBe(true);
});
it('未解析のHighが鮮度期限を超えたら理由付きの保留ジョブを残す', async () => {
  const { bot: original } = harness();
  const bot = new Bot(original.env, { ...original.config, freshnessSeconds: 60 }, original.providers);
  await bot.store.ingest(item, now);
  await bot.tick(now);
  const job = (await bot.store.list('jobs')).find((job) => job.type === 'analyze')!;
  await bot.runJob(job.id, now + 61000);
  expect(await bot.store.getJob(job.id)).toMatchObject({ state: 'held', error: 'publication_event_expired' });
  expect(await bot.store.list('summaries')).toEqual([]);
  await bot.store.retryJob(job.id, now + 62000);
  await bot.runJob(job.id, now + 62000);
  expect(await bot.store.getJob(job.id)).toMatchObject({ state: 'held', error: 'publication_event_expired' });
});
it('個別方式のため停止した未送信まとめを再開時に配信する', async () => {
  const { bot, sent } = harness();
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  const publish = (await bot.store.list('jobs')).find((job) => job.type === 'publish' && job.state === 'pending')!;
  const legacy = new Bot(
    bot.env,
    { ...bot.config, publishing: { ...bot.config.publishing, mode: 'individual' } },
    bot.providers,
  );
  await legacy.runJob(publish.id, boundary);
  expect((await bot.store.list('deliveries'))[0]).toMatchObject({ state: 'held', error: 'digest_disabled' });
  await bot.tick(boundary + 60000);
  await drain(bot, boundary + 60000);
  expect(sent).toHaveLength(1);
  expect((await bot.store.list('deliveries'))[0]?.state).toBe('sent');
});
it('まとめに掲載済みの同じ改訂を個別方式へ切り替えても再投稿しない', async () => {
  const { bot, sent } = harness();
  await bot.store.ingest(item, now);
  await bot.tick(now);
  await drain(bot, now);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  const legacy = new Bot(
    bot.env,
    { ...bot.config, publishing: { ...bot.config.publishing, mode: 'individual' } },
    bot.providers,
  );
  await legacy.tick(boundary + 60000);
  await drain(legacy, boundary + 60000);
  expect(sent).toHaveLength(1);
  expect(await bot.store.list('deliveries')).toHaveLength(1);
});
it.each(['preview', 'held'] as const)('個別方式の未送信%sをまとめ方式へ切り替える', async (state) => {
  const { bot, sent } = harness();
  await bot.store.publications.initialize(now);
  const legacy = new Bot(
    bot.env,
    { ...bot.config, dryRun: true, publishing: { ...bot.config.publishing, mode: 'individual' } },
    bot.providers,
  );
  await legacy.store.ingest(item, now);
  await legacy.tick(now);
  await drain(legacy, now);
  const individual = (await legacy.store.list('deliveries'))[0]!;
  expect(individual.state).toBe('preview');
  if (state === 'held') {
    await legacy.store.holdDelivery(individual.id, 'test_hold', now);
  }
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain('NVD Highまとめ');
  expect((await bot.store.getDelivery(individual.id))?.state).toBe('stale');
});
it('悪用確認済みのHighでもCriticalへの昇格を別に通知する', async () => {
  const { bot, sent } = harness();
  const exploited = { ...item, exploited: true, urgent: true };
  await bot.store.ingest(exploited, now);
  await bot.tick(now);
  await drain(bot, now);
  expect(sent).toHaveLength(1);
  await bot.store.ingest(
    { ...exploited, modifiedAt: now + 360000, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] },
    now + 360000,
  );
  await bot.tick(now + 360000);
  await drain(bot, now + 360000);
  expect(sent).toHaveLength(2);
  expect(sent[1]).toContain('[Critical]');
});
it('未送信個別Highをまとめへ移行してから個別へ戻しても失わない', async () => {
  const { bot, sent } = harness();
  await bot.store.publications.initialize(now);
  const config = { ...bot.config, dryRun: true, publishing: { ...bot.config.publishing, mode: 'individual' as const } };
  const legacy = new Bot(bot.env, config, bot.providers);
  await legacy.store.ingest(item, now);
  await legacy.tick(now);
  await drain(legacy, now);
  const individual = (await legacy.store.list('deliveries'))[0]!;
  await bot.tick(now + 60000);
  expect((await bot.store.getDelivery(individual.id))?.state).toBe('stale');
  const live = new Bot(bot.env, { ...config, dryRun: false }, bot.providers);
  await live.tick(now + 120000);
  await drain(live, now + 120000);
  expect(sent).toHaveLength(1);
  expect((await live.store.getDelivery(individual.id))?.state).toBe('sent');
});
it('プレビューしたまとめを実配信へ切り替えたら現在の条件で送る', async () => {
  const { bot, sent } = harness();
  const preview = new Bot(bot.env, { ...bot.config, dryRun: true }, bot.providers);
  await preview.store.ingest(item, now);
  await preview.tick(now);
  await drain(preview, now);
  await preview.tick(boundary);
  await drain(preview, boundary);
  expect((await preview.store.list('deliveries'))[0]?.state).toBe('preview');
  await bot.tick(boundary + 60000);
  await drain(bot, boundary + 60000);
  expect(sent).toHaveLength(1);
  expect((await bot.store.list('deliveries'))[0]?.state).toBe('sent');
});
it('収集再開で古い更新から初めて悪用を確認した時刻を通知に使う', async () => {
  const { bot, sent } = harness();
  const old = { ...item, publishedAt: now - 10 * 86400000, modifiedAt: now - 10 * 86400000 };
  await bot.store.ingest(old, now);
  await bot.store.ingest(
    { ...old, modifiedAt: now - 5 * 86400000, fetchedAt: now + 1000, exploited: true, urgent: true },
    now + 1000,
  );
  await bot.tick(now + 1000);
  await drain(bot, now + 1000);
  expect(sent).toHaveLength(1);
  expect((await bot.store.list('deliveries'))[0]).toMatchObject({ urgent: 1, event_at: now + 1000 });
});
it('cutoff前にNVDが更新した昇格も再開後の初検知時刻で扱う', async () => {
  const { bot: original } = harness();
  const bot = new Bot(
    original.env,
    { ...original.config, sources: original.config.sources.map((source) => ({ ...source, enabled: true })) },
    original.providers,
  );
  await bot.store.ingest({ ...item, scores: [{ score: 6, version: '3.1', issuer: 'nvd' }] }, now);
  await bot.store.skipBefore(now + 1000, now + 1000);
  await bot.store.enqueue(
    'resumed-ingest',
    'ingest',
    { sourceId: 'custom', item: { ...item, modifiedAt: now + 500, fetchedAt: now + 2000 } },
    now + 2000,
  );
  await bot.runJob('resumed-ingest', now + 2000);
  const row = await db
    .prepare('SELECT revision_id FROM threats WHERE key=?')
    .bind('CVE-2026-1111')
    .first<{ revision_id: string }>();
  expect(await bot.store.publications.decision((await bot.store.getRevision(row!.revision_id))!, 'main')).toMatchObject(
    { route: 'digest', eventAt: now + 2000 },
  );
  expect((await bot.store.getJob('resumed-ingest'))?.error).toBeNull();
});
it('まとめの一部だけが期限切れになっても有効な項目を再構成して送る', async () => {
  const { bot: original, sent } = harness();
  const bot = new Bot(original.env, { ...original.config, freshnessSeconds: 86400 }, original.providers);
  const hour = 3600000;
  await bot.store.ingest({ ...item, publishedAt: now + 3 * hour, modifiedAt: now + 3 * hour }, now + 3 * hour);
  await bot.tick(now + 3 * hour);
  await drain(bot, now + 3 * hour);
  await bot.store.ingest(
    {
      ...item,
      id: '2',
      cves: ['CVE-2026-2222'],
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-2222',
      publishedAt: now + 8 * hour,
      modifiedAt: now + 8 * hour,
    },
    now + 8 * hour,
  );
  await bot.tick(now + 8 * hour);
  await drain(bot, now + 8 * hour);
  await bot.tick(now + 9 * hour);
  expect((await bot.store.list('deliveries')).find((delivery) => delivery.mode === 'digest')?.state).toBe('ready');
  await bot.tick(now + 27 * hour);
  await bot.tick(now + 28 * hour);
  await drain(bot, now + 28 * hour);
  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain('CVE-2026-2222');
  expect(sent[0]).not.toContain('CVE-2026-1111');
});
it.each(['nvd-high-digest', 'individual'] as const)(
  'cutoffで混在まとめを除外しても次の定時を待たず有効な項目を再構成する: %s',
  async (mode) => {
    const { bot: original, sent } = harness();
    const bot = new Bot(original.env, { ...original.config, freshnessSeconds: 86400 }, original.providers);
    const hour = 3600000;
    await bot.store.ingest({ ...item, publishedAt: now + 3 * hour, modifiedAt: now + 3 * hour }, now + 3 * hour);
    await bot.tick(now + 3 * hour);
    await drain(bot, now + 3 * hour);
    await bot.store.ingest(
      {
        ...item,
        id: '2',
        cves: ['CVE-2026-2222'],
        url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-2222',
        publishedAt: now + 8 * hour,
        modifiedAt: now + 8 * hour,
      },
      now + 8 * hour,
    );
    await bot.tick(now + 8 * hour);
    await drain(bot, now + 8 * hour);
    await bot.tick(now + 9 * hour);
    await bot.tick(now + 27 * hour);
    const delayed = now + 31.5 * hour;
    const cutoffBot = new Bot(
      bot.env,
      { ...bot.config, publishing: { ...bot.config.publishing, mode } },
      bot.providers,
    );
    await cutoffBot.store.skipBefore(now + 5 * hour, delayed);
    await bot.tick(delayed);
    await drain(bot, delayed);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toContain('CVE-2026-2222');
    expect(sent[0]).not.toContain('CVE-2026-1111');
  },
);
it('個別方式への一時切替中もcutoff前のNVD更新を観測し続ける', async () => {
  const { bot: original } = harness();
  await original.store.ingest({ ...item, scores: [{ score: 6, version: '3.1', issuer: 'nvd' }] }, now);
  const legacy = new Bot(
    original.env,
    {
      ...original.config,
      sources: original.config.sources.map((source) => ({ ...source, enabled: true })),
      publishing: { ...original.config.publishing, mode: 'individual' },
    },
    original.providers,
  );
  await legacy.store.skipBefore(now + 1000, now + 1000);
  await legacy.store.enqueue(
    'legacy-resumed-ingest',
    'ingest',
    { sourceId: 'custom', item: { ...item, modifiedAt: now + 500, fetchedAt: now + 2000 } },
    now + 2000,
  );
  await legacy.runJob('legacy-resumed-ingest', now + 2000);
  const row = await db
    .prepare('SELECT revision_id FROM threats WHERE key=?')
    .bind('CVE-2026-1111')
    .first<{ revision_id: string }>();
  expect(
    await original.store.publications.decision((await original.store.getRevision(row!.revision_id))!, 'main'),
  ).toMatchObject({ route: 'digest', eventAt: now + 2000 });
});
it('別方式で保留した解析ジョブを元の設定へ戻したら再評価する', async () => {
  const { bot, sent } = harness();
  const old = { ...item, publishedAt: now - 10 * 86400000, modifiedAt: now - 8 * 86400000 };
  await bot.store.ingest({ ...old, scores: [{ score: 6, version: '3.1', issuer: 'nvd' }] }, now);
  await bot.store.skipBefore(now, now);
  await bot.store.ingest({ ...old, modifiedAt: now - 4 * 86400000, fetchedAt: now + 1000 }, now + 1000);
  await bot.tick(now + 1000);
  const analysis = (await bot.store.list('jobs')).find((job) => job.type === 'analyze')!;
  const legacy = new Bot(
    bot.env,
    { ...bot.config, publishing: { ...bot.config.publishing, mode: 'individual' } },
    bot.providers,
  );
  await legacy.store.skipOldWork(now + 2000);
  expect((await bot.store.getJob(analysis.id))?.state).toBe('pending');
  await legacy.runJob(analysis.id, now + 2000);
  expect(await bot.store.getJob(analysis.id)).toMatchObject({ state: 'held', error: 'analysis_policy_changed' });
  await bot.tick(now + 3000);
  await drain(bot, now + 3000);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain('High昇格');
});
it.each([
  ['nvd', 9.8],
  ['rss', 8],
] as const)('新方式でも%sの個別プレビューを実配信へ移行する', async (kind, score) => {
  const { bot: original, sent } = harness();
  const preview = new Bot(
    original.env,
    { ...original.config, dryRun: true, sources: original.config.sources.map((source) => ({ ...source, kind })) },
    original.providers,
  );
  await preview.store.ingest({ ...item, scores: [{ score, version: '3.1', issuer: kind }] }, now);
  await preview.tick(now);
  await drain(preview, now);
  expect((await preview.store.list('deliveries'))[0]).toMatchObject({ mode: 'individual', state: 'preview' });
  const live = new Bot(preview.env, { ...preview.config, dryRun: false }, preview.providers);
  await live.tick(now + 60000);
  await drain(live, now + 60000);
  expect(sent).toHaveLength(1);
  expect((await live.store.list('deliveries'))[0]?.state).toBe('sent');
});
it('品質設定を変更した場合は保留中の個別配信を新設定で再評価する', async () => {
  const { bot: original, sent } = harness();
  const base = original.providers.llm!;
  const providers = {
    ...original.providers,
    llm: {
      async generateStructured<T>(request: Parameters<typeof base.generateStructured>[0], schema: z.ZodType<T>) {
        const result = await base.generateStructured(request, schema);
        return {
          ...result,
          value: schema.parse(
            request.system === VERIFY_SYSTEM
              ? result.value
              : { ...(result.value as Record<string, unknown>), impact: null },
          ),
        };
      },
    },
  };
  const bot = new Bot(original.env, original.config, providers);
  await bot.store.ingest({ ...item, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] }, now);
  await bot.tick(now);
  await drain(bot, now);
  expect(sent).toEqual([]);
  expect((await bot.store.list('deliveries'))[0]?.state).toBe('held');
  const relaxed = new Bot(
    bot.env,
    { ...bot.config, targets: bot.config.targets.map((target) => ({ ...target, qualityGate: { enabled: false } })) },
    bot.providers,
  );
  await relaxed.tick(now + 60000);
  await drain(relaxed, now + 60000);
  expect(sent).toHaveLength(1);
});
it('CVE関連の撤回中に要約が更新されても復旧した個別配信を送れる', async () => {
  const { bot: original, sent } = harness();
  const alert = { ...original.config.sources[0]!, id: 'alert', kind: 'rss' as const, url: 'https://example.com/rss' };
  const bot = new Bot(
    original.env,
    { ...original.config, sources: [...original.config.sources, alert] },
    original.providers,
  );
  const rss = { ...item, sourceId: 'alert' };
  const analyzeCve = async (at: number) => {
    for (const job of (await bot.store.list('jobs')).filter(
      (job) => job.type === 'analyze' && job.state === 'pending',
    )) {
      const record = (await bot.store.getJob(job.id))!;
      const { revisionId } = JSON.parse(record.payload) as { revisionId: string };
      if ((await bot.store.getRevision(revisionId))?.threat_key === 'CVE-2026-1111') {
        await bot.runJob(job.id, at);
      }
    }
  };
  await bot.store.ingest(item, now);
  await bot.store.ingest({ ...rss, modifiedAt: now + 1000 }, now + 1000);
  await bot.tick(now + 1000);
  await analyzeCve(now + 1000);
  const individual = (await bot.store.list('deliveries'))[0]!;
  await bot.store.ingest({ ...rss, cves: [], modifiedAt: now + 2000 }, now + 2000);
  await bot.tick(now + 2000);
  await analyzeCve(now + 2000);
  expect((await bot.store.getDelivery(individual.id))?.state).toBe('stale');
  await bot.store.ingest({ ...rss, modifiedAt: now + 3000 }, now + 3000);
  await bot.tick(now + 3000);
  await drain(bot, now + 3000);
  await bot.tick(now + 65000);
  await drain(bot, now + 65000);
  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain('CVE-2026-1111');
  expect((await bot.store.getDelivery(individual.id))?.state).toBe('sent');
});
it('同じHigh帯の根拠が元に戻っても現行要約を回復してまとめる', async () => {
  const { bot, sent } = harness();
  const revisions: string[] = [];
  for (const [index, score] of [8, 8.1, 8].entries()) {
    const at = now + index * 1000;
    revisions.push(
      (await bot.store.ingest({ ...item, modifiedAt: at, scores: [{ score, version: '3.1', issuer: 'nvd' }] }, at))[0]!,
    );
    await bot.tick(at);
    await drain(bot, at);
  }
  expect(new Set(revisions).size).toBe(1);
  await bot.tick(boundary);
  await drain(bot, boundary);
  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain('NVD Highまとめ');
  expect(await bot.store.getSummary((await bot.store.getRevision(revisions[0]!))!)).not.toBeNull();
});
it('根拠の更新途中では要約や送信を進めず確定後に再開する', async () => {
  const { bot, sent } = harness();
  const [id] = await bot.store.ingest({ ...item, scores: [{ score: 9.8, version: '3.1', issuer: 'nvd' }] }, now);
  await bot.tick(now);
  for (const job of (await bot.store.list('jobs')).filter((job) => job.type === 'analyze')) {
    await bot.runJob(job.id, now);
  }
  const revision = (await bot.store.getRevision(id!))!;
  const calls = (await bot.store.budgetStatus(now))?.calls;
  await db.prepare('UPDATE revisions SET evidence_hash=? WHERE id=?').bind('updating:test', id).run();
  await drain(bot, now);
  await bot.tick(now + 61000);
  await drain(bot, now + 61000);
  expect(sent).toEqual([]);
  expect((await bot.store.budgetStatus(now))?.calls).toBe(calls);
  await db.prepare('UPDATE revisions SET evidence_hash=? WHERE id=?').bind(revision.evidence_hash, id).run();
  await bot.tick(now + 122000);
  await drain(bot, now + 122000);
  expect(sent).toHaveLength(1);
});
