import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { Bot } from '../src/pipeline';
import { adminRequest } from '../src/admin';
import { loadConfig } from '../src/config';
import { Store } from '../src/store';
import { PublishError } from '../src/social/provider';
import { UrlReferenceProvider } from '../src/social/url-reference';
import { SUMMARY_SYSTEM, VERIFY_SYSTEM } from '../src/llm/prompts';
import type { LlmProvider, LlmRequest } from '../src/llm/provider';
import type { PostIntent, SourceItem } from '../src/domain';

const db = (env as unknown as { DB: D1Database }).DB;
const now = Date.parse('2026-10-27T00:00:00Z');
const item: SourceItem = {
  sourceId: 'jvn',
  id: '1',
  url: 'https://jvn.jp/1',
  title: 'Acme',
  text: 'Acme 1.0 allows remote execution. Upgrade to 2.0.',
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
const claim = (text: string, quote: string) => ({
  text,
  evidence: [{ id: 'jvn:1', quote }],
});
const summary = {
  overview: claim('Acmeに脆弱性', 'Acme 1.0 allows remote execution.'),
  impact: claim('Acme 1.0が対象', 'Acme 1.0'),
  action: claim('2.0へ更新', 'Upgrade to 2.0.'),
  actionKind: 'routine_update' as const,
  uncertainties: [],
};
function makeConfig(dryRun = false) {
  return loadConfig({
    dryRun,
    sources: [],
    targets: [
      {
        id: 'main',
        enabled: true,
        baseUrl: 'https://social.example',
        tokenSecret: 'TOKEN',
      },
      {
        id: 'unsafe',
        enabled: true,
        baseUrl: 'https://social.example',
        tokenSecret: 'TOKEN',
        qualityGate: { enabled: false },
      },
    ],
  });
}
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
function harness(
  options: { partial?: boolean; contradiction?: boolean; failure?: 'unknown' | 'auth'; dryRun?: boolean } = {},
) {
  const sent: PostIntent[] = [],
    queue: string[] = [];
  const llm: LlmProvider = {
    async generateStructured<T>(_request: unknown, schema: z.ZodType<T>) {
      const value = schema.safeParse(summary).success
        ? {
            ...summary,
            ...(options.partial ? { impact: null, action: null, actionKind: null } : {}),
          }
        : {
            supported: !options.contradiction,
            contradictions: options.contradiction ? ['conflict'] : [],
            unsupportedClaims: [],
          };
      return {
        value: schema.parse(value),
        usage: { inputTokens: 100, outputTokens: 100 },
      };
    },
  };
  const bot = new Bot(
    {
      DB: db,
      JOBS: {
        async send(body: { id: string }) {
          queue.push(body.id);
        },
      },
    },
    makeConfig(options.dryRun),
    {
      llm,
      social: () => ({
        prepare(intent) {
          sent.push(intent);
          return new UrlReferenceProvider(500).prepare(intent);
        },
        async publish() {
          if (options.failure) {
            throw new PublishError(options.failure, 'test_failure');
          }
          return { id: 'note1', url: 'https://social.example/notes/note1' };
        },
      }),
    },
  );
  return { bot, queue, sent, store: new Store(db) };
}
async function processAll(bot: Bot, now: number) {
  for (let round = 0; round < 6; round++) {
    const rows = (
      await db
        .prepare("SELECT id FROM jobs WHERE state IN ('pending','deferred') AND available_at<=?")
        .bind(now)
        .all<{ id: string }>()
    ).results;
    if (!rows.length) {
      break;
    }

    for (const row of rows) {
      await bot.runJob(row.id, now);
    }
  }
}
describe('complete pipeline', () => {
  it.each([null, undefined])('新しく生成した対策に種別がなければ非表示のまま送らず保留する: %s', async (actionKind) => {
    const { bot: original, store } = harness();
    const bot = new Bot(original.env, original.config, {
      ...original.providers,
      llm: {
        async generateStructured<T>(request: LlmRequest, schema: z.ZodType<T>) {
          if (request.system === SUMMARY_SYSTEM) {
            return {
              value: schema.parse({ ...summary, subject: claim('Acme', 'Acme 1.0'), actionKind }),
              usage: { inputTokens: 100, outputTokens: 100 },
            };
          }
          return original.providers.llm!.generateStructured(request, schema);
        },
      },
    });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);
    expect((await store.list('deliveries')).map((delivery) => delivery.state)).toEqual(['held', 'held']);
  });

  it.each(['routine_update', 'workaround'] as const)(
    '対象・分類と対策種別を保存して意味検証し、投稿へ反映する: %s',
    async (actionKind) => {
      const { bot: original, store } = harness();
      const quoted = 'Acme is a VPN product. Disable its management interface as a workaround.';
      const metadata = {
        ...summary,
        subject: claim('Acme', 'Acme 1.0'),
        overview: claim('任意コード実行の脆弱性', 'Acme 1.0 allows remote execution.'),
        actionKind,
        action: actionKind === 'workaround' ? claim('管理画面を無効にしてください。', quoted) : summary.action,
        tags: [
          { kind: 'usage', ...claim('ネットワーク', quoted) },
          { kind: 'product', ...claim('Acme', 'Acme 1.0') },
        ],
      };
      const texts: string[] = [];
      const verified: unknown[] = [];
      const bot = new Bot(original.env, original.config, {
        llm: {
          async generateStructured<T>(request: LlmRequest, schema: z.ZodType<T>) {
            if (request.system === VERIFY_SYSTEM) {
              verified.push(request.data);
            } else {
              expect(request.system).toBe(SUMMARY_SYSTEM);
            }
            return {
              value: schema.parse(
                request.system === VERIFY_SYSTEM
                  ? { supported: true, contradictions: [], unsupportedClaims: [] }
                  : metadata,
              ),
              usage: { inputTokens: 100, outputTokens: 100 },
            };
          },
        },
        social: () => ({
          prepare: (intent) => new UrlReferenceProvider(500).prepare(intent),
          async publish(post) {
            texts.push(post.text);
            return { id: 'metadata', url: 'https://social.example/notes/metadata' };
          },
        }),
      });
      const [id] = await store.ingest({ ...item, text: `${item.text} ${quoted}` }, now);
      await bot.tick(now);
      await processAll(bot, now);

      expect(texts).toHaveLength(2);
      expect(texts[0]).toContain('[High] CVE-2026-1111\nAcme\n任意コード実行の脆弱性');
      expect(texts[0]).toContain('#ネットワーク #ACME');
      expect(texts[0]!.includes('対策:')).toBe(actionKind === 'workaround');
      expect(verified).toEqual([expect.objectContaining({ summary: metadata })]);
      const revision = (await store.getRevision(id!))!;
      expect((await store.getSummary(revision))?.summary).toEqual(metadata);
      expect((await store.budgetStatus(now))?.calls).toBe(2);
    },
  );

  it('改訂の保存日時が古くても最新更新が新しければ要約して投稿する', async () => {
    const { bot, store } = harness();
    const [id] = await store.ingest(item, now);
    await db
      .prepare('UPDATE revisions SET event_at=? WHERE id=?')
      .bind(now - 5 * 86400000, id)
      .run();
    await store.skipBefore(now - 6 * 3600000, now);
    await bot.tick(now);

    await processAll(bot, now);

    expect((await store.list('deliveries')).filter((delivery) => delivery.state === 'sent')).toHaveLength(2);
    expect((await store.budgetStatus(now))?.calls).toBe(2);
  });

  it('改訂の保存日時が新しくても最新更新が鮮度期限より古ければ要約しない', async () => {
    const { bot, store } = harness();
    const old = now - 5 * 86400000;
    const [id] = await store.ingest({ ...item, publishedAt: old, modifiedAt: old }, now);
    await db.prepare('UPDATE revisions SET event_at=? WHERE id=?').bind(now, id).run();
    await bot.tick(now);

    await processAll(bot, now);

    expect(await store.list('deliveries')).toEqual([]);
    expect((await store.budgetStatus(now))?.calls ?? 0).toBe(0);
  });

  it('足切りAPIは固定境界を保存し古いQueue配送を無視して新しい更新は処理する', async () => {
    const { bot, store } = harness();
    const clock = Date.now();
    const [oldId] = await store.ingest({ ...item, modifiedAt: clock - 7 * 3600000 }, clock);
    const response = await adminRequest(
      new Request('https://bot.example/admin/backlog/skip', {
        method: 'POST',
        headers: { Authorization: 'Bearer token' },
        body: JSON.stringify({ hours: 6 }),
      }),
      bot,
      'token',
    );
    expect(response?.status).toBe(200);
    const result = (await response!.json()) as { cutoff: number };
    expect(result.cutoff).toBeGreaterThanOrEqual(clock - 6 * 3600000);
    await store.enqueue('old-queued', 'analyze', { revisionId: oldId }, clock);
    await bot.runJob('old-queued', clock);
    expect(await store.getJob('old-queued')).toMatchObject({ state: 'done', error: 'skipped_before_cutoff' });
    expect(await store.budgetStatus(clock)).toBeNull();
    const [newId] = await store.ingest({ ...item, modifiedAt: clock, remediation: 'Upgrade to 3.0' }, clock);
    expect(newId).toBeDefined();
    await store.enqueue('new-queued', 'analyze', { revisionId: newId }, clock);
    await bot.runJob('new-queued', clock);
    expect((await store.budgetStatus(clock))?.calls).toBeGreaterThan(0);
  });

  it('要約生成中に境界が進んだら意味検証や配信作成へ進まない', async () => {
    const { bot: original, store } = harness();
    const [id] = await store.ingest({ ...item, modifiedAt: now - 2 }, now);
    let calls = 0;
    const bot = new Bot(original.env, original.config, {
      ...original.providers,
      llm: {
        async generateStructured<T>(request: LlmRequest, schema: z.ZodType<T>) {
          calls++;
          await store.skipBefore(now - 1, now);
          return original.providers.llm!.generateStructured(request, schema);
        },
      },
    });
    await store.enqueue('running-cutoff', 'analyze', { revisionId: id }, now);

    await bot.runJob('running-cutoff', now);

    expect(calls).toBe(1);
    expect(await store.list('deliveries')).toEqual([]);
    expect(await store.getJob('running-cutoff')).toMatchObject({ state: 'done' });
  });

  it.each([0, -1, '6', null])('足切りAPIは不正な時間数を拒否し境界を保存しない: %s', async (hours) => {
    const { bot, store } = harness();
    const response = await adminRequest(
      new Request('https://bot.example/admin/backlog/skip', {
        method: 'POST',
        headers: { Authorization: 'Bearer token' },
        body: JSON.stringify({ hours }),
      }),
      bot,
      'token',
    );
    expect(response?.status).toBe(400);
    expect(await store.eventCutoff()).toBe(0);
  });

  it('収集と要約が先に大量登録されても投稿を先にキューへ送る', async () => {
    const { bot, store, queue } = harness();
    bot.config.budget.queueOperations = 3;
    for (let index = 0; index < 25; index++) {
      await store.enqueue(`analyze:${index}`, 'analyze', { revisionId: 'missing' }, now - 1000);
    }
    await store.enqueue('collect:first', 'collect', { sourceId: 'jvn' }, now - 2000);
    await store.enqueue('publish:first', 'publish', { deliveryId: 'ready' }, now);

    await bot.flush(now);

    expect(queue).toEqual(['publish:first']);
    expect((await store.budgetStatus(now))?.queue_ops).toBe(3);
  });

  it.each(['calls', 'neurons'] as const)('AIの%s上限では未生成の要約を配送せず翌UTC日まで延期する', async (limit) => {
    const { bot, store, queue } = harness();
    const [id] = await store.ingest(item, now);
    await store.enqueue('analyze:waiting', 'analyze', { revisionId: id }, now);
    await db
      .prepare('INSERT INTO budgets(day,calls,neurons) VALUES(?,?,?)')
      .bind(
        '2026-10-27',
        limit === 'calls' ? bot.config.budget.maxCalls : 0,
        limit === 'neurons' ? bot.config.budget.neurons : 0,
      )
      .run();

    await bot.flush(now);
    await bot.flush(now + 60000);

    expect(queue).toEqual([]);
    expect(await store.getJob('analyze:waiting')).toMatchObject({
      state: 'deferred',
      attempts: 0,
      error: 'AI_daily_budget_exhausted',
      available_at: now + 86400000,
    });
    expect((await store.budgetStatus(now))?.queue_ops).toBe(0);
    await bot.flush(now + 86400000);
    expect(queue).toEqual(['analyze:waiting']);
  });

  it('AI予算切れでも検証済み要約から配信を作り実行中と直近配送済みの所有権を維持する', async () => {
    const { bot, store, queue } = harness();
    const [id] = await store.ingest(item, now);
    const revision = (await store.getRevision(id!))!;
    await store.saveSummary(revision, summary, { valid: true, complete: true, reasons: [] }, now);
    const [uncachedId] = await store.ingest({ ...item, id: '2', cves: ['CVE-2026-2222'] }, now);
    await store.enqueue('cached', 'analyze', { revisionId: id }, now);
    await store.enqueue('running', 'analyze', { revisionId: uncachedId }, now);
    const running = await store.claimJob('running', now);
    await store.enqueue('dispatched', 'analyze', { revisionId: uncachedId }, now);
    await store.markDispatched('dispatched', now);
    await db.prepare('INSERT INTO budgets(day,calls) VALUES(?,?)').bind('2026-10-27', bot.config.budget.maxCalls).run();

    await bot.flush(now);
    expect(queue).toEqual(['cached']);
    await bot.runJob('cached', now);
    expect((await store.list('deliveries')).map((delivery) => delivery.state)).toEqual(['ready', 'ready']);
    expect(await store.getJob('running')).toEqual(running);
    expect(await store.getJob('dispatched')).toMatchObject({ state: 'pending', dispatched_at: now, error: null });
    await bot.flush(now + 120001);
    expect(await store.getJob('dispatched')).toMatchObject({ state: 'deferred', attempts: 0 });
    expect(await store.getJob('running')).toEqual(running);
  });

  it('古い根拠のキャッシュとFake由来のキャッシュはAI予算切れで延期する', async () => {
    const { bot, store, queue } = harness();
    const [id] = await store.ingest(item, now);
    const revision = (await store.getRevision(id!))!;
    await store.saveSummary(
      { ...revision, evidence_hash: 'old' },
      summary,
      { valid: true, complete: true, reasons: [] },
      now,
    );
    await store.enqueue('stale', 'analyze', { revisionId: id }, now);
    const [fakeId] = await store.ingest({ ...item, id: '2', cves: ['CVE-2026-2222'] }, now);
    await store.saveSummary(
      (await store.getRevision(fakeId!))!,
      summary,
      { valid: false, complete: true, reasons: ['fake_provider'] },
      now,
    );
    await store.enqueue('fake', 'analyze', { revisionId: fakeId }, now);
    await db.prepare('INSERT INTO budgets(day,calls) VALUES(?,?)').bind('2026-10-27', bot.config.budget.maxCalls).run();

    await bot.flush(now);

    expect(queue).toEqual([]);
    expect(await store.getJob('stale')).toMatchObject({ state: 'deferred', attempts: 0 });
    expect(await store.getJob('fake')).toMatchObject({ state: 'deferred', attempts: 0 });
  });

  it('AI予算を使わないFake LLMのジョブは日次予算切れでも配送する', async () => {
    const { bot, store, queue } = harness();
    bot.config.llm.provider = 'fake';
    delete bot.providers.llm;
    const [id] = await store.ingest(item, now);
    await store.enqueue('fake', 'analyze', { revisionId: id }, now);
    await db.prepare('INSERT INTO budgets(day,calls) VALUES(?,?)').bind('2026-10-27', bot.config.budget.maxCalls).run();

    await bot.flush(now);

    expect(queue).toEqual(['fake']);
  });

  it('意味検証待ちのキャッシュはAI予算切れで配送前に延期する', async () => {
    const { bot, store, queue } = harness();
    const [id] = await store.ingest(item, now);
    await store.saveSummary(
      (await store.getRevision(id!))!,
      summary,
      { valid: false, complete: true, reasons: ['verification_pending'] },
      now,
    );
    await store.enqueue('verify', 'analyze', { revisionId: id }, now);
    await db.prepare('INSERT INTO budgets(day,calls) VALUES(?,?)').bind('2026-10-27', bot.config.budget.maxCalls).run();

    await bot.flush(now);

    expect(queue).toEqual([]);
    expect(await store.getJob('verify')).toMatchObject({ state: 'deferred', attempts: 0 });
  });

  it('設定のFake LLMで要約を生成し、意味検証を通過したことにはしない', async () => {
    const config = loadConfig({ sources: [], llm: { provider: 'fake' }, targets: [{ id: 'local', provider: 'fake' }] });
    const bot = new Bot(
      {
        DB: db,
        JOBS: { async send() {} },
        AI: {
          async run() {
            throw new Error('unexpected_AI_call');
          },
        },
      },
      config,
    );
    const [id] = await bot.store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    const revision = await bot.store.getRevision(id!);
    const cached = await bot.store.getSummary(revision!);
    expect(cached?.summary.overview?.text).toContain('Acme');
    expect(cached?.summary.uncertainties.join('')).toContain('Fake LLM');
    expect(cached?.validation.valid).toBe(false);
    expect((await bot.store.budgetStatus(now))?.neurons).toBe(0);
    expect((await bot.store.list('deliveries')).map((delivery) => delivery.state)).toEqual(['held']);
  });

  it('設定のFake投稿先はSecretなしでstdoutへ出力し配信を完了する', async () => {
    const { bot: original } = harness();
    const config = loadConfig({
      sources: [],
      dryRun: false,
      targets: [{ id: 'local', provider: 'fake', enabled: true }],
    });
    const bot = new Bot(original.env, config, { llm: original.providers.llm });
    const output: string[] = [];
    const log = vi.spyOn(console, 'log').mockImplementation((text) => {
      output.push(String(text));
    });
    try {
      await bot.store.ingest(item, now);
      await bot.tick(now);
      await processAll(bot, now);
      expect(output).toHaveLength(1);
      expect(output[0]).toContain('CVE-2026-1111');
      expect((await bot.store.list('deliveries')).map((delivery) => delivery.state)).toEqual(['sent']);
    } finally {
      log.mockRestore();
    }
  });

  it('Fakeから実LLMへ切り替えた場合はFake要約を再生成して品質検証する', async () => {
    const config = loadConfig({ sources: [], llm: { provider: 'fake' }, targets: [{ id: 'local', provider: 'fake' }] });
    const fake = new Bot({ DB: db, JOBS: { async send() {} } }, config);
    const [id] = await fake.store.ingest(item, now);
    await fake.tick(now);
    await processAll(fake, now);

    const { bot: real } = harness({ dryRun: true });
    await real.tick(now + 1000);
    await processAll(real, now + 1000);
    const cached = await real.store.getSummary((await real.store.getRevision(id!))!);
    expect(cached?.validation.valid).toBe(true);
    expect(cached?.summary.overview?.text).toBe('Acmeに脆弱性');
  });

  it('検証済みの要約を投稿先間で共有し各投稿先に一度だけ投稿する', async () => {
    const { bot, store } = harness();
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    const deliveries = await store.list('deliveries');
    expect(deliveries.map((d) => d.state)).toEqual(['sent', 'sent']);
    expect((await store.budgetStatus(now))?.calls).toBe(2);
    await bot.tick(now + 60000);
    await processAll(bot, now + 60000);
    expect((await store.list('deliveries')).filter((d) => d.state === 'sent')).toHaveLength(2);
  });

  it('不完全な内容は通常の投稿先では保留し緩和した投稿先では注記して投稿する', async () => {
    const { bot, store, sent } = harness({ partial: true });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    const deliveries = await store.list('deliveries');
    expect(deliveries.find((d) => d.target_id === 'main')?.state).toBe('held');
    expect(deliveries.find((d) => d.target_id === 'unsafe')?.state).toBe('sent');
    expect(sent[0]?.summary.impact).toBeNull();
  });

  it('矛盾する内容を両方のアカウントで保留する', async () => {
    const { bot, store } = harness({ contradiction: true });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    expect((await store.list('deliveries')).every((d) => d.state === 'held')).toBe(true);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM attempts').first<{ n: number }>()).toEqual({ n: 0 });
  });

  it('dry-runでは送信や投稿枠の消費をせずプレビューを作成する', async () => {
    const { bot, store } = harness({ dryRun: true });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    expect((await store.list('deliveries')).map((d) => d.state)).toEqual(['preview', 'preview']);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM quotas').first<{ n: number }>()).toEqual({ n: 0 });
  });

  it('古い初期基準の情報を要約しない', async () => {
    const { bot, store } = harness();
    await store.ingest({ ...item, publishedAt: now - 864000000, modifiedAt: now - 864000000 }, now);
    await bot.tick(now);
    await processAll(bot, now);
    expect((await store.budgetStatus(now))?.calls ?? 0).toBe(0);
  });

  it.each(['request', 'recording'] as const)(
    '配信失敗の段階と安全な診断情報をD1・ログに残し、unknownを再送しない: %s',
    async (phase) => {
      const { bot: original, store } = harness();
      let calls = 0;
      const bot = new Bot(original.env, original.config, {
        ...original.providers,
        social: (target) => ({
          ...original.providers.social!(target),
          async publish() {
            calls++;
            if (phase === 'request') {
              throw new PublishError('unknown', 'send_result_unknown', 0, {
                phase,
                reason: 'dns',
                exception: 'TypeError',
                code: 'ENOTFOUND',
              });
            }
            return { id: 'posted', url: 'https://social.example/notes/posted' };
          },
        }),
      });
      if (phase === 'recording') {
        vi.spyOn(bot.store, 'finishDelivery').mockRejectedValue(
          new Error('sensitive SQL or secret-token private-post'),
        );
      }
      const log = vi.spyOn(console, 'warn').mockImplementation(() => {});
      try {
        await store.ingest(item, now);
        await bot.tick(now);
        await processAll(bot, now);
        const rows = await store.list('deliveries');
        for (const row of rows) {
          expect(row.state).toBe('unknown');
          expect(JSON.parse(row.error!)).toMatchObject({
            reason: phase === 'request' ? 'send_result_unknown' : 'publication_or_recording_result_unknown',
            diagnostics: {
              phase,
              ...(phase === 'request' ? { reason: 'dns', code: 'ENOTFOUND' } : { exception: 'Error' }),
            },
          });
        }
        const messages = log.mock.calls.map(([text]) => JSON.parse(String(text)));
        expect(messages).toHaveLength(2);
        expect(messages[0]).toMatchObject({ event: 'publication_failed', kind: 'unknown', diagnostics: { phase } });
        expect(JSON.stringify(messages)).not.toContain('secret-token');
        expect(JSON.stringify(rows)).not.toContain('sensitive SQL');
        const attempts = await db.prepare('SELECT error FROM attempts').all<{ error: string }>();
        expect(attempts.results.map((row) => JSON.parse(row.error).diagnostics.phase)).toEqual([phase, phase]);
        await bot.tick(now + 400000);
        await processAll(bot, now + 400000);
        expect(calls).toBe(2);
      } finally {
        log.mockRestore();
      }
    },
  );

  it('受理された可能性がある送信はCronで復旧した後も再送しない', async () => {
    const { bot, store } = harness({ failure: 'unknown' });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    expect((await store.list('deliveries')).map((d) => d.state)).toEqual(['unknown', 'unknown']);
    await bot.tick(now + 400000);
    await processAll(bot, now + 400000);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM attempts').first<{ n: number }>()).toEqual({ n: 2 });
  });

  it('期限切れの試行Aが古い認証エラーを返しても再試行Bを停止しない', async () => {
    let rejectSend: ((reason: unknown) => void) | undefined;
    const config = { ...makeConfig(), targets: [makeConfig().targets[0]!] };
    const base = harness();
    const bot = new Bot(base.bot.env, config, {
      llm: base.bot.providers.llm,
      social: () => ({
        prepare: (intent) => new UrlReferenceProvider(500).prepare(intent),
        publish: () =>
          new Promise((_resolve, reject) => {
            rejectSend = reject;
          }),
      }),
    });
    const store = new Store(db);
    await store.ingest(item, now);
    await bot.tick(now);
    const analyze = (await store.list('jobs')).find((j) => j.type === 'analyze')!;
    await bot.runJob(String(analyze.id), now);
    const publish = (await store.list('jobs')).find((j) => j.type === 'publish')!;
    const running = bot.runJob(String(publish.id), now);
    const deliveryId = String((await store.list('deliveries'))[0]!.id);
    for (let i = 0; i < 50 && !rejectSend; i++) {
      await db.prepare('SELECT 1').first();
    }
    expect(rejectSend).toBeDefined();
    await store.recover(now + 301000);
    await store.retryDelivery(deliveryId, now + 302000);
    expect(await store.reserveDelivery(deliveryId, config.targets[0]!, now + 302000)).not.toBeNull();
    rejectSend!(new PublishError('auth', 'old_token_error'));
    await running;
    expect((await store.list('targets'))[0]?.paused).toBe(0);
  });

  it('AIの日次予算を使い切った場合はQueue内で再試行せず延期する', async () => {
    const { bot, store } = harness();
    const budgetBot = new Bot(bot.env, { ...bot.config, budget: { ...bot.config.budget, maxCalls: 1 } }, bot.providers);
    await store.ingest(item, now);
    await budgetBot.tick(now);
    await processAll(budgetBot, now);
    expect((await store.list('jobs')).some((j) => j.state === 'deferred')).toBe(true);
    expect((await store.list('deliveries')).filter((d) => d.state === 'sent')).toHaveLength(0);
  });

  it('有効な投稿を短縮する際も厳格な品質ゲートを維持する', async () => {
    const config = makeConfig();
    const llm: LlmProvider = {
      async generateStructured<T>(request: LlmRequest, schema: z.ZodType<T>) {
        const value = schema.safeParse(summary).success
          ? request.system.includes('at most 45')
            ? { ...summary, impact: null }
            : {
                ...summary,
                overview: { ...summary.overview, text: '脆弱性'.repeat(200) },
              }
          : { supported: true, contradictions: [], unsupportedClaims: [] };
        return {
          value: schema.parse(value),
          usage: { inputTokens: 100, outputTokens: 100 },
        };
      },
    };
    const bot = new Bot(
      {
        DB: db,
        JOBS: {
          async send() {},
        },
      },
      config,
      {
        llm,
        social: () => ({
          prepare: (intent) => new UrlReferenceProvider(500).prepare(intent),
          publish: async () => ({
            id: 'p',
            url: 'https://social.example/notes/p',
          }),
        }),
      },
    );
    const store = new Store(db);
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);
    expect((await store.list('deliveries')).find((d) => d.target_id === 'main')?.state).toBe('held');
  });

  it.each([null, 'workaround'] as const)(
    '短縮後も対策種別を検証し、合格した対象・タグ・回避策を再送準備で再利用する: %s',
    async (shortenedActionKind) => {
      const config = makeConfig();
      config.targets = config.targets.filter((target) => target.id === 'main');
      const quoted = 'Disable the management interface as a workaround.';
      const metadata = {
        ...summary,
        subject: claim('Acme', 'Acme 1.0'),
        action: claim('管理画面を無効にしてください。', quoted),
        actionKind: 'workaround',
        tags: [{ kind: 'product', ...claim('Acme', 'Acme 1.0') }],
      };
      const texts: string[] = [];
      const bot = new Bot({ DB: db, JOBS: { async send() {} } }, config, {
        llm: {
          async generateStructured<T>(request: LlmRequest, schema: z.ZodType<T>) {
            const value =
              request.system === VERIFY_SYSTEM
                ? { supported: true, contradictions: [], unsupportedClaims: [] }
                : request.system.includes('at most 45')
                  ? { ...metadata, actionKind: shortenedActionKind }
                  : { ...metadata, overview: claim('脆弱性'.repeat(200), 'Acme 1.0 allows remote execution.') };
            return { value: schema.parse(value), usage: { inputTokens: 100, outputTokens: 100 } };
          },
        },
        social: () => ({
          prepare: (intent) => new UrlReferenceProvider(250).prepare(intent),
          async publish(post) {
            texts.push(post.text);
            if (texts.length === 1) {
              throw new PublishError('retry', 'test_rate_limit', 60000);
            }
            return { id: 'short', url: 'https://social.example/notes/short' };
          },
        }),
      });
      const [id] = await bot.store.ingest({ ...item, text: `${item.text} ${quoted}` }, now);
      await bot.tick(now);
      await processAll(bot, now);
      const delivery = (await bot.store.list('deliveries'))[0]!;
      const revision = (await bot.store.getRevision(id!))!;
      const shortened = await bot.store.getShortened(delivery.id, revision.evidence_hash);

      if (shortenedActionKind === null) {
        expect(delivery.state).toBe('held');
        expect(shortened?.validation).toMatchObject({ valid: false, reasons: ['action: missing action kind'] });
        expect(texts).toEqual([]);
        return;
      }

      expect(shortened?.summary).toEqual(metadata);
      expect(texts).toHaveLength(1);
      expect(texts[0]).toContain('対策: 管理画面を無効にしてください。');
      expect(texts[0]).toContain('#ACME');
      const calls = (await bot.store.budgetStatus(now))?.calls;
      await bot.tick(now + 3600000);
      await processAll(bot, now + 3600000);
      expect(texts).toEqual([texts[0], texts[0]]);
      expect((await bot.store.budgetStatus(now))?.calls).toBe(calls);
      expect((await bot.store.list('deliveries'))[0]?.state).toBe('sent');
    },
  );
});

describe('management boundary', () => {
  it('保存済み要約を新しい順に直近50件返し、未生成と古い根拠の要約を除外する', async () => {
    const { bot, store } = harness();
    const get = () =>
      adminRequest(
        new Request('https://bot.example/admin/summaries', { headers: { Authorization: 'Bearer token' } }),
        bot,
        'token',
      );
    expect(await (await get())?.json()).toEqual([]);

    const ids: string[] = [];
    const invalid = { valid: false, complete: false, reasons: ['overview_missing'] };
    for (let index = 0; index < 53; index++) {
      const [id] = await store.ingest({ ...item, id: String(index), cves: [`CVE-2026-${1000 + index}`] }, now + index);
      ids.push(id!);
      if (index !== 52) {
        await store.saveSummary(
          (await store.getRevision(id!))!,
          summary,
          index === 50 ? invalid : { valid: true, complete: true, reasons: [] },
          now + index,
        );
      }
    }
    await db.prepare('UPDATE revisions SET evidence_hash=? WHERE id=?').bind('updated', ids[51]).run();

    const response = await get();
    expect(response?.status).toBe(200);
    expect(response?.headers.get('Cache-Control')).toBe('no-store');
    const rows = (await response?.json()) as { revisionId: string }[];
    expect(rows).toHaveLength(50);
    expect(rows.map((row) => row.revisionId)).toEqual(ids.slice(1, 51).reverse());
    expect(rows[0]).toMatchObject({
      revisionId: ids[50],
      key: 'CVE-2026-1050',
      evidenceHash: (await store.getRevision(ids[50]!))!.evidence_hash,
      status: 'generated',
      summary,
      validation: invalid,
      createdAt: now + 50,
    });
  });

  it('不合格の生成結果も取得でき、未生成と改訂不存在を区別する', async () => {
    const { bot, store } = harness();
    const [id] = await store.ingest(item, now);
    const get = (revisionId: string) =>
      adminRequest(
        new Request(`https://bot.example/admin/summaries/${revisionId}`, {
          headers: { Authorization: 'Bearer token' },
        }),
        bot,
        'token',
      );

    expect((await get('missing'))?.status).toBe(404);
    const empty = await get(id!);
    expect(empty?.status).toBe(200);
    expect(await empty?.json()).toMatchObject({
      revisionId: id,
      status: 'not_generated',
      summary: null,
      validation: null,
    });

    const generated = { overview: null, impact: null, action: null, uncertainties: ['未確認'] };
    await store.saveSummary(
      (await store.getRevision(id!))!,
      generated,
      { valid: false, complete: false, reasons: ['overview_missing'] },
      now,
    );
    const saved = await get(id!);
    expect(await saved?.json()).toMatchObject({
      revisionId: id,
      status: 'generated',
      summary: generated,
      validation: { valid: false, reasons: ['overview_missing'] },
    });
  });

  it('生成結果の取得と診断には管理認証を要求する', async () => {
    const { bot } = harness();
    expect((await adminRequest(new Request('https://bot.example/admin/summaries'), bot, 'token'))?.status).toBe(401);
    expect((await adminRequest(new Request('https://bot.example/admin/summaries/id'), bot, 'token'))?.status).toBe(401);
    expect(
      (
        await adminRequest(
          new Request('https://bot.example/admin/summaries/generate', { method: 'POST' }),
          bot,
          'token',
        )
      )?.status,
    ).toBe(401);
  });

  it('生成診断では保存済み不合格要約を再利用せず、配信やキャッシュを変更しない', async () => {
    const { bot, store } = harness();
    const [id] = await store.ingest(item, now);
    const revision = (await store.getRevision(id!))!;
    const saved = { overview: null, impact: null, action: null, uncertainties: [] };
    await store.saveSummary(revision, saved, { valid: false, complete: false, reasons: ['overview_missing'] }, now);
    const response = await adminRequest(
      new Request('https://bot.example/admin/summaries/generate', {
        method: 'POST',
        headers: { Authorization: 'Bearer token' },
        body: JSON.stringify({ id }),
      }),
      bot,
      'token',
    );
    expect(response?.status).toBe(200);
    expect(await response?.json()).toMatchObject({
      revisionId: id,
      summary,
      validation: { valid: true, complete: true },
      verdict: { supported: true },
      saved: false,
    });
    expect((await store.getSummary(revision))?.summary).toEqual(saved);
    expect(await store.list('jobs')).toEqual([]);
    expect(await store.list('deliveries')).toEqual([]);
  });

  it.each([false, true])(
    '保存を明示した合格要約を新規保存または上書きし、ジョブと配信を変更しない: 既存=%s',
    async (existing) => {
      const { bot, store } = harness();
      const [id] = await store.ingest(item, now);
      const revision = (await store.getRevision(id!))!;
      if (existing) {
        await store.saveSummary(
          revision,
          { ...summary, overview: null },
          { valid: false, complete: false, reasons: ['overview_missing'] },
          now,
        );
      }
      await store.enqueue('held-analysis', 'analyze', { revisionId: id }, now);
      await db.prepare("UPDATE jobs SET state='held' WHERE id='held-analysis'").run();
      await store.createDelivery('unknown-delivery', 'main', id!, false, now);
      await db.prepare("UPDATE deliveries SET state='unknown' WHERE id='unknown-delivery'").run();
      const jobsBefore = await store.list('jobs');
      const deliveriesBefore = await store.list('deliveries');

      const response = await adminRequest(
        new Request('https://bot.example/admin/summaries/generate', {
          method: 'POST',
          headers: { Authorization: 'Bearer token' },
          body: JSON.stringify({ id, save: true }),
        }),
        bot,
        'token',
      );
      expect(response?.status).toBe(200);
      expect(await response?.json()).toMatchObject({ saved: true, validation: { valid: true } });
      expect((await store.list('summaries'))[0]).toMatchObject({
        revisionId: id,
        summary,
        validation: { valid: true },
      });
      expect(await store.list('jobs')).toEqual(jobsBefore);
      expect(await store.list('deliveries')).toEqual(deliveriesBefore);
    },
  );

  it('意味検証が不合格なら保存を要求しても以前の要約を残す', async () => {
    const { bot, store } = harness({ contradiction: true });
    const [id] = await store.ingest(item, now);
    const revision = (await store.getRevision(id!))!;
    const previous = { ...summary, overview: null };
    await store.saveSummary(revision, previous, { valid: false, complete: false, reasons: ['overview_missing'] }, now);
    const result = await bot.generateSummary(id!, now + 1, { save: true });
    expect(result).toMatchObject({ saved: false, validation: { valid: false } });
    expect((await store.getSummary(revision))?.summary).toEqual(previous);
  });

  it('Fakeの診断結果は保存を要求しても保存しない', async () => {
    const { bot: original, store } = harness();
    const [id] = await store.ingest(item, now);
    const bot = new Bot(original.env, loadConfig({ llm: { provider: 'fake' } }));
    const result = await bot.generateSummary(id!, now, { save: true });
    expect(result).toMatchObject({
      saved: false,
      validation: { valid: false, reasons: expect.arrayContaining(['fake_provider']) },
    });
    expect(await store.getSummary((await store.getRevision(id!))!)).toBeNull();
  });

  it.each(['hash', 'current'])('事前確認後に根拠または現在改訂が変わっても保存時に拒否する: %s', async (change) => {
    const { bot, store } = harness();
    const [id] = await store.ingest(item, now);
    const revision = (await store.getRevision(id!))!;
    const previous = { ...summary, overview: null };
    await store.saveSummary(revision, previous, { valid: false, complete: false, reasons: [] }, now);
    const save = bot.store.saveCurrentSummary.bind(bot.store);
    vi.spyOn(bot.store, 'saveCurrentSummary').mockImplementationOnce(async (...args) => {
      if (change === 'hash') {
        await db.prepare('UPDATE revisions SET evidence_hash=? WHERE id=?').bind('changed', id).run();
      } else {
        await db.prepare('UPDATE threats SET revision_id=NULL WHERE revision_id=?').bind(id).run();
      }
      return save(...args);
    });
    const result = await bot.generateSummary(id!, now + 1, { save: true });
    expect(result).toMatchObject({
      saved: false,
      validation: { valid: false, reasons: expect.arrayContaining(['evidence_changed']) },
    });
    expect((await store.getSummary(revision))?.summary).toEqual(previous);
  });

  it('診断の予算が枯渇している場合はLLMを呼ばない', async () => {
    const { bot, store } = harness();
    const [id] = await store.ingest(item, now);
    await store.reserveBudget('exhausted', now, bot.config.budget.neurons, bot.config.budget);
    await expect(bot.generateSummary(id!, now)).rejects.toThrow('AI_daily_budget_exhausted');
    expect(await store.getSummary((await store.getRevision(id!))!)).toBeNull();
  });

  it('診断でも捏造引用を不合格にし、意味検証の呼び出しを行わない', async () => {
    const { bot: original, store } = harness();
    const [id] = await store.ingest(item, now);
    let calls = 0;
    const bot = new Bot(original.env, original.config, {
      llm: {
        async generateStructured<T>(_request: LlmRequest, schema: z.ZodType<T>) {
          calls++;
          return {
            value: schema.parse({ ...summary, overview: claim('不正な主張', '原文にない引用') }),
            usage: { inputTokens: 1, outputTokens: 1 },
          };
        },
      },
    });
    const result = await bot.generateSummary(id!, now);
    expect(result.validation.valid).toBe(false);
    expect(result.validation.reasons).toContain('overview: fabricated evidence');
    expect(result.verdict).toBeNull();
    expect(calls).toBe(1);
  });

  it('診断中に根拠が更新された場合は結果を有効と扱わない', async () => {
    const { bot: original, store } = harness();
    const [id] = await store.ingest(item, now);
    const llm = original.providers.llm!;
    let updated = false;
    const bot = new Bot(original.env, original.config, {
      llm: {
        async generateStructured<T>(request: LlmRequest, schema: z.ZodType<T>) {
          if (!updated) {
            updated = true;
            await store.ingest({ ...item, text: item.text + ' More information.', modifiedAt: now + 1000 }, now + 1000);
          }
          return llm.generateStructured(request, schema);
        },
      },
    });
    const result = await bot.generateSummary(id!, now, { save: true });
    expect(result.saved).toBe(false);
    expect(result.validation.valid).toBe(false);
    expect(result.validation.reasons).toContain('evidence_changed');
    expect(await store.list('deliveries')).toEqual([]);
  });

  it('IDでジョブと配信の詳細を返しレコードが存在しない場合は通知する', async () => {
    const { bot, store } = harness();
    const id = "quoted:'id";
    await store.enqueue(id, 'analyze', { revisionId: 'r' }, now);
    await store.createDelivery(id, 'main', 'r', false, now);

    for (const table of ['jobs', 'deliveries']) {
      const request = new Request(`https://bot.example/admin/${table}/${encodeURIComponent(id)}`, {
        headers: { Authorization: 'Bearer token' },
      });
      const response = await adminRequest(request, bot, 'token');
      expect(response?.status).toBe(200);
      expect(await response?.json()).toMatchObject({ id, lease_token: null, error: null });

      const missing = await adminRequest(
        new Request(`https://bot.example/admin/${table}/missing`, {
          headers: { Authorization: 'Bearer token' },
        }),
        bot,
        'token',
      );
      expect(missing?.status).toBe(404);
      expect(await missing?.json()).toEqual({ error: 'not_found' });
    }
  });

  it('認証のない要求を拒否し認証済みの状態取得を許可する', async () => {
    const { bot } = harness();
    expect((await adminRequest(new Request('https://bot.example/admin/status'), bot, 'token'))?.status).toBe(401);
    const response = await adminRequest(
      new Request('https://bot.example/admin/status', {
        headers: { Authorization: 'Bearer token' },
      }),
      bot,
      'token',
    );
    expect(response?.status).toBe(200);
    expect(await response?.json()).toHaveProperty('budget');
  });

  it('結果不明の送信を再試行するには明示的な確認を要求する', async () => {
    const { bot, store } = harness({ failure: 'unknown' });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);
    const id = String((await store.list('deliveries'))[0]!.id);
    const response = await adminRequest(
      new Request('https://bot.example/admin/deliveries/retry', {
        method: 'POST',
        headers: { Authorization: 'Bearer token' },
        body: JSON.stringify({ id }),
      }),
      bot,
      'token',
    );
    expect(response?.status).toBe(409);
    expect((await store.getDelivery(id))?.state).toBe('unknown');
  });

  it('本番モードでも送信試行を作らずキャッシュ済み内容をプレビューする', async () => {
    const { bot, store } = harness();
    const [id] = await store.ingest(item, now);
    const revision = (await store.getRevision(id!))!;
    await store.saveSummary(revision, summary, { valid: true, complete: true, reasons: [] }, now);
    const response = await adminRequest(
      new Request(`https://bot.example/admin/dry-run?id=${id}`, {
        headers: { Authorization: 'Bearer token' },
      }),
      bot,
      'token',
    );
    expect(response?.status).toBe(200);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM attempts').first<{ n: number }>()).toEqual({ n: 0 });
  });
});
