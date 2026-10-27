import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { Bot } from '../src/pipeline';
import { adminRequest } from '../src/admin';
import { loadConfig } from '../src/config';
import { Store } from '../src/store';
import { PublishError, UrlReferenceProvider } from '../src/social';
import type { LlmProvider, LlmRequest } from '../src/llm';
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
            ...(options.partial ? { impact: null, action: null } : {}),
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
  it('shares one verified summary across targets and publishes each target once', async () => {
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

  it('holds incomplete normal content but labels and publishes the relaxed target', async () => {
    const { bot, store, sent } = harness({ partial: true });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    const deliveries = await store.list('deliveries');
    expect(deliveries.find((d) => d.target_id === 'main')?.state).toBe('held');
    expect(deliveries.find((d) => d.target_id === 'unsafe')?.state).toBe('sent');
    expect(sent[0]?.summary.impact).toBeNull();
  });

  it('holds contradictions on both accounts', async () => {
    const { bot, store } = harness({ contradiction: true });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    expect((await store.list('deliveries')).every((d) => d.state === 'held')).toBe(true);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM attempts').first<{ n: number }>()).toEqual({ n: 0 });
  });

  it('creates dry-run previews without sending or consuming publication slots', async () => {
    const { bot, store } = harness({ dryRun: true });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    expect((await store.list('deliveries')).map((d) => d.state)).toEqual(['preview', 'preview']);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM quotas').first<{ n: number }>()).toEqual({ n: 0 });
  });

  it('does not summarize stale baseline information', async () => {
    const { bot, store } = harness();
    await store.ingest({ ...item, publishedAt: now - 864000000, modifiedAt: now - 864000000 }, now);
    await bot.tick(now);
    await processAll(bot, now);
    expect((await store.budgetStatus(now))?.calls ?? 0).toBe(0);
  });

  it('does not replay a possibly accepted send even after Cron recovery', async () => {
    const { bot, store } = harness({ failure: 'unknown' });
    await store.ingest(item, now);
    await bot.tick(now);
    await processAll(bot, now);

    expect((await store.list('deliveries')).map((d) => d.state)).toEqual(['unknown', 'unknown']);
    await bot.tick(now + 400000);
    await processAll(bot, now + 400000);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM attempts').first<{ n: number }>()).toEqual({ n: 2 });
  });

  it('does not pause retry B when expired attempt A returns an old authentication error', async () => {
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

  it('defers when the daily AI budget runs out instead of retrying in the Queue', async () => {
    const { bot, store } = harness();
    const budgetBot = new Bot(bot.env, { ...bot.config, budget: { ...bot.config.budget, maxCalls: 1 } }, bot.providers);
    await store.ingest(item, now);
    await budgetBot.tick(now);
    await processAll(budgetBot, now);
    expect((await store.list('jobs')).some((j) => j.state === 'deferred')).toBe(true);
    expect((await store.list('deliveries')).filter((d) => d.state === 'sent')).toHaveLength(0);
  });

  it('keeps the strict gate when shortening an otherwise valid post', async () => {
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
});

describe('management boundary', () => {
  it('returns job and delivery details by ID and reports missing records', async () => {
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

  it('denies missing auth and permits authenticated status', async () => {
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

  it('requires explicit acknowledgement to retry an unknown send', async () => {
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

  it('previews cached content without creating attempts even in live mode', async () => {
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
