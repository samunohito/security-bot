import { env } from 'cloudflare:test';
import { beforeEach, expect, it, vi } from 'vitest';
import { Bot } from '../src/pipeline';
import { loadConfig } from '../src/config';
import { Store } from '../src/store';

const db = (env as unknown as { DB: D1Database }).DB;
const now = Date.parse('2026-10-29T00:00:00Z');
const config = loadConfig({ sources: [], targets: [], llm: { provider: 'fake' } });
const store = new Store(db, config);

beforeEach(async () => {
  await db.batch(['jobs', 'budgets', 'settings'].map((table) => db.prepare(`DELETE FROM ${table}`)));
});

it('並行flushと長時間のQueue待機で同じジョブを追加送信しない', async () => {
  const sent: string[] = [];
  const bot = new Bot(
    {
      DB: db,
      JOBS: {
        async send(body) {
          sent.push(body.id);
        },
      },
    },
    config,
  );
  await store.enqueue('waiting', 'collect', { sourceId: 'test' }, now);

  await Promise.all(Array.from({ length: 5 }, () => bot.flush(now)));
  await bot.flush(now + 120001);
  await bot.flush(now + 3 * 3600000);

  expect(sent).toEqual(['waiting']);
  expect(await store.budgetStatus(now)).toMatchObject({ queue_ops: 3 });
});

it('配送権を取得できない競合と予算不足では予算もジョブも変更しない', async () => {
  await store.enqueue('one', 'collect', {}, now);
  await store.enqueue('two', 'collect', {}, now);
  const tokens = await Promise.all(Array.from({ length: 5 }, () => store.reserveDispatch('one', now, 3)));
  expect(tokens.filter(Boolean)).toHaveLength(1);
  expect(await store.reserveDispatch('two', now, 3)).toBeNull();
  expect(await store.getJob('two')).toMatchObject({ dispatched_at: null, dispatch_token: null });
  expect(await store.budgetStatus(now)).toMatchObject({ queue_ops: 3 });
});

it('送信開始前の中断は短いリース後に回復し旧所有者の送信開始を拒否する', async () => {
  await store.enqueue('one', 'collect', {}, now);
  const first = (await store.reserveDispatch('one', now, 100))!;
  expect(await store.reserveDispatch('one', now + 179999, 100)).toBeNull();
  const second = (await store.reserveDispatch('one', now + 180000, 100))!;
  expect(second).not.toBe(first);
  expect(await store.beginDispatch('one', first, now + 180000)).toBe(false);
  await store.markDispatched('one', now + 180000, first);
  await store.retryDispatch('one', first, now + 240000);
  expect(await store.getJob('one')).toMatchObject({ dispatch_token: second, dispatched_at: null });
});

it('送信開始後の中断は保持期間と猶予が過ぎるまで再投入しない', async () => {
  await store.enqueue('one', 'collect', {}, now);
  const token = (await store.reserveDispatch('one', now, 100))!;
  expect(await store.beginDispatch('one', token, now)).toBe(true);
  expect(await store.outbox(now + 3 * 3600000)).toHaveLength(0);
  expect(await store.outbox(now + 86400000 + 899999)).toHaveLength(0);
  expect(await store.outbox(now + 86400000 + 900000)).toHaveLength(1);
});

it('設定したQueue保持期間を待機期限に使う', async () => {
  const custom = new Store(db, loadConfig({ queue: { messageRetentionSeconds: 172800 } }));
  await custom.enqueue('one', 'collect', {}, now);
  const token = (await custom.reserveDispatch('one', now, 100))!;
  await custom.beginDispatch('one', token, now);
  expect(await custom.outbox(now + 86400000 + 900000)).toHaveLength(0);
  expect(await custom.outbox(now + 172800000 + 900000)).toHaveLength(1);
});

it('consumerの延期後に到着した旧senderの成功は次の実行を塞がない', async () => {
  await store.enqueue('one', 'collect', {}, now);
  const token = (await store.reserveDispatch('one', now, 100))!;
  await store.beginDispatch('one', token, now);
  const claimed = (await store.claimJob('one', now))!;
  await store.failJob(claimed, 'deferred', 'wait', now + 60000);
  await store.markDispatched('one', now + 1000, token);
  expect(await store.outbox(now + 60000)).toHaveLength(1);
});

it('Queue送信の結果が不明なら短周期に再送せず保存した期限を待つ', async () => {
  let sends = 0;
  const bot = new Bot(
    {
      DB: db,
      JOBS: {
        async send() {
          sends++;
          throw new Error('response_lost');
        },
      },
    },
    config,
  );
  await store.enqueue('one', 'collect', {}, now);
  await bot.flush(now);
  await bot.flush(now + 120001);
  expect(sends).toBe(1);
  expect(await store.budgetStatus(now)).toMatchObject({ queue_ops: 3 });
});

it.each(['Too Many Requests', 'Storage Limit Exceeded'])(
  'Queueからの明示的な拒否%sは1分後に再試行する',
  async (reason) => {
    let sends = 0;
    const bot = new Bot(
      {
        DB: db,
        JOBS: {
          async send() {
            sends++;
            if (sends === 1) {
              throw new Error(reason);
            }
          },
        },
      },
      config,
    );
    await store.enqueue('one', 'collect', {}, now);
    await bot.flush(now);
    await bot.flush(now + 59000);
    expect(sends).toBe(1);
    await bot.flush(now + 61000);
    expect(sends).toBe(2);
    expect(await store.budgetStatus(now)).toMatchObject({ queue_ops: 6 });
  },
);

it('Queue送信後の記録エラーは明示的な拒否と同じ文言でも再送しない', async () => {
  let sends = 0;
  const bot = new Bot(
    {
      DB: db,
      JOBS: {
        async send() {
          sends++;
        },
      },
    },
    config,
  );
  vi.spyOn(bot.store, 'markDispatched').mockRejectedValue(new Error('Too Many Requests'));
  await store.enqueue('one', 'collect', {}, now);
  await bot.flush(now);
  await bot.flush(now + 61000);
  expect(sends).toBe(1);
});
