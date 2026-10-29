import { describe, expect, it } from 'vitest';
import { loadConfig, parseConfig } from '../src/config';

describe('configuration', () => {
  it('Queue保持期間は既定24時間で実Queueに合わせて変更できる', () => {
    expect(loadConfig().queue.messageRetentionSeconds).toBe(86400);
    expect(loadConfig({ queue: { messageRetentionSeconds: 172800 } }).queue.messageRetentionSeconds).toBe(172800);
  });

  it.each([0, 59, 1209601, 60.5])('不正なQueue保持期間%sを拒否する', (messageRetentionSeconds) => {
    expect(() => loadConfig({ queue: { messageRetentionSeconds } })).toThrow();
  });
  it('FakeのLLMと投稿先を実サービス用のモデル・接続先・Secretなしで検証する', () => {
    const config = loadConfig({ llm: { provider: 'fake' }, targets: [{ id: 'local', provider: 'fake' }] });
    expect(config.llm.provider).toBe('fake');
    expect(config.targets[0]?.provider).toBe('fake');
    expect(config.targets[0]?.enabled).toBe(false);
  });

  it('Fake LLMではカスタムモデルの料金係数を要求しない', () => {
    expect(loadConfig({ llm: { provider: 'fake', model: 'local' } }).llm.provider).toBe('fake');
  });

  it('Provider省略時は既存のWorkers AIとMisskeyを選択する', () => {
    const config = loadConfig({ targets: [{ id: 'main', baseUrl: 'https://social.example', tokenSecret: 'TOKEN' }] });
    expect(config.llm.provider).toBe('workers-ai');
    expect(config.targets[0]?.provider).toBe('misskey');
  });

  it.each([
    { llm: { provider: 'unknown' } },
    { targets: [{ id: 'main', provider: 'unknown' }] },
    { targets: [{ id: 'main', provider: 'misskey' }] },
    { llm: { provider: 'workers-ai', model: 'custom' } },
  ])('未知のProviderや実サービスの設定不足を拒否する: %j', (raw) => {
    expect(() => loadConfig(raw)).toThrow();
  });

  it('品質方針を変えずに明示設定やプリセットより環境変数を優先する', () => {
    const config = loadConfig(
      {
        mode: 'balanced',
        budget: { maxCalls: 55 },
        targets: [
          {
            id: 'unsafe',
            baseUrl: 'https://social.example',
            tokenSecret: 'TOKEN',
            qualityGate: { enabled: false },
          },
        ],
      },
      { BOT_MODE: 'performance', LLM_MAX_CALLS: '40' },
    );
    expect(config.budget.maxCalls).toBe(40);
    expect(config.budget.concurrency).toBe(5);
    expect(config.targets[0]?.qualityGate.enabled).toBe(false);
    expect(config.dryRun).toBe(true);
  });

  it('無料枠向けの保守的な既定値と情報源ごとの取得間隔を使う', () => {
    const config = loadConfig({}, {});
    expect(config.budget.maxCalls).toBe(20);
    expect(config.sources.find((s) => s.id === 'nvd')?.pollIntervalSeconds).toBe(7200);
    expect(config.sources.find((s) => s.id === 'jvn')?.pollIntervalSeconds).toBe(900);
  });

  it.each([0, 59, -10, 90.5, NaN])('不正な取得間隔 %s を拒否する', (value) => {
    expect(() => loadConfig({ pollIntervalSeconds: value }, {})).toThrow();
  });

  it('未知のモードと真偽が曖昧な環境変数の値を拒否する', () => {
    expect(() => loadConfig({}, { BOT_MODE: 'cheap' })).toThrow();
    expect(() => loadConfig({}, { DRY_RUN: 'maybe' })).toThrow();
  });
});

describe('JSONC設定', () => {
  it('コメントと末尾カンマを読み込み、URL内の記号を保持する', () => {
    const config = parseConfig(`{
      // 行コメント
      "dryRun": true,
      /* ブロックコメント */
      "targets": [{
        "id": "main",
        "baseUrl": "https://social.example/path//segment",
        "tokenSecret": "TOKEN",
      },],
    }`);
    expect(config.dryRun).toBe(true);
    expect(config.targets[0]?.baseUrl).toBe('https://social.example/path//segment');
  });

  it('通常のJSONも読み込み、環境変数による上書きを適用する', () => {
    expect(parseConfig('{"mode":"free"}', { BOT_MODE: 'balanced' }).mode).toBe('balanced');
  });

  it.each(['', '// コメントのみ', '{"dryRun": false', '{"mode": "free" "dryRun": true}', '{} trailing', '/* 未完了'])(
    '不正な構文を部分的な設定として受理しない: %j',
    (text) => {
      expect(() => parseConfig(text)).toThrow(SyntaxError);
    },
  );

  it('JSONCでも設定値の検証を適用する', () => {
    expect(() => parseConfig('{"pollIntervalSeconds": 59,}')).toThrow();
  });
});
