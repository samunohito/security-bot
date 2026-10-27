import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';

describe('configuration', () => {
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
