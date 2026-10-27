import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';

describe('configuration', () => {
  it('applies env over explicit settings and presets without changing quality policy', () => {
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

  it('uses conservative free defaults and per-source intervals', () => {
    const config = loadConfig({}, {});
    expect(config.budget.maxCalls).toBe(20);
    expect(config.sources.find((s) => s.id === 'nvd')?.pollIntervalSeconds).toBe(7200);
    expect(config.sources.find((s) => s.id === 'jvn')?.pollIntervalSeconds).toBe(900);
  });

  it.each([0, 59, -10, 90.5, NaN])('rejects invalid polling interval %s', (value) => {
    expect(() => loadConfig({ pollIntervalSeconds: value }, {})).toThrow();
  });

  it('rejects unknown modes and ambiguous boolean environment values', () => {
    expect(() => loadConfig({}, { BOT_MODE: 'cheap' })).toThrow();
    expect(() => loadConfig({}, { DRY_RUN: 'maybe' })).toThrow();
  });
});
