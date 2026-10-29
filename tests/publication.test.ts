import { describe, expect, it } from 'vitest';
import { digestWindow, severityLevel, publicationRoute } from '../src/publication';
import { loadConfig } from '../src/config';

describe('発信方式と重大度', () => {
  it('HighとCriticalの境界を区別する', () => {
    expect([0, 6.9, 7, 8.9, 9, 10].map((score) => severityLevel([{ score }]))).toEqual([0, 1, 2, 2, 3, 3]);
  });
  it('情報源のkindと悪用確認から個別とまとめを選ぶ', () => {
    expect(publicationRoute(2, true, false)).toBe('digest');
    expect(publicationRoute(3, true, false)).toBe('individual');
    expect(publicationRoute(2, false, false)).toBe('individual');
    expect(publicationRoute(1, true, true)).toBe('individual');
  });
  it('JSTの6時間境界で閉じた窓を返す', () => {
    const boundary = Date.parse('2026-10-28T03:00:00Z');
    expect(digestWindow(boundary, 21600)).toEqual({ start: boundary - 21600000, end: boundary });
    expect(digestWindow(boundary - 1, 21600).end).toBe(boundary - 21600000);
  });
  it('設定を省略すると既存方式、明示すると6時間まとめを使う', () => {
    expect(loadConfig({}).publishing).toEqual({ mode: 'individual', digestIntervalSeconds: 21600 });
    expect(loadConfig({ publishing: { mode: 'nvd-high-digest' } }).publishing.digestIntervalSeconds).toBe(21600);
  });
});
