import { describe, expect, it } from 'vitest';
import { classify, materialKey, normalizeItem, publicationDay } from '../src/domain';
import { snapshot } from '../src/domain';
import { formatPost } from '../src/social/format';

const item = {
  sourceId: 'jvn',
  id: 'JVN1',
  url: 'https://jvn.jp/jp/JVN1/',
  title: 'Two flaws',
  text: 'CVE-2026-1111 and CVE-2026-2222 in Product.',
  publishedAt: 100,
  modifiedAt: 100,
  fetchedAt: 200,
  cves: ['CVE-2026-1111', 'CVE-2026-2222'],
  scores: [{ score: 8.1, version: '3.1', issuer: 'JVN' }],
  exploited: false,
  advisory: false,
  urgent: false,
  affected: null,
  remediation: null,
  rejected: false,
};

describe('security domain', () => {
  it('CVEを分割し共通の記述を記事全体の根拠として扱う', () => {
    const records = normalizeItem(item);
    expect(records.map((r) => r.key)).toEqual(['CVE-2026-1111', 'CVE-2026-2222']);
    expect(records[0]?.evidence.scope).toBe('article');
  });

  it('未採点の勧告を推測でCriticalや緊急扱いにしない', () => {
    expect(
      classify({
        scores: [],
        exploited: false,
        urgent: false,
        advisory: true,
        rejected: false,
      }),
    ).toEqual({
      eligible: true,
      priority: 3,
      severity: '未評価',
      urgent: false,
    });
    expect(
      classify({
        scores: [{ score: 9.8 }],
        exploited: false,
        urgent: false,
        advisory: false,
        rejected: false,
      }).urgent,
    ).toBe(false);
    expect(
      classify({
        scores: [],
        exploited: true,
        urgent: false,
        advisory: false,
        rejected: false,
      }).priority,
    ).toBe(0);
  });

  it('重要な改訂の判定では取得時刻、スコア、文面の変化を無視し公式の修正を検出する', () => {
    expect(materialKey(item)).toBe(materialKey({ ...item, fetchedAt: 999, text: 'Reformatted', scores: [] }));
    expect(materialKey(item)).not.toBe(materialKey({ ...item, remediation: 'Upgrade to 2.0' }));
  });

  it('日本時間の日付で投稿数を集計する', () => {
    expect(publicationDay(Date.parse('2026-10-27T15:00:00Z'))).toBe('2026-10-28');
  });

  it('公式の影響範囲の訂正を重要な改訂として扱う', () => {
    expect(materialKey({ ...item, impact: 'Remote code execution' })).not.toBe(
      materialKey({ ...item, impact: 'Denial of service only' }),
    );
  });

  it('記事全体のスコアや悪用フラグで全CVEの重要度を一律に引き上げない', () => {
    const records = normalizeItem({
      ...item,
      scores: [
        { score: 9.8, version: '3.1', issuer: 'JVN' },
        { score: 5.3, version: '3.1', issuer: 'JVN' },
      ],
      exploited: true,
      urgent: true,
    });
    for (const record of records) {
      const result = classify(snapshot(record.key, [record.evidence]));
      expect(result.eligible).toBe(false);
      expect(result.urgent).toBe(false);
      const text = formatPost({
        kind: 'new',
        key: record.key,
        title: 'Article',
        severity: result.severity,
        summary: {
          overview: null,
          impact: null,
          action: null,
          uncertainties: [],
        },
        sources: [],
      });
      expect(text).toContain('【未評価】');
    }
  });
});
