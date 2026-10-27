import { describe, expect, it } from 'vitest';
import { classify, materialKey, normalizeItem, publicationDay } from '../src/domain';
import { snapshot } from '../src/domain';
import { formatPost } from '../src/social';

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
  it('splits CVEs but marks shared statements as article-wide evidence', () => {
    const records = normalizeItem(item);
    expect(records.map((r) => r.key)).toEqual(['CVE-2026-1111', 'CVE-2026-2222']);
    expect(records[0]?.evidence.scope).toBe('article');
  });
  it('does not turn unscored advisories into Critical or urgent by inference', () => {
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
  it('material revisions ignore fetch time, scores and prose but capture official fixes', () => {
    expect(materialKey(item)).toBe(materialKey({ ...item, fetchedAt: 999, text: 'Reformatted', scores: [] }));
    expect(materialKey(item)).not.toBe(materialKey({ ...item, remediation: 'Upgrade to 2.0' }));
  });
  it('counts publications in Japan days', () => {
    expect(publicationDay(Date.parse('2026-10-27T15:00:00Z'))).toBe('2026-10-28');
  });
  it('treats an official impact correction as a material revision', () => {
    expect(materialKey({ ...item, impact: 'Remote code execution' })).not.toBe(
      materialKey({ ...item, impact: 'Denial of service only' }),
    );
  });
  it('never promotes every CVE using article-wide scores or exploitation flags', () => {
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
