import { describe, expect, it } from 'vitest';
import { validateSummary, summarySchema, validateVerdict } from '../src/quality';
import type { Evidence, Summary } from '../src/domain';

const evidence: Evidence[] = [
  {
    evidenceId: 'jvn:1',
    scope: 'cve',
    sourceId: 'jvn',
    id: '1',
    url: 'https://jvn.jp/1',
    title: 'Acme',
    text: 'Acme 1.0 allows remote execution. Upgrade to 2.0.',
    publishedAt: 0,
    modifiedAt: 0,
    fetchedAt: 0,
    cves: ['CVE-2026-1111'],
    scores: [],
    exploited: false,
    urgent: false,
    advisory: false,
    affected: 'Acme 1.0',
    remediation: 'Upgrade to 2.0',
    rejected: false,
  },
];
const claim = (text: string, quote: string) => ({
  text,
  evidence: [{ id: 'jvn:1', quote }],
});

describe('quality validation', () => {
  it('緩和方針の場合にのみ不完全な情報を許可する', () => {
    const summary = {
      overview: claim('Acmeに脆弱性', 'Acme 1.0 allows remote execution.'),
      impact: null,
      action: null,
      uncertainties: [],
    };
    const result = validateSummary(summary, evidence, 'CVE-2026-1111');
    expect(result.valid).toBe(true);
    expect(result.complete).toBe(false);
  });

  it('捏造されたバージョン、未知の情報源、架空の引用を拒否する', () => {
    const summary: Summary = {
      overview: claim('Acme 9.9に脆弱性', 'Acme 1.0 allows remote execution.'),
      impact: null,
      action: null,
      uncertainties: [],
    };
    expect(validateSummary(summary, evidence, 'CVE-2026-1111').valid).toBe(false);
    summary.overview = claim('脆弱性', 'not in source');
    expect(validateSummary(summary, evidence, 'CVE-2026-1111').valid).toBe(false);
    summary.overview = {
      text: '脆弱性',
      evidence: [{ id: 'evil', quote: 'Acme' }],
    };
    expect(validateSummary(summary, evidence, 'CVE-2026-1111').valid).toBe(false);
  });

  it('形式不正の出力、矛盾するレビュー、根拠のない複数CVEへの主張を保留する', () => {
    expect(summarySchema.safeParse({ overview: 'trust me' }).success).toBe(false);
    expect(
      validateVerdict({
        supported: true,
        contradictions: ['version conflict'],
        unsupportedClaims: [],
      }),
    ).toBe(false);
    const summary: Summary = {
      overview: claim('Acmeに脆弱性', 'Acme'),
      impact: claim('Acme 1.0が対象', 'Acme 1.0'),
      action: null,
      uncertainties: [],
    };
    expect(validateSummary(summary, [{ ...evidence[0]!, scope: 'article' }], 'CVE-2026-1111').valid).toBe(false);
  });
});
