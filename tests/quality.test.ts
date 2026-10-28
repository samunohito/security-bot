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
  const base: Summary = {
    overview: claim('Acmeに脆弱性', 'Acme 1.0 allows remote execution.'),
    impact: claim('任意のコードが実行される', 'Acme 1.0 allows remote execution.'),
    action: claim('更新してください', 'Upgrade to 2.0.'),
    uncertainties: [],
  };

  it('対象名・固定分類・抽出した製品名を引用付きで受け取り、旧要約も読める', () => {
    expect(summarySchema.safeParse(base).success).toBe(true);
    expect(
      summarySchema.safeParse({
        ...base,
        subject: claim('Acme', 'Acme 1.0 allows remote execution.'),
        actionKind: 'routine_update',
        tags: [{ kind: 'product', ...claim('Acme', 'Acme 1.0 allows remote execution.') }],
      }).success,
    ).toBe(true);
    expect(validateSummary(base, evidence, 'CVE-2026-1111')).toMatchObject({ valid: true, complete: true });
  });

  it.each(['.NET', 'AT&T', 'C#'])('記号を含む正当な抽出名称も引用付きで受け取る: %s', (text) => {
    const summary = { ...base, tags: [{ kind: 'product' as const, ...claim(text, text) }] };
    expect(summarySchema.safeParse(summary).success).toBe(true);
    expect(
      validateSummary(summary, [{ ...evidence[0]!, text: `${evidence[0]!.text} ${text}` }], 'CVE-2026-1111').valid,
    ).toBe(true);
  });

  it('対象名・タグにも架空の引用と複数CVEへの曖昧な帰属を許可しない', () => {
    const summary = {
      ...base,
      subject: claim('Acme', '架空の引用'),
      tags: [{ kind: 'product' as const, ...claim('Acme', 'Acme 1.0') }],
    };
    expect(validateSummary(summary, evidence, 'CVE-2026-1111').valid).toBe(false);
    expect(
      validateSummary({ ...base, tags: summary.tags }, [{ ...evidence[0]!, scope: 'article' }], 'CVE-2026-1111').valid,
    ).toBe(false);
  });

  it('引用にない製品名と固定候補にない分類を拒否する', () => {
    const tags = [{ kind: 'product' as const, ...claim('Other Product', 'Acme 1.0') }];
    expect(validateSummary({ ...base, tags }, evidence, 'CVE-2026-1111').valid).toBe(false);
    expect(
      summarySchema.safeParse({
        ...base,
        tags: [{ kind: 'usage', ...claim('勝手な分類', 'Acme 1.0') }],
      }).success,
    ).toBe(false);
  });

  it('用途の重複・テーマの過剰選択・対策本文のない例外指定を拒否する', () => {
    const ref = claim('ネットワーク', 'Acme 1.0');
    expect(
      validateSummary(
        {
          ...base,
          tags: [
            { ...ref, kind: 'usage' as const },
            { ...ref, kind: 'usage' as const },
          ],
        },
        evidence,
        'CVE-2026-1111',
      ).valid,
    ).toBe(false);
    expect(
      validateSummary(
        { ...base, tags: ['認証', '暗号', 'パス処理'].map((text) => ({ ...ref, text, kind: 'theme' as const })) },
        evidence,
        'CVE-2026-1111',
      ).valid,
    ).toBe(false);
    expect(
      validateSummary({ ...base, action: null, actionKind: 'unpatched' as const }, evidence, 'CVE-2026-1111').valid,
    ).toBe(false);
  });

  it('新規生成では対策種別を必須にし、旧要約の読み取りでは省略を許可する', () => {
    expect(validateSummary(base, evidence, 'CVE-2026-1111').valid).toBe(true);
    expect(validateSummary(base, evidence, 'CVE-2026-1111', { requireActionKind: true }).valid).toBe(false);
    expect(
      validateSummary({ ...base, actionKind: 'routine_update' as const }, evidence, 'CVE-2026-1111', {
        requireActionKind: true,
      }).valid,
    ).toBe(true);
  });

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
