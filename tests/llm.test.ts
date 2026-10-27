import { describe, expect, it } from 'vitest';
import { evidencePrompt } from '../src/llm/evidence';
import type { Evidence } from '../src/domain';

const key = 'CVE-2026-1111';
const evidence: Evidence = {
  evidenceId: 'jvn:1',
  scope: 'cve',
  sourceId: 'jvn',
  id: '1',
  url: 'https://jvn.jp/1',
  title: key,
  text: `${'ナビゲーション '.repeat(400)}\n I. 概要\n${key} Acmeに脆弱性。\n影響\n任意のコードを実行される。\n対策\n修正済みバージョンへ更新してください。`,
  affected: null,
  impact: '任意のコードを実行される。',
  remediation: '修正済みバージョンへ更新してください。',
  cves: [key],
  scores: [],
  publishedAt: 0,
  modifiedAt: 0,
  fetchedAt: 0,
  exploited: false,
  advisory: false,
  urgent: false,
  rejected: false,
};

describe('LLMへ渡す根拠', () => {
  it('長いナビゲーションより本文の概要と影響・対策を優先し、引用可能な抜粋を渡す', () => {
    const result = evidencePrompt(key, [evidence]).evidence[0]!;
    expect(result.text).toContain(`${key} Acmeに脆弱性。`);
    expect(result.sections.impact).toBe('任意のコードを実行される。');
    expect(result.sections.remediation).toBe('修正済みバージョンへ更新してください。');
    for (const excerpt of [result.text, ...Object.values(result.sections)]) {
      if (excerpt) {
        expect(evidence.text).toContain(excerpt);
      }
    }
  });

  it('複数CVEの本文では対象CVEの近傍を渡し、存在しない抽出値は渡さない', () => {
    const result = evidencePrompt(key, [
      {
        ...evidence,
        scope: 'article',
        remediation: '根拠にない指示',
        text: `${'無関係な情報 '.repeat(500)}${key} 対象の説明`,
      },
    ]).evidence[0]!;
    expect(result.text).toContain(key);
    expect(result.scope).toBe('article');
    expect(result.sections.remediation).toBeNull();
  });

  it('根拠は4件まで、1件の抜粋合計は2200文字までに制限する', () => {
    const long = {
      ...evidence,
      text: 'a'.repeat(5000),
      affected: 'a'.repeat(900),
      impact: 'a'.repeat(900),
      remediation: 'a'.repeat(900),
    };
    const result = evidencePrompt(key, Array(8).fill(long));
    expect(result.evidence).toHaveLength(4);
    const first = result.evidence[0]!;
    expect(
      first.text.length + Object.values(first.sections).reduce((n, text) => n + (text?.length ?? 0), 0),
    ).toBeLessThanOrEqual(2200);
  });
});
