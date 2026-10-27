import { z } from 'zod';
import type { Evidence, Summary, Validation } from './domain';

const claimSchema = z
  .object({
    text: z
      .string()
      .min(1)
      .max(1500)
      .describe('開発者・運用者向けの簡潔な日本語。引用から裏付けられる内容だけを書く。'),
    evidence: z
      .array(z.object({ id: z.string().min(1), quote: z.string().min(2).max(4000) }).strict())
      .min(1)
      .max(10)
      .describe('根拠のidと、同じ根拠のtextまたはsectionsから一字も変えずに抜き出した引用。'),
  })
  .strict();

export const summarySchema = z
  .object({
    overview: claimSchema
      .nullable()
      .describe('対象製品と脆弱性の概要。CVSSや悪用状況が不明でも、概要を裏付ける本文があれば生成する。'),
    impact: claimSchema.nullable().describe('攻撃により起こる被害や影響。原文に記載がなければnull。'),
    action: claimSchema
      .nullable()
      .describe('修正適用・更新・回避策など、利用者が取るべき対処。原文に記載がなければnull。'),
    uncertainties: z
      .array(z.string().max(500))
      .max(10)
      .describe('必要な判断に影響する未確認事項を日本語で書く。特にない場合は空配列。'),
  })
  .strict();

export const verdictSchema = z
  .object({
    supported: z.boolean(),
    contradictions: z.array(z.string()),
    unsupportedClaims: z.array(z.string()),
  })
  .strict();

export type Verdict = z.infer<typeof verdictSchema>;

/** 外部評価結果に矛盾や未裏付けの主張がないか判定する。 */
export function validateVerdict(verdict: Verdict): boolean {
  return verdict.supported && verdict.contradictions.length === 0 && verdict.unsupportedClaims.length === 0;
}

/** 要約の引用と具体的な事実表現を収集根拠に照合する。 */
export function validateSummary(summary: Summary, evidence: Evidence[], key: string): Validation {
  const reasons: string[] = [];
  for (const [field, claim] of Object.entries({
    overview: summary.overview,
    impact: summary.impact,
    action: summary.action,
  })) {
    if (!claim) {
      continue;
    }

    const quotes: string[] = [];
    for (const ref of claim.evidence) {
      const item = evidence.find((e) => e.evidenceId === ref.id);
      if (!item || !item.text.includes(ref.quote)) {
        reasons.push(`${field}: fabricated evidence`);
        continue;
      }
      if (item.scope === 'article' && key.startsWith('CVE-') && !ref.quote.includes(key)) {
        reasons.push(`${field}: ambiguous multi-CVE evidence`);
      }
      quotes.push(ref.quote);
    }

    const facts = claim.text.match(/https?:\/\/[^\s]+|CVE-\d{4}-\d{4,}|\d+(?:\.\d+)*(?:[a-z]\d*)?/gi) ?? [];
    for (const fact of facts) {
      if (!quotes.some((q) => q.includes(fact))) {
        reasons.push(`${field}: unsupported literal ${fact}`);
      }
    }
  }

  if (!summary.overview) {
    reasons.push('overview_missing');
  }

  return {
    valid: reasons.length === 0,
    complete: Boolean(summary.overview && summary.impact && summary.action && summary.uncertainties.length === 0),
    reasons,
  };
}
