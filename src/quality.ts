import { z } from 'zod';
import type { Evidence, Summary, Validation } from './domain';
import { EXTRACTED_TAG_PATTERN, THEME_TAGS, USAGE_TAGS } from './social/tags';

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

const tagSchema = z.discriminatedUnion('kind', [
  claimSchema.extend({ kind: z.literal('usage'), text: z.enum(USAGE_TAGS) }),
  claimSchema.extend({ kind: z.literal('theme'), text: z.enum(THEME_TAGS) }),
  claimSchema.extend({ kind: z.literal('vendor'), text: z.string().regex(EXTRACTED_TAG_PATTERN) }),
  claimSchema.extend({ kind: z.literal('product'), text: z.string().regex(EXTRACTED_TAG_PATTERN) }),
]);

export const summarySchema = z
  .object({
    overview: claimSchema
      .nullable()
      .describe('問題や出来事の短い見出し。対象名はsubjectに分ける。CVSSなどが不明でも裏付ける本文があれば生成する。'),
    impact: claimSchema.nullable().describe('攻撃により起こる被害や影響。原文に記載がなければnull。'),
    action: claimSchema
      .nullable()
      .describe('修正適用・更新・回避策など、利用者が取るべき対処。原文に記載がなければnull。'),
    uncertainties: z
      .array(z.string().max(500))
      .max(10)
      .describe('必要な判断に影響する未確認事項を日本語で書く。特にない場合は空配列。'),
    subject: claimSchema.nullable().default(null).describe('出典に基づく対象メーカー・製品・製品群や話題の対象。'),
    actionKind: z
      .enum(['routine_update', 'unpatched', 'workaround', 'additional_steps', 'patch_warning'])
      .nullable()
      .default(null)
      .describe('対策の種類。通常更新、修正版未提供、具体的回避策、更新以外の追加作業、修正版の注意点。'),
    tags: z.array(tagSchema).max(6).default([]).describe('用途は最大1、テーマは最大2、メーカーは最大1、製品は最大2。'),
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
export function validateSummary(
  summary: Summary,
  evidence: Evidence[],
  key: string,
  options: { requireActionKind?: boolean } = {},
): Validation {
  const reasons: string[] = [];
  const tags = summary.tags ?? [];
  if (!summarySchema.safeParse(summary).success) {
    reasons.push('invalid_summary_structure');
  }
  for (const [kind, limit] of Object.entries({ usage: 1, theme: 2, vendor: 1, product: 2 })) {
    if (tags.filter((tag) => tag.kind === kind).length > limit) {
      reasons.push(`tags: too many ${kind}`);
    }
  }
  if (summary.actionKind && !summary.action) {
    reasons.push('action: missing classified action');
  }
  if (options.requireActionKind && summary.action && !summary.actionKind) {
    reasons.push('action: missing action kind');
  }

  for (const [field, claim] of Object.entries({
    subject: summary.subject,
    overview: summary.overview,
    impact: summary.impact,
    action: summary.action,
    ...Object.fromEntries(tags.map((tag, index) => [`tags.${index}`, tag])),
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
    if (field.startsWith('tags.') && 'kind' in claim && ['vendor', 'product'].includes(String(claim.kind))) {
      const name = claim.text.normalize('NFKC').toLowerCase();
      if (!quotes.some((quote) => quote.normalize('NFKC').toLowerCase().includes(name))) {
        reasons.push(`${field}: unsupported name`);
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
