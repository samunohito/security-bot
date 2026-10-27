import { z } from 'zod';
import type { Evidence, Summary, Validation } from './domain';
const claimSchema = z
  .object({
    text: z.string().min(1).max(1500),
    evidence: z
      .array(
        z
          .object({ id: z.string().min(1), quote: z.string().min(2).max(4000) })
          .strict(),
      )
      .min(1)
      .max(10),
  })
  .strict();
export const summarySchema = z
  .object({
    overview: claimSchema.nullable(),
    impact: claimSchema.nullable(),
    action: claimSchema.nullable(),
    uncertainties: z.array(z.string().max(500)).max(10),
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
export function validateVerdict(v: Verdict): boolean {
  return (
    v.supported &&
    v.contradictions.length === 0 &&
    v.unsupportedClaims.length === 0
  );
}
export function validateSummary(
  summary: Summary,
  evidence: Evidence[],
  key: string,
): Validation {
  const reasons: string[] = [];
  for (const [field, claim] of Object.entries({
    overview: summary.overview,
    impact: summary.impact,
    action: summary.action,
  })) {
    if (!claim) continue;
    const quotes: string[] = [];
    for (const ref of claim.evidence) {
      const item = evidence.find((e) => e.evidenceId === ref.id);
      if (!item || !item.text.includes(ref.quote)) {
        reasons.push(`${field}: fabricated evidence`);
        continue;
      }
      if (
        item.scope === 'article' &&
        key.startsWith('CVE-') &&
        !ref.quote.includes(key)
      )
        reasons.push(`${field}: ambiguous multi-CVE evidence`);
      quotes.push(ref.quote);
    }
    const facts =
      claim.text.match(
        /https?:\/\/[^\s]+|CVE-\d{4}-\d{4,}|\d+(?:\.\d+)*(?:[a-z]\d*)?/gi,
      ) ?? [];
    for (const fact of facts)
      if (!quotes.some((q) => q.includes(fact)))
        reasons.push(`${field}: unsupported literal ${fact}`);
  }
  if (!summary.overview) reasons.push('overview_missing');
  return {
    valid: reasons.length === 0,
    complete: Boolean(
      summary.overview &&
      summary.impact &&
      summary.action &&
      summary.uncertainties.length === 0,
    ),
    reasons,
  };
}
