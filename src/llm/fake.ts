import { z } from 'zod';
import { SUMMARY_SYSTEM } from './prompts';
import type { LlmProvider, LlmRequest, LlmResult } from './provider';

export class FakeLlmProvider implements LlmProvider {
  /** 推論せず根拠本文を抜粋し、ローカル疎通用の構造化要約を返す。意味検証には使用できない。 */
  async generateStructured<T>(request: LlmRequest, schema: z.ZodType<T>): Promise<LlmResult<T>> {
    if (request.system !== SUMMARY_SYSTEM) {
      throw new Error('fake_llm_supports_summary_only');
    }

    const data = z
      .object({
        key: z.string(),
        evidence: z.array(z.object({ id: z.string(), text: z.string() })),
      })
      .parse(request.data);
    const evidence = data.evidence.find((item) => item.text.trim().length >= 2);
    const quote = evidence?.text.trim().slice(0, 180);

    return {
      value: schema.parse({
        overview: quote && evidence ? { text: quote, evidence: [{ id: evidence.id, quote }] } : null,
        impact: null,
        action: null,
        uncertainties: ['Fake LLMによる本文抜粋です。AI要約・意味的な裏付け検証は未実施です。'],
      }),
    };
  }
}
