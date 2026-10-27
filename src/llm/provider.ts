import type { z } from 'zod';

export interface LlmRequest {
  system: string;
  data: unknown;
  maxOutputTokens?: number;
}

export interface LlmUsage {
  inputTokens: number;
  outputTokens: number;
}

export interface LlmResult<T> {
  value: T;
  usage?: LlmUsage;
}

export interface LlmProvider {
  /** 指定スキーマに合う構造化結果を生成する。 */
  generateStructured<T>(input: LlmRequest, schema: z.ZodType<T>): Promise<LlmResult<T>>;
}

export interface AiBinding {
  /** Cloudflare AIモデルを実行し、モデル固有の応答を返す。 */
  run(model: string, input: Record<string, unknown>): Promise<unknown>;
}
