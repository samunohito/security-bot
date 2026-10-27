import type { Config } from '../config';
import { FakeLlmProvider } from './fake';
import type { AiBinding, LlmProvider } from './provider';
import { WorkersAiProvider } from './workers-ai';

/** 設定に応じたLLMを生成し、Workers AIのバインディング未設定時は未構成として返す。 */
export function createLlmProvider(config: Config['llm'], ai?: AiBinding): LlmProvider | undefined {
  if (config.provider === 'fake') {
    return new FakeLlmProvider();
  }

  return ai ? new WorkersAiProvider(ai, config) : undefined;
}
