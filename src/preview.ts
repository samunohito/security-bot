import type { Config } from './config';
import { classify, normalizeItem } from './domain';
import type { Fetcher } from './http';
import { FakeLlmProvider } from './llm/fake';
import { SUMMARY_SYSTEM } from './llm/prompts';
import { summarySchema, validateSummary } from './quality';
import { StdoutSocialProvider } from './social/stdout';
import { sourceProvider } from './sources';

/** 情報源の1件を取得し、永続化せずFake要約・根拠検証・投稿整形の結果を返す。 */
export async function preview(
  config: Config,
  options: { source: string; item?: string; key?: string },
  fetcher: Fetcher = fetch,
) {
  const source = config.sources.find((candidate) => candidate.id === options.source);
  if (!source) {
    throw new Error('unknown_preview_source');
  }

  const provider = sourceProvider(source, {}, fetcher, { initialLookbackSeconds: config.initialLookbackSeconds });
  const batch = await provider.collect({}, Date.now());
  const item = options.item ? batch.items.find((candidate) => candidate.id === options.item) : batch.items[0];
  if (!item) {
    throw new Error(options.item ? 'preview_item_not_found' : 'preview_no_items');
  }

  const hydrated = provider.hydrate ? await provider.hydrate(item) : item;
  const normalized = normalizeItem(hydrated);
  const selected = options.key ? normalized.find((entry) => entry.key === options.key) : normalized[0];
  if (!selected) {
    throw new Error('preview_key_not_found');
  }

  const { key, evidence } = selected;
  const classification = classify(evidence);
  const { value: summary } = await new FakeLlmProvider().generateStructured(
    {
      system: SUMMARY_SYSTEM,
      data: { key, evidence: [{ id: evidence.evidenceId, text: evidence.text }] },
    },
    summarySchema,
  );
  const validation = validateSummary(summary, [evidence], key);
  const post = new StdoutSocialProvider().prepare({
    kind: 'new',
    key,
    title: evidence.title,
    severity: classification.severity,
    summary,
    sources: [evidence.url],
  });

  return {
    mode: 'fake' as const,
    semanticVerification: 'not_performed' as const,
    sourceId: source.id,
    itemId: item.id,
    key,
    classification,
    summary,
    validation,
    post,
  };
}
