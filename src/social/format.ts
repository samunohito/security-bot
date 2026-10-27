import type { PostIntent } from '../domain';

function escapeText(text: string): string {
  return text.replace(/[@#$*`<>\[\]\\]/g, (s) => `${s}\u200b`);
}

/** 投稿意図を日本語のセキュリティ告知文に整形する。 */
export function formatPost(intent: PostIntent): string {
  const summary = intent.summary;
  const label = intent.kind === 'new' ? '' : intent.kind === 'correction' ? '訂正 ' : '更新 ';

  return [
    `【${label}${intent.severity}】${intent.key}`,
    escapeText(intent.title),
    `概要: ${escapeText(summary.overview?.text ?? '未確認')}`,
    `影響: ${escapeText(summary.impact?.text ?? '未確認')}`,
    `対策: ${escapeText(summary.action?.text ?? '未確認')}`,
    ...(summary.uncertainties.length ? [`未確認事項: ${escapeText(summary.uncertainties.join('／'))}`] : []),
    `出典: ${intent.sources.join('\n')}`,
  ].join('\n');
}
