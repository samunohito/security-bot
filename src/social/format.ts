import type { PostIntent, Summary } from '../domain';
import { formatHashtags } from './tags';

function escapeText(text: string): string {
  return text
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[@#$*`<>\[\]\\]/g, (s) => `${s}\u200b`);
}

function formatAction(summary: Summary): string {
  return summary.action &&
    ['unpatched', 'workaround', 'additional_steps', 'patch_warning'].includes(summary.actionKind ?? '')
    ? `対策: ${escapeText(summary.action.text)}`
    : '';
}

/** 検証済みのHighを、概要・影響・必要な例外情報を維持したまとめ用の項目に整形する。 */
export function formatDigestEntry(intent: PostIntent, reason: string, score: number): string {
  const summary = intent.summary;
  const subject = escapeText(summary.subject?.text ?? intent.title);
  const overview = summary.overview ? escapeText(summary.overview.text) : '概要: 未確認';

  return [
    `${intent.key}｜${escapeText(reason)}｜CVSS ${score}`,
    overview === subject ? subject : `${subject}：${overview}`,
    `影響: ${escapeText(summary.impact?.text ?? '未確認')}`,
    formatAction(summary),
    summary.uncertainties.length ? `未確認事項: ${escapeText(summary.uncertainties.join('／'))}` : '',
    ...intent.sources,
  ]
    .filter(Boolean)
    .join('\n');
}

/** 投稿意図を日本語のセキュリティ告知文に整形する。 */
export function formatPost(intent: PostIntent): string {
  const summary = intent.summary;
  const label = intent.kind === 'new' ? '' : intent.kind === 'correction' ? '[訂正] ' : '[更新] ';
  const hasCve = /^CVE-\d{4}-\d{4,}$/.test(intent.key);
  const subject = escapeText(summary.subject?.text ?? intent.title);
  const overview = summary.overview ? escapeText(summary.overview.text) : '概要: 未確認';
  const heading = [
    ...(hasCve ? [`${label}[${escapeText(intent.severity)}] ${intent.key}`] : []),
    `${hasCve ? '' : label}${subject}`,
    ...(overview !== subject ? [overview] : []),
  ].join('\n');

  return [
    heading,
    hasCve
      ? `影響: ${escapeText(summary.impact?.text ?? '未確認')}`
      : summary.impact
        ? escapeText(summary.impact.text)
        : '',
    formatAction(summary),
    summary.uncertainties.length ? `未確認事項: ${escapeText(summary.uncertainties.join('／'))}` : '',
    `出典: ${intent.sources.join('\n')}`,
    formatHashtags(summary.tags ?? []),
  ]
    .filter(Boolean)
    .join('\n\n');
}
