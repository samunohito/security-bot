function japaneseTime(time: number): string {
  return new Date(time + 9 * 3600000).toISOString().slice(0, 16).replace('T', ' ');
}

/** 検証済みの項目を、期間・分割番号を含む文字数上限内のまとめ本文にする。 */
export function formatDigest(
  entries: { id: string; text: string }[],
  window: { start: number; end: number },
  maxCharacters: number,
  maxEntries = entries.length,
): { ids: string[]; text: string }[] {
  const header = `NVD Highまとめ ${japaneseTime(window.start)}〜${japaneseTime(window.end)} JST`;
  return paginateDigest(entries, header, '#NVD', maxCharacters, maxEntries);
}

/** KEVの追加件数と悪用確認を明示し、投稿先の上限内に分割する。 */
export function formatKevDigest(
  entries: { id: string; text: string }[],
  maxCharacters: number,
  maxEntries = entries.length,
): { ids: string[]; text: string }[] {
  return paginateDigest(
    entries,
    `CISA KEV追加 ${maxEntries}件（悪用確認済み）`,
    '出典: https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    maxCharacters,
    maxEntries,
  );
}

function paginateDigest(
  entries: { id: string; text: string }[],
  header: string,
  footer: string,
  maxCharacters: number,
  maxEntries: number,
) {
  const groups: (typeof entries)[] = [];
  let group: typeof entries = [];
  // 分割数の最大桁数を先に予約し、番号の確定で上限を超えないようにする。
  const digits = String(Math.max(entries.length, maxEntries)).length;
  const overhead = `${header} (${'9'.repeat(digits)}/${'9'.repeat(digits)})\n\n\n\n${footer}`.length;

  for (const entry of entries) {
    if ([...entry.text].length + overhead + 1 > maxCharacters) {
      throw new Error(`digest_item_too_long:${entry.id}`);
    }
    const next = [...group, entry];
    if ([...next.map((item) => `・${item.text}`).join('\n\n')].length + overhead > maxCharacters) {
      groups.push(group);
      group = [entry];
    } else {
      group = next;
    }
  }
  if (group.length) {
    groups.push(group);
  }

  return groups.map((items, index) => ({
    ids: items.map((item) => item.id),
    text: `${header} (${index + 1}/${groups.length})\n\n${items.map((item) => `・${item.text}`).join('\n\n')}\n\n${footer}`,
  }));
}
