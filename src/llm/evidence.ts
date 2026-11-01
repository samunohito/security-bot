import type { Evidence } from '../domain';

type SectionKind = 'affected' | 'impact' | 'remediation';

interface TextLine {
  start: number;
  end: number;
  text: string;
}

const sectionHeadings: Record<SectionKind, string[]> = {
  affected: ['影響を受けるシステム', '影響を受ける製品', '対象製品', 'Affected Products', 'Affected'],
  impact: ['想定される影響', '影響', 'Impact'],
  remediation: ['対策方法', '対策', '対処方法', '緩和策', 'Solutions', 'Mitigations', 'Workarounds'],
};
const otherHeadings = [
  '概要',
  '対象',
  '詳細情報',
  'ベンダ情報',
  '参考情報',
  '関連情報',
  '謝辞',
  '更新履歴',
  '改訂履歴',
  '侵害調査',
  'Overview',
  'Description',
  'Details',
  'References',
  'Acknowledgements',
  'Revision History',
];
const headingNumber = /^(?:(?:[IVXLCDM]+|[0-9０-９]+)(?:[.．、)）]|\s+)\s*|[（(][0-9０-９]+[)）]\s*)/i;

function clippedSection(value: string): string | null {
  if (value.length <= 400) {
    return value || null;
  }

  // 固定位置で切るとCVEや設定値が変わるため、完全な行・文が収まらなければ候補を渡さない。
  let end = 0;
  for (const match of value.matchAll(/\r\n|[\r\n]|[。！？]|[.!?](?=\s|$)/g)) {
    const boundary = match.index + match[0].length;
    if (boundary > 400) {
      break;
    }
    end = boundary;
  }

  return value.slice(0, end).trimEnd() || null;
}

function sectionQuote(evidence: Evidence, value: string | null | undefined): string | null {
  if (!value || !evidence.text.includes(value)) {
    return null;
  }

  return clippedSection(value);
}

function textLines(text: string): TextLine[] {
  return [...text.matchAll(/[^\r\n]+/g)].map((match) => ({
    start: match.index,
    end: match.index + match[0].length,
    text: match[0],
  }));
}

function heading(line: string): SectionKind | 'other' | null {
  const label = line
    .trim()
    .replace(/^#{1,6}\s+/, '')
    .replace(headingNumber, '')
    .replace(/\s*[:：]\s*$/, '')
    .toLowerCase();

  for (const kind of ['affected', 'impact', 'remediation'] as const) {
    if (sectionHeadings[kind].some((title) => title.toLowerCase() === label)) {
      return kind;
    }
  }

  // 平文では未知の番号付き見出しと手順を区別できないため、別の節の混入を避ける側に倒す。
  // CVE付き項目は見出しにせず、対象の選択と次CVEの境界判定に残す。
  return otherHeadings.some((title) => title.toLowerCase() === label) ||
    /^\s*#{1,6}\s+/.test(line) ||
    (headingNumber.test(line.trim()) && cves(line).length === 0)
    ? 'other'
    : null;
}

function cves(text: string): string[] {
  return (text.match(/\bCVE-\d{4}-\d{4,}\b/gi) ?? []).map((value) => value.toUpperCase());
}

function articleSections(key: string, text: string): Record<SectionKind, string | null> {
  const lines = textLines(text);
  const headings = lines.flatMap((line, index) => {
    const kind = heading(line.text);
    return kind ? [{ index, kind }] : [];
  });
  const target: Record<SectionKind, string[]> = { affected: [], impact: [], remediation: [] };
  const shared: Record<SectionKind, string[]> = { affected: [], impact: [], remediation: [] };

  for (const [index, entry] of headings.entries()) {
    if (entry.kind === 'other') {
      continue;
    }
    const body = lines.slice(entry.index + 1, headings[index + 1]?.index ?? lines.length);
    const explicit = body.findIndex((line) => cves(line.text).includes(key.toUpperCase()));
    if (explicit >= 0) {
      const remaining = body.slice(explicit);
      const next = remaining.findIndex(
        (line, offset) =>
          offset > 0 &&
          /^[\s\-*+•●○・\d０-９.．、()（）\[\]【】]*CVE-/i.test(line.text) &&
          cves(line.text)[0] !== key.toUpperCase(),
      );
      const end = next >= 0 ? remaining[next]!.start : remaining.at(-1)!.end;
      target[entry.kind].push(text.slice(remaining[0]!.start, end).trim());
    } else if (body.length && !body.some((line) => cves(line.text).length > 0)) {
      // CVE番号のない節は記事共通の参考情報。scopeや保存済みの帰属情報は変更しない。
      shared[entry.kind].push(text.slice(body[0]!.start, body.at(-1)!.end).trim());
    }
  }

  const select = (kind: SectionKind) =>
    target[kind].map(clippedSection).find((value) => value && cves(value).includes(key.toUpperCase())) ??
    shared[kind].map(clippedSection).find(Boolean) ??
    null;

  return { affected: select('affected'), impact: select('impact'), remediation: select('remediation') };
}

/** 原文の連続した抜粋だけを使い、本文の概要と影響・対策を文字数枠内で優先する。 */
export function evidencePrompt(key: string, evidence: Evidence[]) {
  return {
    key,
    evidence: evidence.slice(0, 4).map((item) => {
      const overview = item.text.search(/(?:^|\n)\s*(?:I\.\s*)?概要\s*(?:\r?\n|$)/m);
      const cve =
        [...item.text.matchAll(/\bCVE-\d{4}-\d{4,}\b/gi)].find((match) => match[0].toUpperCase() === key.toUpperCase())
          ?.index ?? -1;
      const start = item.scope === 'article' && cve >= 0 ? Math.max(0, cve - 150) : Math.max(0, overview);
      const sections = {
        affected: sectionQuote(item, item.affected),
        impact: sectionQuote(item, item.impact),
        remediation: sectionQuote(item, item.remediation),
      };
      if (item.scope === 'article' && Object.values(sections).some((value) => !value)) {
        const fallback = articleSections(key, item.text);
        sections.affected ??= fallback.affected;
        sections.impact ??= fallback.impact;
        sections.remediation ??= fallback.remediation;
      }

      return {
        id: item.evidenceId,
        scope: item.scope,
        cves: item.cves,
        url: item.url,
        text: item.text.slice(start, start + 1000),
        sections,
      };
    }),
  };
}
