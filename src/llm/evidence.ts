import type { Evidence } from '../domain';

type SectionKind = 'affected' | 'impact' | 'remediation';

interface TextRange {
  start: number;
  end: number;
}

interface TextLine extends TextRange {
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
const headingNumber =
  /^(?:(?:[IVXLCDM]+|[0-9０-９]+)(?:[.．、)）](?![0-9０-９]|[xX*＊](?:[.．\s]|$))|\s+)\s*|[（(][0-9０-９]+[)）]\s*)/i;
const quotePairs: Record<string, string> = { '"': '"', "'": "'", '`': '`', '「': '」', '『': '』', '“': '”', '‘': '’' };
const bracketPairs: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
const itemPrefix = /^(?:[\p{P}\p{S}\p{N}\s]+|(?:[ivxlcdm]+|[a-z])[\p{Pe}\p{Pf}.．、]\s*|[ivxlcdm]+\s+)*/iu;

function hasStringPrefix(before: string): boolean {
  return /(?:^|[^a-z0-9_])(?:[rbufentxl]|br|rb|fr|rf|tr|rt|u8)$/i.test(before) || /=\s*[a-z_]\w*$/i.test(before);
}

interface QuoteContext {
  kind: 'quote';
  opening: string | null;
  closing: string;
  braces: boolean;
  dollars: boolean;
}

function quoteContext(value: string, index: number, closing: string): QuoteContext {
  const before = value.slice(0, index);

  return {
    kind: 'quote',
    opening: quotePairs[value[index]!] !== value[index] ? value[index]! : null,
    closing,
    braces: /(?:^|[^a-z0-9_])(?:f|fr|rf|t|tr|rt)$/i.test(before) || /(?:\$@?|@\$)$/.test(before),
    dollars: closing === '`',
  };
}

function clippedSection(value: string): string | null {
  if (value.length <= 400) {
    return value || null;
  }

  // 固定位置で切るとCVEや設定値が変わるため、完全な行・文が収まらなければ候補を渡さない。
  let end = 0;
  const contexts: (QuoteContext | { kind: 'bracket'; closing: string })[] = [];
  for (let index = 0; index <= 400 && index < value.length; index++) {
    const character = value[index]!;
    const context = contexts.at(-1);
    if (character === '\\') {
      index++;
      continue;
    }
    if (context?.kind === 'quote') {
      if (character === context.opening) {
        contexts.push(quoteContext(value, index, context.closing));
      } else if (value.startsWith(context.closing, index)) {
        if (['"', "'"].includes(context.closing) && value.startsWith(context.closing.repeat(2), index)) {
          index++;
        } else {
          index += context.closing.length - 1;
          contexts.pop();
        }
      } else if (context.braces && character === '{') {
        if (value[index + 1] === '{') {
          index++;
        } else {
          contexts.push({ kind: 'bracket', closing: '}' });
        }
      } else if (context.dollars && character === '$' && value[index + 1] === '{') {
        contexts.push({ kind: 'bracket', closing: '}' });
        index++;
      }
      continue;
    }
    if (['"', "'", '`'].includes(character) && value.startsWith(character.repeat(3), index)) {
      contexts.push(quoteContext(value, index, character.repeat(3)));
      index += 2;
      continue;
    }
    const wordApostrophe =
      character === "'" && /[a-z0-9]/i.test(value.charAt(index - 1)) && !hasStringPrefix(value.slice(0, index));
    if (quotePairs[character] && !wordApostrophe) {
      contexts.push(quoteContext(value, index, quotePairs[character]));
      continue;
    }
    if (bracketPairs[character]) {
      contexts.push({ kind: 'bracket', closing: bracketPairs[character] });
      continue;
    }
    if (character === context?.closing) {
      contexts.pop();
      continue;
    }
    if (contexts.length) {
      continue;
    }

    if (character === '\r' || character === '\n') {
      end = index;
    } else if (
      index < 400 &&
      (/[。！？]/.test(character) || (/[.!?]/.test(character) && /\s|^$/.test(value.charAt(index + 1))))
    ) {
      end = index + 1;
    }
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

function leadingCve(text: string): string | null {
  const content = text.replace(itemPrefix, '');

  return content.match(/^(CVE-\d{4}-\d{4,})\b/i)?.[1]?.toUpperCase() ?? null;
}

function labelledCve(text: string): string | null {
  const content = text.replace(itemPrefix, '');

  return content.match(/^(CVE-\d{4}-\d{4,})\b[\])）】]*\s*(?:[:：]|$)/i)?.[1]?.toUpperCase() ?? null;
}

function articleSections(key: string, text: string): Record<SectionKind, string | null> {
  const targetKey = key.toUpperCase();
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
    const explicit = body.findIndex((line) => {
      const leading = leadingCve(line.text);
      return cves(line.text).includes(targetKey) && (!leading || leading === targetKey);
    });
    if (explicit >= 0) {
      const remaining = body.slice(explicit);
      const next = remaining.findIndex((line, offset) => {
        const leading = leadingCve(line.text);
        return offset > 0 && leading !== null && leading !== targetKey;
      });
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

function* matchingOffsets(text: string, value: string) {
  for (let start = text.indexOf(value); start >= 0; start = text.indexOf(value, start + 1)) {
    yield start;
  }
}

function targetRanges(key: string, text: string): TextRange[] {
  const target = key.toUpperCase();
  const ranges: TextRange[] = [];
  let current: TextRange | null = null;
  let context: 'target' | 'ambiguous' | null = null;

  // 抜粋から解析すると、先頭で落ちた別CVEや空行を見失うため、保存全文で先に帰属を区切る。
  for (const match of text.matchAll(/[^\r\n]*(?:\r\n|\r|\n|$)/g)) {
    const line = match[0].replace(/[\r\n]+$/, '');
    const leading = leadingCve(line);
    const label = labelledCve(line);
    if (!line.trim() || (heading(line) && !leading)) {
      current = null;
      context = null;
      continue;
    }

    const identifiers = cves(line);
    if (identifiers.length) {
      current = null;
      const onlyTarget = identifiers.every((value) => value === target);
      const range = { start: match.index, end: match.index + line.length };
      if (label === target && onlyTarget) {
        ranges.push(range);
        current = range;
        context = 'target';
      } else if (onlyTarget && context !== 'ambiguous') {
        // 自然文中の言及は対象の説明と参照を区別できないので、後続行へ帰属を継承しない。
        ranges.push(range);
      } else if (context !== null || leading !== null) {
        // 独立した自然文の列記まで項目扱いすると、後の対象CVE段落を不当に拒否する。
        context = 'ambiguous';
      }
      continue;
    }

    if (current) {
      current.end = match.index + line.length;
    }
  }

  return ranges;
}

function evidenceInput(key: string, evidence: Evidence[]) {
  return evidence.slice(0, 4).map((item) => {
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
      item,
      start,
      prompt: {
        id: item.evidenceId,
        scope: item.scope,
        cves: item.cves,
        url: item.url,
        text: item.text.slice(start, start + 1000),
        sections,
      },
    };
  });
}

/** 原文の連続した抜粋だけを使い、本文の概要と影響・対策を文字数枠内で優先する。 */
export function evidencePrompt(key: string, evidence: Evidence[]) {
  return { key, evidence: evidenceInput(key, evidence).map((entry) => entry.prompt) };
}

/** 送信した原文範囲と対象CVEの項目を共有し、引用の実在・送信範囲・帰属を照合する。 */
export function evidenceQuoteValidator(key: string, evidence: Evidence[]) {
  const sources = evidenceInput(key, evidence).map((entry) => ({
    ...entry,
    excerpts: [
      { text: entry.prompt.text, positions: () => [entry.start] },
      ...Object.values(entry.prompt.sections).flatMap((value) =>
        value
          ? // 抽出値には位置情報がないため、最初の一致だけを対象の箇所と決めつけない。
            [{ text: value, positions: () => matchingOffsets(entry.item.text, value) }]
          : [],
      ),
    ],
    attribution:
      entry.item.scope === 'article' && /^CVE-\d{4}-\d{4,}$/i.test(key) ? targetRanges(key, entry.item.text) : null,
  }));

  const validate = (id: string, quote: string): string | null => {
    const item = evidence.find((entry) => entry.evidenceId === id);
    if (!item || !quote || !item.text.includes(quote)) {
      return 'fabricated evidence';
    }
    const source = sources.find((entry) => entry.item === item);
    if (!source) {
      return 'evidence not supplied';
    }

    let supplied = false;
    for (const excerpt of source.excerpts) {
      const offsets = [...matchingOffsets(excerpt.text, quote)];
      if (!offsets.length) {
        continue;
      }
      supplied = true;
      if (!source.attribution) {
        return null;
      }
      for (const position of excerpt.positions()) {
        if (containsRange(source.attribution, position + offsets[0]!, position + offsets.at(-1)! + quote.length)) {
          continue;
        }
        for (const offset of offsets) {
          const start = position + offset;
          if (!containsRange(source.attribution, start, start + quote.length)) {
            return 'ambiguous multi-CVE evidence';
          }
        }
      }
    }

    return supplied ? null : 'evidence not supplied';
  };

  const results = new Map<string, string | null>();
  return (id: string, quote: string): string | null => {
    const cacheKey = JSON.stringify([id, quote]);
    if (!results.has(cacheKey)) {
      results.set(cacheKey, validate(id, quote));
    }

    return results.get(cacheKey)!;
  };
}

function containsRange(ranges: TextRange[], start: number, end: number): boolean {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const range = ranges[middle]!;
    if (start < range.start) {
      high = middle - 1;
    } else if (start >= range.end) {
      low = middle + 1;
    } else {
      return end <= range.end;
    }
  }

  return false;
}
