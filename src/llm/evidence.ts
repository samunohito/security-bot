import type { Evidence } from '../domain';

function sectionQuote(evidence: Evidence, value: string | null | undefined): string | null {
  if (!value || !evidence.text.includes(value)) {
    return null;
  }

  return value.slice(0, 400);
}

/** 原文の連続した抜粋だけを使い、本文の概要と影響・対策を文字数枠内で優先する。 */
export function evidencePrompt(key: string, evidence: Evidence[]) {
  return {
    key,
    evidence: evidence.slice(0, 4).map((item) => {
      const overview = item.text.search(/(?:^|\n)\s*(?:I\.\s*)?概要\s*(?:\r?\n|$)/m);
      const cve = item.text.indexOf(key);
      const start = item.scope === 'article' && cve >= 0 ? Math.max(0, cve - 150) : Math.max(0, overview);

      return {
        id: item.evidenceId,
        scope: item.scope,
        cves: item.cves,
        url: item.url,
        text: item.text.slice(start, start + 1000),
        sections: {
          affected: sectionQuote(item, item.affected),
          impact: sectionQuote(item, item.impact),
          remediation: sectionQuote(item, item.remediation),
        },
      };
    }),
  };
}
