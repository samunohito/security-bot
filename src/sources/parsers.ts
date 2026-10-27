import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { z } from 'zod';
import type { SourceConfig } from '../config';
import type { Score, SourceItem } from '../domain';

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  removeNSPrefix: true,
  parseTagValue: false,
  processEntities: true,
  isArray: (name) => ['item', 'entry', 'link'].includes(name),
});

type Obj = Record<string, unknown>;

const object = (v: unknown): Obj => (typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Obj) : {});

const array = (v: unknown): unknown[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

const str = (v: unknown): string =>
  typeof v === 'string' || typeof v === 'number'
    ? String(v)
    : typeof object(v)['#text'] === 'string'
      ? String(object(v)['#text'])
      : '';

const cves = (s: string): string[] => [...new Set((s.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((v) => v.toUpperCase()))];

function timestamp(value: string): number {
  const t = Date.parse(
    value && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(value) && /^\d{4}-\d{2}-\d{2}T/.test(value) ? `${value}Z` : value,
  );

  return Number.isFinite(t) ? t : 0;
}

/** HTML本文からスクリプト等を除き、解析用のプレーンテキストを抽出する。 */
export function htmlText(html: string): string {
  return html
    .replace(/<(script|style|noscript)\b[^>]*>[\s\S]*?<\/\1>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<img\b[^>]*\balt=["']([^"']*)["'][^>]*>/gi, '$1')
    .replace(/<\/(?:p|div|li|h[1-6]|section|tr)>|<br\s*\/?\s*>/gi, '\n')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n/g, '\n')
    .trim();
}

function section(text: string, labels: string[]): string | null {
  for (const label of labels) {
    const match = text.match(
      new RegExp(
        `(?:^|\\n)\\s*(?:[IVX.0-9]+[.．、 ]*)?${label}\\s*[:：]?\\s*\\n([\\s\\S]*?)(?=\\n\\s*(?:[IVX.0-9]+[.．、 ]*)?(?:概要|影響を受けるシステム|影響を受ける製品|想定される影響|対策方法|対策|ベンダ情報|参考情報|関連情報|詳細情報|謝辞|更新履歴|Solutions|Affected|References)\\s*[:：]?\\s*(?:\\n|$)|$)`,
        'i',
      ),
    );
    if (match?.[1]?.trim()) {
      return match[1].trim().slice(0, 3000);
    }
  }

  return null;
}

/** 記事HTMLからCVSS、影響範囲、対策などを収集項目へ補う。 */
export function enrichArticle(item: SourceItem, html: string): SourceItem {
  const text = htmlText(html);
  const scores: Score[] = [];
  for (const m of text.matchAll(
    /CVSS\s*[:：]?\s*(?:v(?:ersion)?\s*)?([234](?:\.\d)?)?(?:(?!CVSS)[\s\S]){0,180}?(?:基本値|基本スコア|Base Score|スコア|score|評価値)\s*[:：]?\s*(10(?:\.0)?|[0-9](?:\.\d)?)/gi,
  )) {
    scores.push({
      score: Number(m[2]),
      version: m[1] ?? 'unknown',
      issuer: item.sourceId,
    });
  }

  return {
    ...item,
    impact: section(text, ['想定される影響', 'Impact']),
    text,
    cves: cves(`${item.title}\n${text}`),
    scores: scores.length ? scores : item.scores,
    affected: section(text, ['影響を受けるシステム', '影響を受ける製品', '対象製品', 'Affected Products']),
    remediation: section(text, ['対策方法', '対策', '対処方法', 'Solutions']),
  };
}

/** RSS/Atom XMLを検証し、許可された記事URLの項目へ変換する。 */
export function parseFeed(xml: string, source: SourceConfig, now: number): SourceItem[] {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml) || XMLValidator.validate(xml) !== true) {
    throw new Error('invalid_feed');
  }

  const root = object(parser.parse(xml));
  const rdf = object(root.RDF),
    rss = object(object(root.rss).channel),
    atom = object(root.feed);
  const entries = array(rdf.item ?? rss.item ?? atom.entry);

  return entries.slice(0, 100).flatMap((entry) => {
    const o = object(entry),
      links = array(o.link);
    const link =
      links.map((l) => (object(l)['@rel'] === 'self' ? '' : str(object(l)['@href'] ?? l))).find(Boolean) ?? '';
    let url: URL;
    try {
      url = new URL(link, source.url);
    } catch {
      return [];
    }
    if (url.protocol !== 'https:' || (source.articleHosts.length && !source.articleHosts.includes(url.hostname))) {
      return [];
    }

    url.hash = '';
    const title = str(o.title),
      text = htmlText(str(o.description ?? o.summary ?? o.content));
    const publishedAt = timestamp(str(o.published ?? o.pubDate ?? o.date ?? o.issued ?? o.updated));
    const modifiedAt = timestamp(str(o.modified ?? o.updated ?? o.date)) || publishedAt;
    const advisory = source.id === 'jpcert' && /^\/at\//.test(url.pathname);

    return [
      {
        sourceId: source.id,
        id: str(o.guid ?? o.id ?? o['@about']) || url.href,
        url: url.href,
        title,
        text: `${title}\n${text}`,
        publishedAt,
        modifiedAt,
        fetchedAt: now,
        cves: cves(`${title}\n${text}`),
        scores: [],
        exploited: false,
        advisory,
        urgent: advisory && /緊急|悪用|ゼロデイ/.test(title),
        affected: null,
        remediation: null,
        rejected: false,
      },
    ];
  });
}

const kevSchema = z.object({
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vulnerabilityName: z.string(),
      vendorProject: z.string(),
      product: z.string(),
      shortDescription: z.string(),
      requiredAction: z.string(),
      dateAdded: z.string(),
      notes: z.string().optional(),
    }),
  ),
});

/** CISA KEVカタログを検証し、脆弱性項目へ変換する。 */
export function parseKev(raw: unknown, sourceId: string, now: number): SourceItem[] {
  return kevSchema.parse(raw).vulnerabilities.map((v) => ({
    sourceId,
    id: v.cveID,
    url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.cveID)}`,
    title: v.vulnerabilityName,
    impact: v.shortDescription,
    text: `${v.cveID}\n${v.vendorProject} ${v.product}\n${v.shortDescription}\n${v.requiredAction}\n${v.notes ?? ''}`,
    publishedAt: timestamp(v.dateAdded),
    modifiedAt: timestamp(v.dateAdded),
    fetchedAt: now,
    cves: [v.cveID],
    scores: [],
    exploited: true,
    advisory: true,
    urgent: true,
    affected: `${v.vendorProject} ${v.product}`,
    remediation: v.requiredAction,
    rejected: false,
  }));
}

/** NVD CVE応答を検証し、脆弱性項目へ変換する。 */
export function parseNvd(raw: unknown, sourceId: string, now: number): SourceItem[] {
  const records = z
    .object({
      vulnerabilities: z.array(z.object({ cve: z.record(z.string(), z.unknown()) })),
    })
    .parse(raw).vulnerabilities;

  return records.map(({ cve: c }) => {
    const id = z
      .string()
      .regex(/^CVE-\d{4}-\d{4,}$/)
      .parse(c.id);
    const descriptions = array(c.descriptions).map(object);
    const text = str((descriptions.find((d) => d.lang === 'en') ?? descriptions[0])?.value);
    const scores: Score[] = [];
    for (const metrics of Object.values(object(c.metrics))) {
      for (const metric of array(metrics)) {
        const m = object(metric),
          data = object(m.cvssData);
        if (typeof data.baseScore === 'number' && data.baseScore >= 0 && data.baseScore <= 10) {
          scores.push({
            score: data.baseScore,
            version: str(data.version),
            issuer: str(m.source),
          });
        }
      }
    }

    const affected = c.configurations ? JSON.stringify(c.configurations) : null;

    return {
      sourceId,
      id,
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
      title: id,
      impact: text,
      text: `${id}\n${text}${affected ? `\nAffected configurations: ${affected}` : ''}`,
      publishedAt: timestamp(str(c.published)),
      modifiedAt: timestamp(str(c.lastModified)),
      fetchedAt: now,
      cves: [id],
      scores,
      exploited: Boolean(c.cisaExploitAdd),
      urgent: Boolean(c.cisaExploitAdd),
      advisory: false,
      affected,
      remediation: null,
      rejected: c.vulnStatus === 'Rejected',
    };
  });
}
