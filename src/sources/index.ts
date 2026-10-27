import type { Environment, SourceConfig } from '../config';
import type { SourceItem } from '../domain';
import { getText, type Fetcher } from '../http';
import { enrichArticle, parseFeed, parseKev, parseNvd } from './parsers';

export interface SourceCursor {
  etag?: string;
  lastModified?: string;
  completedThrough?: number;
  windowStart?: number;
  windowEnd?: number;
  startIndex?: number;
  kevSignatures?: Record<string, string>;
}

export interface SourceBatch {
  items: SourceItem[];
  cursor: SourceCursor;
  more: boolean;
}

export interface SourceProvider {
  /** カーソル位置から収集し、次回位置とページ継続有無を返す。 */
  collect(cursor: SourceCursor, now: number): Promise<SourceBatch>;
  /** RSS項目の記事本文を追加取得し、項目の根拠情報を補う。 */
  hydrate?(item: SourceItem): Promise<SourceItem>;
}

/** 収集元設定に対応するプロバイダーを生成する。 */
export function sourceProvider(
  config: SourceConfig,
  env: Environment = {},
  fetcher: Fetcher = fetch,
  options: { initialLookbackSeconds?: number } = {},
): SourceProvider {
  return {
    /** 保存済みカーソルから収集し、完了した検索範囲だけを次回へ進める。 */
    async collect(cursor, now) {
      const url = new URL(config.url);
      const headers: Record<string, string> = {};
      if (cursor.etag) {
        headers['If-None-Match'] = cursor.etag;
      }
      if (cursor.lastModified) {
        headers['If-Modified-Since'] = cursor.lastModified;
      }

      let start = 0,
        end = now;
      if (config.kind === 'nvd') {
        start =
          cursor.windowStart ??
          (cursor.completedThrough === undefined
            ? now - (options.initialLookbackSeconds ?? 86400) * 1000
            : cursor.completedThrough - 300000);
        end = cursor.windowEnd ?? Math.min(now, start + 119 * 86400000);
        url.searchParams.set('lastModStartDate', new Date(start).toISOString());
        url.searchParams.set('lastModEndDate', new Date(end).toISOString());
        url.searchParams.set('startIndex', String(cursor.startIndex ?? 0));
        url.searchParams.set('resultsPerPage', '50');
        if (config.apiKeySecret && typeof env[config.apiKeySecret] === 'string') {
          headers.apiKey = String(env[config.apiKeySecret]);
        }
      }

      const response = await getText(
        url.href,
        { headers, maxBytes: config.kind === 'kev' ? 4_000_000 : 1_000_000 },
        fetcher,
      );
      if (response.notModified) {
        return { items: [], cursor, more: false };
      }

      if (config.kind === 'nvd') {
        const data = JSON.parse(response.text) as {
          totalResults: number;
          resultsPerPage: number;
          startIndex: number;
        };
        if (
          ![data.totalResults, data.resultsPerPage, data.startIndex].every(Number.isSafeInteger) ||
          data.totalResults < 0 ||
          (data.totalResults > 0 && data.resultsPerPage <= 0) ||
          data.startIndex !== (cursor.startIndex ?? 0)
        ) {
          throw new Error('invalid_nvd_pagination');
        }

        const next = data.startIndex + data.resultsPerPage,
          more = next < data.totalResults;

        return {
          items: parseNvd(data, config.id, now),
          more,
          cursor: more
            ? {
                ...cursor,
                windowStart: start,
                windowEnd: end,
                startIndex: next,
              }
            : { completedThrough: end },
        };
      }

      const nextCursor: SourceCursor = {
        etag: response.etag,
        lastModified: response.lastModified,
      };
      if (config.kind === 'rss') {
        return {
          items: parseFeed(response.text, config, now),
          more: false,
          cursor: nextCursor,
        };
      }

      const all = parseKev(JSON.parse(response.text), config.id, now);
      const signatures: Record<string, string> = {};
      const items: SourceItem[] = [];
      for (const item of all) {
        const signature = JSON.stringify([item.title, item.text]);
        signatures[item.id] = signature;
        const previous = cursor.kevSignatures?.[item.id];
        if (previous === signature) {
          continue;
        }
        if (!cursor.kevSignatures && item.modifiedAt < now - (options.initialLookbackSeconds ?? 86400) * 1000) {
          continue;
        }
        items.push(previous === undefined ? item : { ...item, modifiedAt: now });
      }

      for (const id of Object.keys(cursor.kevSignatures ?? {})) {
        if (signatures[id] !== undefined) {
          continue;
        }
        items.push({
          sourceId: config.id,
          id,
          url: config.url,
          title: `CISA KEV掲載取り下げ: ${id}`,
          text: `${id} is no longer listed in the current CISA KEV catalog. Removal does not establish that exploitation has stopped.`,
          publishedAt: now,
          modifiedAt: now,
          fetchedAt: now,
          cves: [id],
          scores: [],
          exploited: false,
          advisory: true,
          urgent: false,
          affected: null,
          remediation: null,
          rejected: false,
        });
      }

      nextCursor.kevSignatures = signatures;
      if (JSON.stringify(nextCursor).length > 1_500_000) {
        throw new Error('resource_limit: KEV baseline cursor');
      }

      return { items, more: false, cursor: nextCursor };
    },
    ...(config.kind !== 'rss'
      ? {}
      : {
          /** 許可されたホストの記事本文を取得し、RSSの根拠情報を補う。 */
          async hydrate(item: SourceItem) {
            const response = await getText(item.url, { allowedHosts: config.articleHosts, maxBytes: 512000 }, fetcher);

            return enrichArticle(item, response.text);
          },
        }),
  };
}
