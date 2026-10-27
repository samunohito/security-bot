import type { Environment, SourceConfig } from '../config';
import { getText, type Fetcher } from '../http';
import { parseNvd } from './parsers';
import type { SourceCursor, SourceOptions, SourceProvider } from './provider';

/** NVDの固定検索窓とページを収集するプロバイダーを生成する。 */
export function nvdProvider(
  config: SourceConfig,
  env: Environment,
  fetcher: Fetcher = fetch,
  options: SourceOptions = {},
): SourceProvider {
  return {
    /** 保存済みカーソルから収集し、次回位置を返す。 */
    async collect(cursor, now) {
      const url = new URL(config.url);
      const headers: Record<string, string> = {};
      if (cursor.etag) {
        headers['If-None-Match'] = cursor.etag;
      }
      if (cursor.lastModified) {
        headers['If-Modified-Since'] = cursor.lastModified;
      }

      const start =
        cursor.windowStart ??
        (cursor.completedThrough === undefined
          ? now - (options.initialLookbackSeconds ?? 86400) * 1000
          : cursor.completedThrough - 300000);
      const end = cursor.windowEnd ?? Math.min(now, start + 119 * 86400000);
      url.searchParams.set('lastModStartDate', new Date(start).toISOString());
      url.searchParams.set('lastModEndDate', new Date(end).toISOString());
      url.searchParams.set('startIndex', String(cursor.startIndex ?? 0));
      url.searchParams.set('resultsPerPage', '50');
      if (config.apiKeySecret && typeof env[config.apiKeySecret] === 'string') {
        headers.apiKey = String(env[config.apiKeySecret]);
      }

      const response = await getText(url.href, { headers, maxBytes: 1_000_000 }, fetcher);
      if (response.notModified) {
        return { items: [], cursor, more: false };
      }

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
    },
  };
}
