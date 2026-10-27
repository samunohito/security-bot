import type { SourceConfig } from '../config';
import type { SourceItem } from '../domain';
import { getText, type Fetcher } from '../http';
import { enrichArticle, parseFeed } from './parsers';
import type { SourceCursor, SourceProvider } from './provider';

/** RSS/Atomと記事本文を収集するプロバイダーを生成する。 */
export function rssProvider(config: SourceConfig, fetcher: Fetcher = fetch): SourceProvider {
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

      const response = await getText(url.href, { headers, maxBytes: 1_000_000 }, fetcher);
      if (response.notModified) {
        return { items: [], cursor, more: false };
      }

      const nextCursor: SourceCursor = {
        etag: response.etag,
        lastModified: response.lastModified,
      };

      return {
        items: parseFeed(response.text, config, now),
        more: false,
        cursor: nextCursor,
      };
    },
    /** 許可されたホストの記事本文を取得し、RSSの根拠情報を補う。 */
    async hydrate(item: SourceItem) {
      const response = await getText(item.url, { allowedHosts: config.articleHosts, maxBytes: 512000 }, fetcher);

      return enrichArticle(item, response.text);
    },
  };
}
