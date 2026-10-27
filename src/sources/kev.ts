import type { SourceConfig } from '../config';
import type { SourceItem } from '../domain';
import { getText, type Fetcher } from '../http';
import { parseKev } from './parsers';
import type { SourceCursor, SourceOptions, SourceProvider } from './provider';

/** CISA KEVの差分を収集するプロバイダーを生成する。 */
export function kevProvider(
  config: SourceConfig,
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

      const response = await getText(url.href, { headers, maxBytes: 4_000_000 }, fetcher);
      if (response.notModified) {
        return { items: [], cursor, more: false };
      }

      const nextCursor: SourceCursor = {
        etag: response.etag,
        lastModified: response.lastModified,
      };
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
  };
}
