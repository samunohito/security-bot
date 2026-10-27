import type { SourceItem } from '../domain';

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

export interface SourceOptions {
  initialLookbackSeconds?: number;
}
