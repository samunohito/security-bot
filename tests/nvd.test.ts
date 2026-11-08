import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';
import { sourceProvider } from '../src/sources';
import type { SourceCursor, SourceProvider } from '../src/sources/provider';

const now = Date.parse('2026-10-27T00:00:00Z');
const source = loadConfig().sources.find((source) => source.id === 'nvd')!;

async function collectPage(provider: SourceProvider, cursor: SourceCursor, now: number) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const batch = await provider.collect(cursor, now);
    if (batch.items.length > 0 || !batch.more) {
      return batch;
    }

    cursor = batch.cursor;
  }

  throw new Error('NVD collection did not progress');
}

describe('NVDの大きな応答', () => {
  it.each([0, 51, 1.5])('保存された取得件数が範囲外なら外部取得せず拒否する（%s）', async (pageSize) => {
    let attempts = 0;
    const provider = sourceProvider(source, {}, async () => {
      attempts++;

      return Response.json({});
    });

    await expect(provider.collect({ pageSize }, now)).rejects.toThrow('invalid_nvd_pagination');
    expect(attempts).toBe(0);
  });

  it('サイズ超過時は空の継続バッチを返し検索窓・開始位置と縮小した件数を保存する', async () => {
    let attempts = 0;
    const provider = sourceProvider(source, {}, async () => {
      attempts++;

      return new Response('', { headers: { 'Content-Length': '1000001' } });
    });
    const cursor = { completedThrough: now - 48 * 3600000 };
    const batch = await provider.collect(cursor, now);

    expect(batch).toEqual({
      items: [],
      more: true,
      cursor: { ...cursor, windowStart: now - 48 * 3600000 - 300000, windowEnd: now, startIndex: 0, pageSize: 25 },
    });
    expect(attempts).toBe(1);
    expect(cursor).toEqual({ completedThrough: now - 48 * 3600000 });
  });

  it.each([false, true])(
    'サイズ超過時も検索窓と開始位置を維持し全項目を取り込む（Content-Length: %s）',
    async (contentLength) => {
      const requests: URL[] = [];
      const records = Array.from({ length: 6 }, (_, index) => ({
        cve: {
          id: `CVE-2026-${1150 + index}`,
          published: '2026-10-26T00:00:00.000',
          lastModified: '2026-10-27T00:00:00.000',
          descriptions: [{ lang: 'en', value: 'x'.repeat(220000) }],
        },
      }));
      const provider = sourceProvider(source, {}, async (input) => {
        const url = new URL(String(input));
        requests.push(url);
        const startIndex = Number(url.searchParams.get('startIndex'));
        const pageSize = Number(url.searchParams.get('resultsPerPage'));
        const vulnerabilities = records.slice(startIndex - 50, startIndex - 50 + pageSize);
        const body = JSON.stringify({
          vulnerabilities,
          totalResults: 56,
          startIndex,
          resultsPerPage: vulnerabilities.length,
        });

        return new Response(body, {
          headers: contentLength ? { 'Content-Length': String(new TextEncoder().encode(body).length) } : {},
        });
      });
      const cursor = { completedThrough: now - 86400000, windowStart: now - 3600000, windowEnd: now, startIndex: 50 };
      const first = await collectPage(provider, cursor, now + 900000);

      expect(first.items.map((item) => item.id)).toEqual(['CVE-2026-1150', 'CVE-2026-1151', 'CVE-2026-1152']);
      expect(first.more).toBe(true);
      expect(first.cursor).toMatchObject({ ...cursor, startIndex: 53, pageSize: 3 });
      expect(cursor.startIndex).toBe(50);
      for (const request of requests) {
        expect(request.searchParams.get('startIndex')).toBe('50');
        expect(request.searchParams.get('lastModStartDate')).toBe('2026-10-26T23:00:00.000Z');
        expect(request.searchParams.get('lastModEndDate')).toBe('2026-10-27T00:00:00.000Z');
      }

      const attempts = requests.length;
      const second = await provider.collect(JSON.parse(JSON.stringify(first.cursor)), now + 1800000);

      expect(second.items.map((item) => item.id)).toEqual(['CVE-2026-1153', 'CVE-2026-1154', 'CVE-2026-1155']);
      expect(second.more).toBe(false);
      expect(second.cursor).toEqual({ completedThrough: now });
      expect(requests).toHaveLength(attempts + 1);
      expect(requests.at(-1)?.searchParams.get('startIndex')).toBe('53');
      expect(requests.at(-1)?.searchParams.get('resultsPerPage')).toBe('3');
      expect(requests.at(-1)?.searchParams.get('lastModEndDate')).toBe('2026-10-27T00:00:00.000Z');
    },
  );

  it('1件でも上限を超える場合は有限回で失敗しカーソルを進めない', async () => {
    const pageSizes: number[] = [];
    const provider = sourceProvider(source, {}, async (input) => {
      pageSizes.push(Number(new URL(String(input)).searchParams.get('resultsPerPage')));

      return new Response('', { headers: { 'Content-Length': '1000001' } });
    });
    const cursor = { completedThrough: now - 48 * 3600000 };

    await expect(collectPage(provider, cursor, now)).rejects.toThrow('resource_limit: response too large');
    expect(pageSizes.at(-1)).toBe(1);
    expect(pageSizes.length).toBeLessThanOrEqual(6);
    expect(cursor).toEqual({ completedThrough: now - 48 * 3600000 });
  });

  it('件数縮小後の429は追加取得せずRetry-Afterを呼び出し元へ返す', async () => {
    let attempts = 0;
    const provider = sourceProvider(source, {}, async () => {
      attempts++;
      if (attempts === 1) {
        return new Response('', { headers: { 'Content-Length': '1000001' } });
      }

      return new Response('', { status: 429, headers: { 'Retry-After': '120' } });
    });

    const first = await provider.collect({}, now);
    await expect(provider.collect(first.cursor, now + 1000)).rejects.toMatchObject({
      status: 429,
      retryAfterMs: 120000,
    });
    expect(first.cursor.pageSize).toBe(25);
    expect(attempts).toBe(2);
  });

  it.each([
    { status: 500, body: '', error: 'http_500' },
    { status: 200, body: '{', error: 'JSON' },
    { status: 200, body: '{"totalResults":5,"resultsPerPage":0,"startIndex":0}', error: 'invalid_nvd_pagination' },
  ])('サイズ超過以外のエラーを件数縮小で再試行しない（$error）', async ({ status, body, error }) => {
    let attempts = 0;
    const provider = sourceProvider(source, {}, async () => {
      attempts++;

      return new Response(body, { status });
    });

    await expect(provider.collect({}, now)).rejects.toThrow(error);
    expect(attempts).toBe(1);
  });
});
