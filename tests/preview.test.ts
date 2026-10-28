import { describe, expect, it } from 'vitest';
import { FakeLlmProvider } from '../src/llm/fake';
import { SUMMARY_SYSTEM, VERIFY_SYSTEM } from '../src/llm/prompts';
import { summarySchema, verdictSchema } from '../src/quality';
import { StdoutSocialProvider } from '../src/social/stdout';
import { loadConfig } from '../src/config';
import { preview } from '../src/preview';

describe('ローカルProvider', () => {
  it('根拠本文を引用したFake要約を作り、実AIの意味検証を承認しない', async () => {
    const provider = new FakeLlmProvider();
    const result = await provider.generateStructured(
      {
        system: SUMMARY_SYSTEM,
        data: { key: 'CVE-2026-1111', evidence: [{ id: 'jvn:1', scope: 'cve', text: '更新してください。' }] },
      },
      summarySchema,
    );
    expect(result.value.overview).toEqual({
      text: '更新してください。',
      evidence: [{ id: 'jvn:1', quote: '更新してください。' }],
    });
    expect(result.value.impact).toBeNull();
    expect(result.value.action).toBeNull();
    await expect(provider.generateStructured({ system: VERIFY_SYSTEM, data: {} }, verdictSchema)).rejects.toThrow();
  });

  it('投稿本文を整形して出力し、URL参照を含む文字数上限を守る', async () => {
    const output: string[] = [];
    const provider = new StdoutSocialProvider(500, (text) => {
      output.push(text);
    });
    const intent = {
      kind: 'new' as const,
      key: 'CVE-2026-1111',
      title: '告知',
      severity: 'High',
      summary: {
        overview: { text: '更新してください。', evidence: [] },
        impact: null,
        action: null,
        uncertainties: [],
      },
      sources: ['https://jvn.jp/1'],
    };
    const published = await provider.publish(provider.prepare(intent));
    expect(output).toHaveLength(1);
    expect(output[0]).toContain('[High] CVE-2026-1111');
    expect(output[0]).toContain('告知\n更新してください。');
    expect(published.url).toContain('preview.invalid');
    expect(() => new StdoutSocialProvider(10).prepare(intent)).toThrow('post_too_long');
  });
});

const feed = `<rss><channel>
  <item><guid>first</guid><title>告知 CVE-2026-1111</title><link>https://jvn.jp/first</link><description>最初の記事です。</description><pubDate>2026-10-27</pubDate></item>
  <item><guid>second</guid><title>告知 CVE-2026-2222 CVE-2026-3333</title><link>https://jvn.jp/second</link><description>複数の脆弱性の記事です。</description><pubDate>2026-10-27</pubDate></item>
</channel></rss>`;

describe('単発プレビュー', () => {
  it('記事補完のないNVDも1ページの1件だけをプレビューする', async () => {
    const urls: string[] = [];
    const result = await preview(loadConfig(), { source: 'nvd' }, async (url) => {
      urls.push(String(url));
      return Response.json({
        totalResults: 100,
        resultsPerPage: 50,
        startIndex: 0,
        vulnerabilities: [
          {
            cve: {
              id: 'CVE-2026-1111',
              published: '2026-10-27T00:00:00Z',
              lastModified: '2026-10-27T00:00:00Z',
              vulnStatus: 'Analyzed',
              descriptions: [{ lang: 'en', value: 'Remote execution in Acme Server.' }],
              metrics: {},
            },
          },
        ],
      });
    });
    expect(urls).toHaveLength(1);
    expect(new URL(urls[0]!).searchParams.get('startIndex')).toBe('0');
    expect(result.key).toBe('CVE-2026-1111');
    expect(result.validation.valid).toBe(true);
    expect(result.post.text).toContain('Remote execution in Acme Server.');
  });

  it('先頭1件の記事を取得してFake要約と投稿プレビューを返す', async () => {
    const requests: string[] = [];
    const result = await preview(loadConfig(), { source: 'jvn' }, async (url) => {
      requests.push(String(url));
      return new Response(requests.length === 1 ? feed : '<p>記事本文の情報です。</p>');
    });
    expect(requests).toEqual(['https://jvn.jp/rss/jvn.rdf', 'https://jvn.jp/first']);
    expect(result.itemId).toBe('first');
    expect(result.key).toBe('CVE-2026-1111');
    expect(result.mode).toBe('fake');
    expect(result.semanticVerification).toBe('not_performed');
    expect(result.validation.valid).toBe(true);
    expect(result.validation.complete).toBe(false);
    expect(result.post.text).toContain('記事本文の情報です。');
  });

  it('指定した項目とCVEだけを選び、曖昧な複数CVEの根拠は不合格として返す', async () => {
    let calls = 0;
    const result = await preview(loadConfig(), { source: 'jvn', item: 'second', key: 'CVE-2026-3333' }, async () => {
      return new Response(++calls === 1 ? feed : '<p>両方に関する記事本文です。</p>');
    });
    expect(result.itemId).toBe('second');
    expect(result.key).toBe('CVE-2026-3333');
    expect(result.validation.valid).toBe(false);
    expect(result.validation.reasons).toContain('overview: ambiguous multi-CVE evidence');
  });

  it.each([
    [{ source: 'missing' }, feed, 'unknown_preview_source'],
    [{ source: 'jvn' }, '<rss><channel/></rss>', 'preview_no_items'],
    [{ source: 'jvn', item: 'missing' }, feed, 'preview_item_not_found'],
    [{ source: 'jvn', key: 'CVE-2026-9999' }, feed, 'preview_key_not_found'],
  ])('対象を選べない場合は原因を伝える: %j', async (options, xml, error) => {
    await expect(preview(loadConfig(), options, async () => new Response(xml))).rejects.toThrow(error);
  });

  it('情報源の取得失敗を成功したプレビューとして扱わない', async () => {
    await expect(
      preview(loadConfig(), { source: 'jvn' }, async () => new Response('', { status: 503 })),
    ).rejects.toThrow('http_503');
  });
});
