import { describe, expect, it } from 'vitest';
import {
  enrichArticle,
  parseFeed,
  parseKev,
  parseNvd,
} from '../src/sources/parsers';
import { getText, HttpError } from '../src/http';
import { MisskeyProvider, UrlReferenceProvider } from '../src/social';
import { loadConfig } from '../src/config';
import { sourceProvider } from '../src/sources';

const now = Date.parse('2026-10-27T00:00:00Z');
const source = loadConfig().sources[0]!;
describe('source boundaries', () => {
  it.each([
    '<rdf:RDF xmlns:rdf="rdf" xmlns:dc="dc"><item rdf:about="x"><title>Flaw CVE-2026-1111</title><link>https://jvn.jp/jp/1/</link><dc:date>2026-10-27T00:00:00Z</dc:date></item></rdf:RDF>',
    '<rss><channel><item><guid>x</guid><title>Flaw CVE-2026-1111</title><link>https://jvn.jp/jp/1/</link><pubDate>Tue, 27 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>',
    '<feed xmlns="atom"><entry><id>x</id><title>Flaw CVE-2026-1111</title><link href="https://jvn.jp/jp/1/"/><updated>2026-10-27T00:00:00Z</updated></entry></feed>',
  ])('parses supported feed format without inventing timestamps', (xml) => {
    const items = parseFeed(xml, source, now);
    expect(items[0]?.cves).toEqual(['CVE-2026-1111']);
    expect(items[0]?.modifiedAt).toBe(now);
    expect(items[0]?.url).toBe('https://jvn.jp/jp/1/');
  });
  it('rejects DTD/entity payloads', () => {
    expect(() =>
      parseFeed(
        '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss/>',
        source,
        now,
      ),
    ).toThrow();
  });
  it('extracts JVN image headings and preserves the CVSS vector version', () => {
    const feed =
      '<rss><channel><item><title>CVE-2026-1111</title><link>https://jvn.jp/1/</link><pubDate>2026-10-27</pubDate></item></channel></rss>';
    const item = parseFeed(feed, source, now)[0]!;
    const result = enrichArticle(
      item,
      '<h2><img alt="影響を受けるシステム" /></h2><p>Acme 1.0</p><h2><img alt="詳細情報" /></h2><p>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 基本値 9.8</p><h2><img alt="対策方法" /></h2><p>Upgrade to 2.0</p><h2><img alt="ベンダ情報" /></h2>Vendor',
    );
    expect(result.affected).toBe('Acme 1.0');
    expect(result.remediation).toBe('Upgrade to 2.0');
    expect(result.scores).toEqual([
      { score: 9.8, version: '3.1', issuer: 'jvn' },
    ]);
  });
  it('keeps KEV dateAdded as the event time and explicit action', () => {
    const items = parseKev(
      {
        vulnerabilities: [
          {
            cveID: 'CVE-2026-1111',
            vulnerabilityName: 'Flaw',
            vendorProject: 'Acme',
            product: 'Server',
            shortDescription: 'Remote execution',
            requiredAction: 'Apply vendor updates',
            dateAdded: '2026-10-26',
          },
        ],
      },
      'kev',
      now,
    );
    expect(items[0]?.exploited).toBe(true);
    expect(items[0]?.modifiedAt).toBe(Date.parse('2026-10-26T00:00:00Z'));
    expect(items[0]?.remediation).toBe('Apply vendor updates');
  });
  it('preserves NVD issuer/version, unscored records and rejection', () => {
    const data = {
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2026-1111',
            published: '2026-10-26T00:00:00.000',
            lastModified: '2026-10-27T00:00:00.000',
            vulnStatus: 'Rejected',
            descriptions: [{ lang: 'en', value: 'Rejected record' }],
            metrics: {
              cvssMetricV31: [
                {
                  source: 'vendor',
                  cvssData: { baseScore: 8.1, version: '3.1' },
                },
              ],
            },
          },
        },
      ],
    };
    const item = parseNvd(data, 'nvd', now)[0]!;
    expect(item.scores).toEqual([
      { score: 8.1, version: '3.1', issuer: 'vendor' },
    ]);
    expect(item.rejected).toBe(true);
    expect(item.remediation).toBeNull();
  });
  it('honors Retry-After and bounds downloaded data', async () => {
    await expect(
      getText(
        'https://jvn.jp/',
        {},
        async () =>
          new Response('wait', {
            status: 429,
            headers: { 'Retry-After': '120' },
          }),
      ),
    ).rejects.toMatchObject({ retryAfterMs: 120000, retryable: true });
    await expect(
      getText(
        'https://jvn.jp/',
        { maxBytes: 3 },
        async () => new Response('large'),
      ),
    ).rejects.toThrow('resource_limit');
  });
  it('baselines old KEV entries without creating thousands of ingest jobs, then detects a real change', async () => {
    const source = loadConfig().sources.find((s) => s.id === 'kev')!;
    const old = {
      cveID: 'CVE-2020-1111',
      vulnerabilityName: 'Old flaw',
      vendorProject: 'Acme',
      product: 'Server',
      shortDescription: 'Remote execution',
      requiredAction: 'Apply vendor updates',
      dateAdded: '2020-01-01',
    };
    let data = { vulnerabilities: [old] };
    const provider = sourceProvider(source, {}, async () =>
      Response.json(data),
    );
    const initial = await provider.collect({}, now);
    expect(initial.items).toHaveLength(0);
    data = {
      vulnerabilities: [
        { ...old, requiredAction: 'Apply the newly released patch' },
      ],
    };
    const updated = await provider.collect(initial.cursor, now + 900000);
    expect(updated.items).toHaveLength(1);
    expect(updated.items[0]?.modifiedAt).toBe(now + 900000);
  });
  it('keeps a fixed NVD window through pagination and commits its cursor only at the end', async () => {
    const source = loadConfig().sources.find((s) => s.id === 'nvd')!;
    const requests: URL[] = [];
    const provider = sourceProvider(source, {}, async (url) => {
      const u = new URL(String(url));
      requests.push(u);
      return Response.json({
        vulnerabilities: [],
        totalResults: 100,
        startIndex: Number(u.searchParams.get('startIndex')),
        resultsPerPage: 50,
      });
    });
    const first = await provider.collect({}, now);
    expect(first.more).toBe(true);
    expect(first.cursor.completedThrough).toBeUndefined();
    const second = await provider.collect(first.cursor, now + 900000);
    expect(requests[1]?.searchParams.get('lastModEndDate')).toBe(
      '2026-10-27T00:00:00.000Z',
    );
    expect(second.more).toBe(false);
    expect(second.cursor.completedThrough).toBe(now);
  });
  it('resumes all NVD updates after a 48-hour outage instead of clamping to yesterday', async () => {
    const source = loadConfig().sources.find((s) => s.id === 'nvd')!;
    let start = '';
    const provider = sourceProvider(source, {}, async (url) => {
      start = new URL(String(url)).searchParams.get('lastModStartDate')!;
      return Response.json({
        vulnerabilities: [],
        totalResults: 0,
        startIndex: 0,
        resultsPerPage: 0,
      });
    });
    await provider.collect({ completedThrough: now - 48 * 3600000 }, now);
    expect(start).toBe('2026-10-24T23:55:00.000Z');
  });
});
describe('social adapters', () => {
  const target = loadConfig({
    targets: [
      { id: 'main', baseUrl: 'https://social.example', tokenSecret: 'TOKEN' },
    ],
  }).targets[0]!;
  const intent = {
    kind: 'update' as const,
    key: 'CVE-2026-1111',
    title: 'Acme',
    severity: 'High',
    summary: {
      overview: { text: '脆弱性', evidence: [] },
      impact: null,
      action: null,
      uncertainties: [],
    },
    sources: ['https://jvn.jp/'],
    previousPost: { id: 'old', url: 'https://social.example/notes/old' },
  };
  it('prepares a quote and posts through Misskey without leaking its fields into the intent', async () => {
    let payload: Record<string, unknown> = {};
    const provider = new MisskeyProvider(
      target,
      'secret',
      async (_url, init) => {
        payload = JSON.parse(String(init?.body));
        return Response.json({ createdNote: { id: 'new' } });
      },
    );
    const post = await provider.publish(provider.prepare(intent));
    expect(post.url).toBe('https://social.example/notes/new');
    expect(payload.renoteId).toBe('old');
    expect(payload.noExtractMentions).toBe(true);
    expect(String(payload.text)).toContain('未確認');
  });
  it('delegates URL fallback and complete length checking to the adapter', () => {
    const provider = new UrlReferenceProvider(500);
    expect(provider.prepare(intent).text).toContain(
      '関連投稿: https://social.example/notes/old',
    );
    expect(() => new UrlReferenceProvider(20).prepare(intent)).toThrow(
      'post_too_long',
    );
  });
  it('distinguishes definite rejection from ambiguous server failure', async () => {
    const a = new MisskeyProvider(
      target,
      'secret',
      async () => new Response('', { status: 401 }),
    );
    await expect(a.publish(a.prepare(intent))).rejects.toMatchObject({
      kind: 'auth',
    });
    const b = new MisskeyProvider(
      target,
      'secret',
      async () => new Response('', { status: 500 }),
    );
    await expect(b.publish(b.prepare(intent))).rejects.toMatchObject({
      kind: 'unknown',
    });
  });
  it('falls back to a URL only after an explicit quote rejection', async () => {
    const bodies: Record<string, unknown>[] = [];
    const provider = new MisskeyProvider(
      target,
      'secret',
      async (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return bodies.length === 1
          ? Response.json(
              { error: { code: 'NO_SUCH_RENOTE_TARGET' } },
              { status: 400 },
            )
          : Response.json({ createdNote: { id: 'new' } });
      },
    );
    await provider.publish(provider.prepare(intent));
    expect(bodies[1]?.renoteId).toBeUndefined();
    expect(String(bodies[1]?.text)).toContain(
      '関連投稿: https://social.example/notes/old',
    );
  });
});
