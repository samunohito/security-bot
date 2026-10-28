import { describe, expect, it } from 'vitest';
import { enrichArticle, parseFeed, parseKev, parseNvd } from '../src/sources/parsers';
import { getText, HttpError } from '../src/http';
import { MisskeyProvider } from '../src/social/misskey';
import { UrlReferenceProvider } from '../src/social/url-reference';
import { loadConfig } from '../src/config';
import { sourceProvider } from '../src/sources';

const now = Date.parse('2026-10-27T00:00:00Z');
const source = loadConfig().sources[0]!;
describe('source boundaries', () => {
  it.each([
    '<rdf:RDF xmlns:rdf="rdf" xmlns:dc="dc"><item rdf:about="x"><title>Flaw CVE-2026-1111</title><link>https://jvn.jp/jp/1/</link><dc:date>2026-10-27T00:00:00Z</dc:date></item></rdf:RDF>',
    '<rss><channel><item><guid>x</guid><title>Flaw CVE-2026-1111</title><link>https://jvn.jp/jp/1/</link><pubDate>Tue, 27 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>',
    '<feed xmlns="atom"><entry><id>x</id><title>Flaw CVE-2026-1111</title><link href="https://jvn.jp/jp/1/"/><updated>2026-10-27T00:00:00Z</updated></entry></feed>',
  ])('対応するフィード形式を解析し日時を捏造しない', (xml) => {
    const items = parseFeed(xml, source, now);
    expect(items[0]?.cves).toEqual(['CVE-2026-1111']);
    expect(items[0]?.modifiedAt).toBe(now);
    expect(items[0]?.url).toBe('https://jvn.jp/jp/1/');
  });

  it('DTDやエンティティを含む入力を拒否する', () => {
    expect(() => parseFeed('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss/>', source, now)).toThrow();
  });

  it('JVNの画像見出しを抽出しCVSSベクトルのバージョンを保持する', () => {
    const feed =
      '<rss><channel><item><title>CVE-2026-1111</title><link>https://jvn.jp/1/</link><pubDate>2026-10-27</pubDate></item></channel></rss>';
    const item = parseFeed(feed, source, now)[0]!;
    const result = enrichArticle(
      item,
      '<h2><img alt="影響を受けるシステム" /></h2><p>Acme 1.0</p><h2><img alt="詳細情報" /></h2><p>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 基本値 9.8</p><h2><img alt="対策方法" /></h2><p>Upgrade to 2.0</p><h2><img alt="ベンダ情報" /></h2>Vendor',
    );
    expect(result.affected).toBe('Acme 1.0');
    expect(result.remediation).toBe('Upgrade to 2.0');
    expect(result.scores).toEqual([{ score: 9.8, version: '3.1', issuer: 'jvn' }]);
  });

  it('KEVのdateAddedをイベント時刻として扱い明示された対応を保持する', () => {
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

  it('NVDの発行元とバージョン、未採点のレコード、却下状態を保持する', () => {
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
    expect(item.scores).toEqual([{ score: 8.1, version: '3.1', issuer: 'vendor' }]);
    expect(item.rejected).toBe(true);
    expect(item.remediation).toBeNull();
  });

  it('Retry-Afterに従いダウンロード量を制限する', async () => {
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
    await expect(getText('https://jvn.jp/', { maxBytes: 3 }, async () => new Response('large'))).rejects.toThrow(
      'resource_limit',
    );
  });

  it('古いKEV項目から大量の取り込みジョブを作らず初期基準を設定し実際の変更を検出する', async () => {
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
    const provider = sourceProvider(source, {}, async () => Response.json(data));
    const initial = await provider.collect({}, now);
    expect(initial.items).toHaveLength(0);
    data = {
      vulnerabilities: [{ ...old, requiredAction: 'Apply the newly released patch' }],
    };
    const updated = await provider.collect(initial.cursor, now + 900000);
    expect(updated.items).toHaveLength(1);
    expect(updated.items[0]?.modifiedAt).toBe(now + 900000);
  });

  it('NVDのページ取得中は対象期間を固定し完了時にだけカーソルを確定する', async () => {
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
    expect(requests[1]?.searchParams.get('lastModEndDate')).toBe('2026-10-27T00:00:00.000Z');
    expect(second.more).toBe(false);
    expect(second.cursor.completedThrough).toBe(now);
  });

  it('48時間の停止後も取得範囲を前日に切り詰めずNVDの全更新を再開する', async () => {
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
    targets: [{ id: 'main', baseUrl: 'https://social.example', tokenSecret: 'TOKEN' }],
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
  it('投稿意図にMisskey固有のフィールドを混入させず引用を準備して投稿する', async () => {
    let payload: Record<string, unknown> = {};
    const provider = new MisskeyProvider(target, 'secret', async (_url, init) => {
      payload = JSON.parse(String(init?.body));
      return Response.json({ createdNote: { id: 'new' } });
    });
    const post = await provider.publish(provider.prepare(intent));
    expect(post.url).toBe('https://social.example/notes/new');
    expect(payload.renoteId).toBe('old');
    expect(payload.noExtractMentions).toBe(true);
    expect(String(payload.text)).toContain('未確認');
  });

  it('URLへの代替と投稿全体の文字数検証をアダプターに委ねる', () => {
    const provider = new UrlReferenceProvider(500);
    expect(provider.prepare(intent).text).toContain('関連投稿: https://social.example/notes/old');
    expect(() => new UrlReferenceProvider(20).prepare(intent)).toThrow('post_too_long');
  });

  it('明確な拒否と結果が曖昧なサーバー障害を区別する', async () => {
    const rejectedProvider = new MisskeyProvider(target, 'secret', async () => new Response('', { status: 401 }));
    await expect(rejectedProvider.publish(rejectedProvider.prepare(intent))).rejects.toMatchObject({
      kind: 'auth',
    });
    const ambiguousProvider = new MisskeyProvider(target, 'secret', async () => new Response('', { status: 500 }));
    await expect(ambiguousProvider.publish(ambiguousProvider.prepare(intent))).rejects.toMatchObject({
      kind: 'unknown',
    });
  });

  it.each([
    { error: new Error('DNS resolution failed: secret-token'), reason: 'dns', exception: 'Error' },
    { error: new Error('TLS handshake failed: secret-token'), reason: 'tls', exception: 'Error' },
    {
      error: new TypeError('Illegal invocation: function called with incorrect this reference'),
      reason: 'illegal_invocation',
      exception: 'TypeError',
    },
    {
      error: new DOMException('timeout with sensitive body', 'TimeoutError'),
      reason: 'timeout',
      exception: 'TimeoutError',
    },
    { error: new DOMException('aborted secret', 'AbortError'), reason: 'aborted', exception: 'AbortError' },
    {
      error: new TypeError('fetch failed', { cause: Object.assign(new Error('private URL'), { code: 'ENOTFOUND' }) }),
      reason: 'dns',
      exception: 'TypeError',
      code: 'ENOTFOUND',
    },
    {
      error: new TypeError('fetch failed', {
        cause: Object.assign(new Error('private URL'), { code: 'CERT_HAS_EXPIRED' }),
      }),
      reason: 'tls',
      exception: 'TypeError',
      code: 'CERT_HAS_EXPIRED',
    },
    {
      error: new TypeError('fetch failed', { cause: Object.assign(new Error('private URL'), { code: 'ECONNRESET' }) }),
      reason: 'connection',
      exception: 'TypeError',
      code: 'ECONNRESET',
    },
    {
      error: Object.assign(new Error('secret token and private post'), { name: 'secret-name', code: 'secret-code' }),
      reason: 'unknown',
      exception: 'Error',
    },
  ])(
    '送信例外を分類し、秘密のメッセージや未知の識別子を診断情報へ含めない: $reason',
    async ({ error, reason, exception, code }) => {
      const provider = new MisskeyProvider(target, 'secret-token', async () => {
        throw error;
      });
      const failure = await provider.publish({ text: 'private-post' }).catch((value: unknown) => value);
      expect(failure).toMatchObject({
        kind: 'unknown',
        message: 'send_result_unknown',
        diagnostics: { phase: 'request', reason, exception, ...(code ? { code } : {}) },
      });
      const serialized = JSON.stringify(failure);
      for (const sensitive of [
        'secret-token',
        'private-post',
        'secret-name',
        'secret-code',
        'private URL',
        'sensitive body',
      ]) {
        expect(serialized).not.toContain(sensitive);
      }
    },
  );

  it.each([
    { status: 403, kind: 'auth', reason: 'social_auth_failed' },
    { status: 429, kind: 'retry', reason: 'social_rate_limited' },
    { status: 502, kind: 'unknown', reason: 'social_server_result_unknown' },
    { status: 307, kind: 'unknown', reason: 'social_redirect_result_unknown' },
    { status: 400, kind: 'rejected', reason: 'social_rejected' },
  ])('HTTP失敗のステータスを診断情報へ記録する: $status', async ({ status, kind, reason }) => {
    const provider = new MisskeyProvider(target, 'secret-token', async () =>
      Response.json({ error: { code: 'INVALID_PARAM', message: 'private-post secret-token' } }, { status }),
    );
    const failure = await provider.publish({ text: 'private-post' }).catch((value: unknown) => value);
    expect(failure).toMatchObject({ kind, message: reason, diagnostics: { phase: 'response', status } });
    expect(JSON.stringify(failure)).not.toContain('secret-token');
    expect(JSON.stringify(failure)).not.toContain('private-post');
  });

  it.each([200, 400])('応答JSONの解析失敗はステータスと例外種別を残す: %s', async (status) => {
    const provider = new MisskeyProvider(
      target,
      'secret-token',
      async () => new Response('secret-token private-post', { status }),
    );
    const failure = await provider.publish({ text: 'private-post' }).catch((value: unknown) => value);
    expect(failure).toMatchObject({
      kind: status === 200 ? 'unknown' : 'rejected',
      diagnostics: { phase: 'response_body', status, exception: 'SyntaxError' },
    });
    expect(JSON.stringify(failure)).not.toContain('secret-token');
  });

  it.each([
    { status: 401, code: 'INVALID_TOKEN', kind: 'auth' },
    { status: 403, code: 'PERMISSION_DENIED', kind: 'auth' },
    { status: 429, code: 'RATE_LIMIT_EXCEEDED', kind: 'retry' },
    { status: 500, code: 'INTERNAL_ERROR', kind: 'unknown' },
  ])('認証・レート制限・サーバー障害でも既知APIコードを取得する: $status', async ({ status, code, kind }) => {
    const provider = new MisskeyProvider(target, 'secret-token', async () =>
      Response.json({ error: { code } }, { status }),
    );
    await expect(provider.publish({ text: 'private-post' })).rejects.toMatchObject({
      kind,
      diagnostics: { phase: 'response', status, apiCode: code },
    });
  });

  it.each(['invalid JSON', 'x'.repeat(17000)])(
    'エラー本文が不正または大きくてもHTTPによる分類を維持する: %#',
    async (body) => {
      const provider = new MisskeyProvider(target, 'secret-token', async () => new Response(body, { status: 403 }));
      await expect(provider.publish({ text: 'private-post' })).rejects.toMatchObject({
        kind: 'auth',
        diagnostics: { phase: 'response', status: 403 },
      });
    },
  );

  it.each([
    { code: 'INVALID_PARAM', expected: 'INVALID_PARAM' },
    { code: 'TOKEN_secret-token_PRIVATE_POST', expected: 'unrecognized' },
  ])('Misskeyの既知APIコードだけを診断情報へ残す: $expected', async ({ code, expected }) => {
    const provider = new MisskeyProvider(target, 'secret-token', async () =>
      Response.json({ error: { code } }, { status: 400 }),
    );
    const failure = await provider.publish({ text: 'private-post' }).catch((value: unknown) => value);
    expect(failure).toMatchObject({ diagnostics: { phase: 'response', status: 400, apiCode: expected } });
    expect(JSON.stringify(failure)).not.toContain('secret-token');
  });

  it.each([null, [], { createdNote: { id: 123 } }])(
    '不正な成功応答の構造を送信結果不明として扱う: %j',
    async (body) => {
      const provider = new MisskeyProvider(target, 'secret-token', async () => Response.json(body));
      await expect(provider.publish({ text: 'private-post' })).rejects.toMatchObject({
        kind: 'unknown',
        message: 'invalid_social_response',
        diagnostics: { phase: 'response_body', status: 200, exception: 'ZodError' },
      });
    },
  );

  it('引用が明示的に拒否された場合にのみURLで代替する', async () => {
    const bodies: Record<string, unknown>[] = [];
    const provider = new MisskeyProvider(target, 'secret', async (_url, init) => {
      bodies.push(JSON.parse(String(init?.body)));
      return bodies.length === 1
        ? Response.json({ error: { code: 'NO_SUCH_RENOTE_TARGET' } }, { status: 400 })
        : Response.json({ createdNote: { id: 'new' } });
    });
    await provider.publish(provider.prepare(intent));
    expect(bodies[1]?.renoteId).toBeUndefined();
    expect(String(bodies[1]?.text)).toContain('関連投稿: https://social.example/notes/old');
  });
});
