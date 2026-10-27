import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

describe('operator CLI', () => {
  it.each([
    { args: ['show', 'summaries', 'revision/id'], path: '/admin/summaries/revision%2Fid', method: 'GET', body: null },
    {
      args: ['generate-summary', 'revision/id'],
      path: '/admin/summaries/generate',
      method: 'POST',
      body: { id: 'revision/id' },
    },
  ])('生成結果の確認と再生成を管理APIへ送る: $method $path', ({ args, path, method, body }) => {
    const setup = `globalThis.fetch = async (url, init) => {
      if (init.headers.Authorization !== 'Bearer local-test') throw new Error('missing_auth');
      return Response.json({ path: new URL(url).pathname, method: init.method, body: init.body ? JSON.parse(init.body) : null });
    };`;
    const result = spawnSync(
      process.execPath,
      ['--import', 'tsx', '--import', `data:text/javascript,${encodeURIComponent(setup)}`, 'src/cli.ts', ...args],
      {
        encoding: 'utf8',
        env: { ...process.env, SECURITY_BOT_URL: 'http://localhost:8787', SECURITY_BOT_ADMIN_TOKEN: 'local-test' },
      },
    );
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({ path, method, body });
  });

  it.each([
    { html: '<p>更新してください。</p>', status: 0, valid: true },
    { html: '', status: 1, valid: false },
  ])('管理API認証なしで1件をプレビューし、検証結果に応じた終了コードを返す: %j', ({ html, status, valid }) => {
    const feed =
      '<rss><channel><item><guid>one</guid><title>CVE-2026-1111</title><link>https://jvn.jp/one</link><pubDate>2026-10-27</pubDate></item></channel></rss>';
    const setup = `globalThis.fetch = async (url) => {
      if (String(url) === 'https://jvn.jp/rss/jvn.rdf') return new Response(${JSON.stringify(feed)});
      if (String(url) === 'https://jvn.jp/one') return new Response(${JSON.stringify(html)});
      throw new Error('unexpected_external_request');
    };`;
    const result = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        '--import',
        `data:text/javascript,${encodeURIComponent(setup)}`,
        'src/cli.ts',
        'preview',
        '--source',
        'jvn',
      ],
      { encoding: 'utf8', env: { ...process.env, SECURITY_BOT_URL: '', SECURITY_BOT_ADMIN_TOKEN: '' } },
    );
    expect(result.status).toBe(status);
    const output = JSON.parse(result.stdout);
    expect(output).toMatchObject({
      mode: 'fake',
      itemId: 'one',
      semanticVerification: 'not_performed',
      validation: { valid },
    });
    if (valid) {
      expect(output.post.text).toContain('更新してください。');
    } else {
      expect(output.validation.reasons).toContain('overview_missing');
      expect(output.post.text).toContain('概要: 未確認');
    }
  });

  it.each([['preview'], ['preview', '--source', 'jvn', 'extra']])(
    'previewの不正な引数を通信前に拒否する: %j',
    (...args) => {
      const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], { encoding: 'utf8' });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('Usage: preview');
    },
  );

  it('リモート認証情報なしで同梱の設定を検証する', () => {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'config', 'validate'], {
      encoding: 'utf8',
    });
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      valid: true,
      mode: 'free',
      dryRun: true,
    });
  });

  it('リモート認証情報がない場合は原因が分かるエラーを返す', () => {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'status'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        SECURITY_BOT_URL: '',
        SECURITY_BOT_ADMIN_TOKEN: '',
      },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('SECURITY_BOT_URL');
  });
});
