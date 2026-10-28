import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('operator CLI', () => {
  it.each([
    { args: ['skip-before', '--hours', '6'], path: '/admin/backlog/skip', method: 'POST', body: { hours: 6 } },
    { args: ['list', 'summaries'], path: '/admin/summaries', method: 'GET', body: null },
    { args: ['show', 'summaries', 'revision/id'], path: '/admin/summaries/revision%2Fid', method: 'GET', body: null },
    {
      args: ['generate-summary', 'revision/id'],
      path: '/admin/summaries/generate',
      method: 'POST',
      body: { id: 'revision/id' },
    },
  ])('管理コマンドを認証付きで対応するAPIへ送る: $method $path', ({ args, path, method, body }) => {
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

  it.each(
    [[], ['--hours', '0'], ['--hours=-1'], ['--hours', 'Infinity'], ['--hours', 'oops']].map((args) => ({ args })),
  )('足切りコマンドは不正な時間数を通信前に拒否する: %j', ({ args }) => {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'skip-before', ...args], {
      encoding: 'utf8',
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Usage: skip-before --hours HOURS');
  });

  it('generate-summary以外への--saveを通信前に拒否する', () => {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'list', 'summaries', '--save'], {
      encoding: 'utf8',
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('--save is only supported for generate-summary');
  });

  it.each([true, false])('--saveをAPIへ渡し、保存結果に応じた終了コードを返す: %s', (saved) => {
    const setup = `globalThis.fetch = async (url, init) => {
      if (new URL(url).pathname !== '/admin/summaries/generate') throw new Error('unexpected_path');
      if (JSON.stringify(JSON.parse(init.body)) !== JSON.stringify({ id: 'revision', save: true })) throw new Error('unexpected_body');
      return Response.json({ saved: ${saved} });
    };`;
    const result = spawnSync(
      process.execPath,
      [
        '--import',
        'tsx',
        '--import',
        `data:text/javascript,${encodeURIComponent(setup)}`,
        'src/cli.ts',
        'generate-summary',
        'revision',
        '--save',
      ],
      {
        encoding: 'utf8',
        env: { ...process.env, SECURITY_BOT_URL: 'http://localhost:8787', SECURITY_BOT_ADMIN_TOKEN: 'local-test' },
      },
    );
    expect(result.status).toBe(saved ? 0 : 1);
    expect(JSON.parse(result.stdout)).toEqual({ saved });
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

  it('リモート認証情報なしで同梱の設定に環境変数を反映して検証する', () => {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'config', 'validate'], {
      encoding: 'utf8',
      env: { ...process.env, BOT_MODE: 'free', DRY_RUN: 'true' },
    });
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      valid: true,
      mode: 'free',
      dryRun: true,
    });
  });

  it.each([
    { text: '// コメント\n{"dryRun": true,}', status: 0 },
    { text: '{"dryRun": false', status: 1 },
    { text: '{"dryRun": true}', status: 0 },
  ])('--configでJSON・JSONCを検証し、構文エラー時は失敗する: %j', ({ text, status }) => {
    const directory = mkdtempSync(join(tmpdir(), 'security-bot-config-'));
    const path = join(directory, 'custom.jsonc');
    try {
      writeFileSync(path, text);
      const result = spawnSync(
        process.execPath,
        ['--import', 'tsx', 'src/cli.ts', 'config', 'validate', '--config', path],
        { encoding: 'utf8' },
      );
      expect(result.status).toBe(status);
      if (status === 0) {
        expect(JSON.parse(result.stdout)).toMatchObject({ valid: true, dryRun: true });
      } else {
        expect(result.stderr).toContain('Invalid JSONC configuration');
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
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
