import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

describe('operator CLI', () => {
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
