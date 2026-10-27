import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

describe('operator CLI', () => {
  it('validates bundled config without requiring remote credentials', () => {
    const result = spawnSync(
      process.execPath,
      ['--import', 'tsx', 'src/cli.ts', 'config', 'validate'],
      { encoding: 'utf8' },
    );
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      valid: true,
      mode: 'free',
      dryRun: true,
    });
  });
  it('returns a useful error when remote credentials are absent', () => {
    const result = spawnSync(
      process.execPath,
      ['--import', 'tsx', 'src/cli.ts', 'status'],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          SECURITY_BOT_URL: '',
          SECURITY_BOT_ADMIN_TOKEN: '',
        },
      },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('SECURITY_BOT_URL');
  });
});
