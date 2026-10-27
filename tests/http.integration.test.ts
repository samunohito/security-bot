import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';
import { getText, type Fetcher } from '../src/http';
import { MisskeyProvider } from '../src/social/misskey';

function workersFetch(response: Response): Fetcher {
  return async (input, init) => {
    const request = new Request(input, init);
    expect(request.redirect).toBe('manual');

    return response;
  };
}

describe('Workersの外部HTTP通信', () => {
  it('Workersランタイムで情報源の本文を取得できる', async () => {
    expect(await getText('https://source.example/article', {}, workersFetch(new Response('advisory')))).toMatchObject({
      text: 'advisory',
    });
  });

  it('情報源のリダイレクトを追従せず拒否する', async () => {
    const response = new Response('', { status: 302, headers: { location: 'https://other.example/article' } });
    await expect(getText('https://source.example/article', {}, workersFetch(response))).rejects.toMatchObject({
      status: 302,
      retryable: false,
    });
  });

  it('WorkersランタイムでMisskeyへ投稿できる', async () => {
    const target = loadConfig({ targets: [{ id: 'main', baseUrl: 'https://social.example', tokenSecret: 'TOKEN' }] })
      .targets[0]!;
    const response = Response.json({ createdNote: { id: 'one' } });
    expect(await new MisskeyProvider(target, 'test-token', workersFetch(response)).publish({ text: 'test' })).toEqual({
      id: 'one',
      url: 'https://social.example/notes/one',
    });
  });

  it('Misskeyのリダイレクトを追従や再送可能な失敗として扱わない', async () => {
    const target = loadConfig({ targets: [{ id: 'main', baseUrl: 'https://social.example', tokenSecret: 'TOKEN' }] })
      .targets[0]!;
    const response = new Response('', { status: 307, headers: { location: 'https://other.example/api/notes/create' } });
    await expect(
      new MisskeyProvider(target, 'test-token', workersFetch(response)).publish({ text: 'test' }),
    ).rejects.toMatchObject({ kind: 'unknown' });
  });
});
