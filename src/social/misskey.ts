import type { TargetConfig } from '../config';
import type { PostIntent, PublishedPost } from '../domain';
import type { Fetcher } from '../http';
import { formatPost } from './format';
import { PublishError, type PreparedPost, type SocialProvider } from './provider';
import { UrlReferenceProvider } from './url-reference';

export class MisskeyProvider implements SocialProvider {
  private base: string;

  /** 投稿先設定と認証情報からMisskey送信アダプターを構成する。 */
  constructor(
    private target: TargetConfig,
    private token: string,
    private fetcher: Fetcher = fetch,
  ) {
    this.base = target.baseUrl.replace(/\/$/, '');
  }

  /** Misskeyの文字数制限内で投稿本文と更新参照を準備する。 */
  prepare(intent: PostIntent): PreparedPost {
    const text = formatPost(intent);
    if ([...text].length > this.target.maxCharacters) {
      throw new Error('post_too_long');
    }

    let fallbackText: string | undefined;
    if (intent.previousPost) {
      try {
        fallbackText = new UrlReferenceProvider(this.target.maxCharacters).prepare(intent).text;
      } catch {
        // URL参照で長さを超えても引用投稿は可能なので、ここでは投稿全体を拒否しない。
      }
    }

    return { text, referenceId: intent.previousPost?.id, fallbackText };
  }

  /** Misskeyへ投稿し、応答が不明な送信は再送可能な失敗として扱わない。 */
  async publish(post: PreparedPost): Promise<PublishedPost> {
    if (!this.token) {
      throw new PublishError('auth', 'missing_social_secret');
    }

    let response: Response;
    try {
      response = await this.fetcher(`${this.base}/api/notes/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.token}`,
        },
        body: JSON.stringify({
          text: post.text,
          renoteId: post.referenceId,
          visibility: this.target.visibility,
          noExtractMentions: true,
          noExtractHashtags: true,
          noExtractEmojis: true,
        }),
        signal: AbortSignal.timeout(15000),
        redirect: 'error',
      });
    } catch {
      throw new PublishError('unknown', 'send_result_unknown');
    }

    if (response.status === 401 || response.status === 403) {
      throw new PublishError('auth', 'social_auth_failed');
    }
    if (response.status === 429) {
      const retry = response.headers.get('retry-after');
      throw new PublishError(
        'retry',
        'social_rate_limited',
        retry && /^\d+$/.test(retry) ? Number(retry) * 1000 : 60000,
      );
    }
    if (response.status >= 500) {
      throw new PublishError('unknown', 'social_server_result_unknown');
    }

    let body: { error?: { code?: string }; createdNote?: { id?: string } };
    try {
      body = (await response.json()) as typeof body;
    } catch {
      throw new PublishError(response.ok ? 'unknown' : 'rejected', 'invalid_social_response');
    }

    if (!response.ok) {
      if (
        post.referenceId &&
        ['NO_SUCH_RENOTE_TARGET', 'CANNOT_RENOTE_DUE_TO_VISIBILITY', 'CANNOT_RENOTE_OUTSIDE_OF_CHANNEL'].includes(
          body.error?.code ?? '',
        )
      ) {
        if (!post.fallbackText) {
          throw new PublishError('rejected', 'reference_fallback_too_long');
        }
        return this.publish({ text: post.fallbackText });
      }
      throw new PublishError('rejected', 'social_rejected');
    }
    if (!body.createdNote?.id) {
      throw new PublishError('unknown', 'missing_published_id');
    }

    return {
      id: body.createdNote.id,
      url: `${this.base}/notes/${encodeURIComponent(body.createdNote.id)}`,
    };
  }
}
