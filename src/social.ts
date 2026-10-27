import type { TargetConfig } from './config';
import type { PostIntent, PublishedPost } from './domain';
import type { Fetcher } from './http';
export interface PreparedPost {
  text: string;
  referenceId?: string;
  fallbackText?: string;
}
export interface SocialProvider {
  prepare(intent: PostIntent): PreparedPost;
  publish(post: PreparedPost): Promise<PublishedPost>;
}
export class PublishError extends Error {
  constructor(
    public kind: 'auth' | 'retry' | 'rejected' | 'unknown',
    message: string,
    public retryAfterMs = 0,
  ) {
    super(message);
  }
}
function escapeText(text: string): string {
  return text.replace(/[@#$*`<>\[\]\\]/g, (s) => `${s}\u200b`);
}
export function formatPost(intent: PostIntent): string {
  const s = intent.summary;
  const label = intent.kind === 'new' ? '' : intent.kind === 'correction' ? '訂正 ' : '更新 ';
  return [
    `【${label}${intent.severity}】${intent.key}`,
    escapeText(intent.title),
    `概要: ${escapeText(s.overview?.text ?? '未確認')}`,
    `影響: ${escapeText(s.impact?.text ?? '未確認')}`,
    `対策: ${escapeText(s.action?.text ?? '未確認')}`,
    ...(s.uncertainties.length ? [`未確認事項: ${escapeText(s.uncertainties.join('／'))}`] : []),
    `出典: ${intent.sources.join('\n')}`,
  ].join('\n');
}
export class UrlReferenceProvider {
  constructor(private maxCharacters: number) {}
  prepare(intent: PostIntent): PreparedPost {
    const text = formatPost(intent) + (intent.previousPost ? `\n関連投稿: ${intent.previousPost.url}` : '');
    if ([...text].length > this.maxCharacters) throw new Error('post_too_long');
    return { text };
  }
}
export class MisskeyProvider implements SocialProvider {
  private base: string;
  constructor(
    private target: TargetConfig,
    private token: string,
    private fetcher: Fetcher = fetch,
  ) {
    this.base = target.baseUrl.replace(/\/$/, '');
  }
  prepare(intent: PostIntent): PreparedPost {
    const text = formatPost(intent);
    if ([...text].length > this.target.maxCharacters) throw new Error('post_too_long');
    let fallbackText: string | undefined;
    if (intent.previousPost) {
      try {
        fallbackText = new UrlReferenceProvider(this.target.maxCharacters).prepare(intent).text;
      } catch {
        /* fallback is held if quote becomes unavailable */
      }
    }
    return { text, referenceId: intent.previousPost?.id, fallbackText };
  }
  async publish(post: PreparedPost): Promise<PublishedPost> {
    if (!this.token) throw new PublishError('auth', 'missing_social_secret');
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
    if (response.status === 401 || response.status === 403) throw new PublishError('auth', 'social_auth_failed');
    if (response.status === 429) {
      const retry = response.headers.get('retry-after');
      throw new PublishError(
        'retry',
        'social_rate_limited',
        retry && /^\d+$/.test(retry) ? Number(retry) * 1000 : 60000,
      );
    }
    if (response.status >= 500) throw new PublishError('unknown', 'social_server_result_unknown');
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
        if (!post.fallbackText) throw new PublishError('rejected', 'reference_fallback_too_long');
        return this.publish({ text: post.fallbackText });
      }
      throw new PublishError('rejected', 'social_rejected');
    }
    if (!body.createdNote?.id) throw new PublishError('unknown', 'missing_published_id');
    return {
      id: body.createdNote.id,
      url: `${this.base}/notes/${encodeURIComponent(body.createdNote.id)}`,
    };
  }
}
