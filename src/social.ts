import type { TargetConfig } from './config';
import type { PostIntent, PublishedPost } from './domain';
import type { Fetcher } from './http';

export interface PreparedPost {
  text: string;
  referenceId?: string;
  fallbackText?: string;
}

export interface SocialProvider {
  /** 投稿意図を投稿先へ渡せる本文と参照情報に整形する。 */
  prepare(intent: PostIntent): PreparedPost;

  /** 整形済み投稿を送信し、作成された投稿の識別子とURLを返す。 */
  publish(post: PreparedPost): Promise<PublishedPost>;
}

export class PublishError extends Error {
  /** 送信結果の確実性と再試行条件を呼び出し側へ伝える。 */
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

/** 投稿意図を日本語のセキュリティ告知文に整形する。 */
export function formatPost(intent: PostIntent): string {
  const summary = intent.summary;
  const label = intent.kind === 'new' ? '' : intent.kind === 'correction' ? '訂正 ' : '更新 ';

  return [
    `【${label}${intent.severity}】${intent.key}`,
    escapeText(intent.title),
    `概要: ${escapeText(summary.overview?.text ?? '未確認')}`,
    `影響: ${escapeText(summary.impact?.text ?? '未確認')}`,
    `対策: ${escapeText(summary.action?.text ?? '未確認')}`,
    ...(summary.uncertainties.length ? [`未確認事項: ${escapeText(summary.uncertainties.join('／'))}`] : []),
    `出典: ${intent.sources.join('\n')}`,
  ].join('\n');
}

export class UrlReferenceProvider {
  /** URL参照を含む投稿全体の文字数上限を設定する。 */
  constructor(private maxCharacters: number) {}

  /** 既存投稿へのURLを添えた更新文を作成し、文字数上限を検証する。 */
  prepare(intent: PostIntent): PreparedPost {
    const text = formatPost(intent) + (intent.previousPost ? `\n関連投稿: ${intent.previousPost.url}` : '');
    if ([...text].length > this.maxCharacters) {
      throw new Error('post_too_long');
    }

    return { text };
  }
}

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
