import { z } from 'zod';
import type { TargetConfig } from '../config';
import type { PostIntent, PublishedPost } from '../domain';
import type { Fetcher } from '../http';
import { formatPost } from './format';
import { PublishError, type PreparedPost, type SocialProvider } from './provider';
import { UrlReferenceProvider } from './url-reference';
import { describeMisskeyCode, describePublishFailure, type PublishDiagnostics } from './diagnostics';

const responseSchema = z.object({
  error: z.object({ code: z.string().optional() }).optional(),
  createdNote: z.object({ id: z.string().min(1).optional() }).optional(),
});

async function httpFailureDiagnostics(response: Response): Promise<PublishDiagnostics> {
  const diagnostics: PublishDiagnostics = { phase: 'response', status: response.status };
  if (!response.body) {
    return diagnostics;
  }

  const reader = response.body.getReader();
  try {
    const decoder = new TextDecoder();
    let bytes = 0;
    let text = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      bytes += value.byteLength;
      if (bytes > 16384) {
        await reader.cancel();
        return diagnostics;
      }
      text += decoder.decode(value, { stream: true });
    }
    const body = responseSchema.safeParse(JSON.parse(text + decoder.decode()));
    if (body.success) {
      diagnostics.apiCode = describeMisskeyCode(body.data.error?.code);
    }
  } catch {
    // エラー本文を読めなくても、HTTP応答で確定した認証失敗・レート制限などの分類は変えない。
  } finally {
    reader.releaseLock();
  }

  return diagnostics;
}

export class MisskeyProvider implements SocialProvider {
  private base: string;

  /** 投稿先設定と認証情報からMisskey送信アダプターを構成する。 */
  constructor(
    private target: TargetConfig,
    private token: string,
    private fetcher: Fetcher = fetch,
  ) {
    if (target.provider !== 'misskey') {
      throw new Error('misskey_provider_requires_misskey_target');
    }

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
      const fetcher = this.fetcher;
      response = await fetcher(`${this.base}/api/notes/create`, {
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
          noExtractHashtags: false,
          noExtractEmojis: true,
        }),
        signal: AbortSignal.timeout(15000),
        redirect: 'manual',
      });
    } catch (error) {
      throw new PublishError('unknown', 'send_result_unknown', 0, describePublishFailure(error, 'request'));
    }

    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new PublishError('unknown', 'social_redirect_result_unknown', 0, {
        phase: 'response',
        status: response.status,
      });
    }
    if (response.status === 401 || response.status === 403) {
      throw new PublishError('auth', 'social_auth_failed', 0, await httpFailureDiagnostics(response));
    }
    if (response.status === 429) {
      const retry = response.headers.get('retry-after');
      throw new PublishError(
        'retry',
        'social_rate_limited',
        retry && /^\d+$/.test(retry) ? Number(retry) * 1000 : 60000,
        await httpFailureDiagnostics(response),
      );
    }
    if (response.status >= 500) {
      throw new PublishError('unknown', 'social_server_result_unknown', 0, await httpFailureDiagnostics(response));
    }

    let body: z.infer<typeof responseSchema>;
    try {
      body = responseSchema.parse(await response.json());
    } catch (error) {
      throw new PublishError(
        response.ok ? 'unknown' : 'rejected',
        'invalid_social_response',
        0,
        describePublishFailure(error, 'response_body', response.status),
      );
    }

    if (!response.ok) {
      if (
        post.referenceId &&
        ['NO_SUCH_RENOTE_TARGET', 'CANNOT_RENOTE_DUE_TO_VISIBILITY', 'CANNOT_RENOTE_OUTSIDE_OF_CHANNEL'].includes(
          body.error?.code ?? '',
        )
      ) {
        if (!post.fallbackText) {
          throw new PublishError('rejected', 'reference_fallback_too_long', 0, {
            phase: 'response',
            status: response.status,
            apiCode: describeMisskeyCode(body.error?.code),
          });
        }
        return this.publish({ text: post.fallbackText });
      }
      throw new PublishError('rejected', 'social_rejected', 0, {
        phase: 'response',
        status: response.status,
        apiCode: describeMisskeyCode(body.error?.code),
      });
    }
    if (!body.createdNote?.id) {
      throw new PublishError('unknown', 'missing_published_id', 0, { phase: 'response_body', status: response.status });
    }

    return {
      id: body.createdNote.id,
      url: `${this.base}/notes/${encodeURIComponent(body.createdNote.id)}`,
    };
  }
}
