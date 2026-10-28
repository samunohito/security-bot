import type { PostIntent, PublishedPost } from '../domain';
import type { PublishDiagnostics } from './diagnostics';

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
    public diagnostics?: PublishDiagnostics,
  ) {
    super(message);
  }
}
