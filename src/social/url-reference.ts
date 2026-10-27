import type { PostIntent } from '../domain';
import { formatPost } from './format';
import type { PreparedPost } from './provider';

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
