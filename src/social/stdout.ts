import type { PostIntent, PublishedPost } from '../domain';
import type { PreparedPost, SocialProvider } from './provider';
import { UrlReferenceProvider } from './url-reference';

export class StdoutSocialProvider implements SocialProvider {
  /** ローカル出力の文字数上限と、本文の出力先を指定する。 */
  constructor(
    private maxCharacters = 3000,
    private write: (text: string) => void = (text) => console.log(text),
  ) {}

  /** 通常の投稿書式とURL参照を使い、文字数上限を検証する。 */
  prepare(intent: PostIntent): PreparedPost {
    return new UrlReferenceProvider(this.maxCharacters).prepare(intent);
  }

  /** SNSへ送信せず本文を出力し、保存用途を想定しない擬似投稿情報を返す。 */
  async publish(post: PreparedPost): Promise<PublishedPost> {
    this.write(post.text);

    return { id: 'stdout-preview', url: 'https://preview.invalid/notes/stdout-preview' };
  }
}
