import type { Environment, TargetConfig } from '../config';
import { MisskeyProvider } from './misskey';
import type { SocialProvider } from './provider';
import { StdoutSocialProvider } from './stdout';

/** 投稿先設定に応じて、Misskey送信またはネットワークを使わないstdout出力を選ぶ。 */
export function createSocialProvider(target: TargetConfig, env: Environment = {}): SocialProvider {
  if (target.provider === 'fake') {
    return new StdoutSocialProvider(target.maxCharacters);
  }

  return new MisskeyProvider(target, String(env[target.tokenSecret] ?? ''));
}
