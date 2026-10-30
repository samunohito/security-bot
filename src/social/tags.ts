import type { SummaryTag } from '../domain';

export const USAGE_TAGS = [
  'ネットワーク',
  'OS',
  'ブラウザ',
  '業務アプリ',
  'Web基盤',
  '開発ツール',
  'クラウド基盤',
  'データベース',
  '組み込み機器',
] as const;

export const THEME_TAGS = [
  '認証',
  'アクセス制御',
  '暗号',
  'メモリ安全性',
  'インジェクション',
  'パス処理',
  'サプライチェーン',
] as const;

export const TAG_CRITERIA: Record<(typeof USAGE_TAGS)[number] | (typeof THEME_TAGS)[number], string> = {
  ネットワーク: 'VPN、ルーター、DNS、プロキシなど。動作OSより対象製品の主な用途を優先する。',
  OS: 'OS本体、カーネル、ドライバー。単にOS上で動作するアプリは含めない。',
  ブラウザ: 'ブラウザ本体と拡張機能。',
  業務アプリ: 'グループウェア、文書管理、業務システム。',
  Web基盤: 'Webサーバー、CMS、Webフレームワーク。',
  開発ツール: 'IDE、ビルドツール、パッケージ管理。',
  クラウド基盤: '仮想化、コンテナ、クラウド管理。',
  データベース: 'データベース本体と管理ツール。',
  組み込み機器: 'IoT、家電、産業機器。ルーターなど主用途がネットワークならそちらを選ぶ。',
  認証: '本人確認、ログイン、セッション管理が問題に直接関係する。',
  アクセス制御: '権限チェックの不備や、本来許されない資源へのアクセス。',
  暗号: '暗号方式、鍵、証明書検証そのものの問題。暗号を使う製品という理由では選ばない。',
  メモリ安全性: 'バッファオーバーフロー、解放後使用など。',
  インジェクション: 'SQL、コマンド、スクリプトなどの不正な解釈・実行。任意コード実行の被害だけでは選ばない。',
  パス処理: 'パストラバーサル、ファイルパスの解釈の問題。',
  サプライチェーン: '配布物、依存関係、更新経路の侵害。依存ライブラリの通常の脆弱性だけでは選ばない。',
};

export const EXTRACTED_TAG_PATTERN = /^[\p{L}\p{N}.][\p{L}\p{N}\p{M} ._/()+&#-]{0,79}$/u;

function tagName(tag: SummaryTag): string | null {
  if (tag.kind === 'usage') {
    return USAGE_TAGS.find((name) => name === tag.text) ?? null;
  }
  if (tag.kind === 'theme') {
    return THEME_TAGS.find((name) => name === tag.text) ?? null;
  }
  if (!['vendor', 'product'].includes(tag.kind) || !EXTRACTED_TAG_PATTERN.test(tag.text)) {
    return null;
  }

  const name = tag.text
    .normalize('NFKC')
    .trim()
    .replace(/\+/g, '_PLUS')
    .replace(/#/g, '_SHARP')
    .replace(/[^\p{L}\p{N}\p{M}_]+/gu, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();

  return /^\d+$/.test(name) ? null : name;
}

/** 投稿時のタグ表記で重複を除き、分類ごとの上限内で候補順に採用する。根拠検証は呼び出し側で行う。 */
export function selectTags(tags: SummaryTag[]): SummaryTag[] {
  const selected: SummaryTag[] = [];
  const names: string[] = [];
  const limits = { usage: 1, theme: 2, vendor: 1, product: 2 };
  for (const kind of ['usage', 'theme', 'vendor', 'product'] as const) {
    let count = 0;
    for (const tag of tags.filter((tag) => tag.kind === kind)) {
      const name = tagName(tag);
      if (!name || names.includes(name) || count >= limits[kind] || names.length >= 6) {
        continue;
      }
      names.push(name);
      selected.push(tag);
      count++;
    }
  }

  return selected;
}

/** 固定分類と抽出名称を安全なハッシュタグへ変換し、分類順に重複なく並べる。 */
export function formatHashtags(tags: SummaryTag[]): string {
  return selectTags(tags)
    .map((tag) => `#${tagName(tag)}`)
    .join(' ');
}
