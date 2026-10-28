import { describe, expect, it } from 'vitest';
import type { ActionKind, PostIntent, SummaryTag } from '../src/domain';
import { formatPost } from '../src/social/format';

const claim = (text: string) => ({ text, evidence: [{ id: 'jvn:1', quote: text }] });
const tag = (kind: SummaryTag['kind'], text: string): SummaryTag => ({ kind, ...claim(text) });
const intent: PostIntent = {
  kind: 'new',
  key: 'CVE-2026-97860',
  title: '製品名を含む元記事の長い見出し',
  severity: 'High',
  summary: {
    subject: claim('ヤマハ YMS-VPN8／YMS-VPN8-CP'),
    overview: claim('Windowsサービスのファイルパスの引用符不備'),
    impact: claim('書き込み権限を持つユーザーにより、SYSTEM権限でコードが実行される可能性があります。'),
    action: claim('アップデートしてください。'),
    actionKind: 'routine_update',
    uncertainties: [],
    tags: [
      tag('product', 'YMS-VPN8'),
      tag('vendor', 'ヤマハ'),
      tag('theme', 'パス処理'),
      tag('usage', 'ネットワーク'),
      tag('product', 'YMS-VPN8-CP'),
    ],
  },
  sources: ['https://jvn.jp/jp/JVN30675482/'],
};

describe('投稿本文', () => {
  it('CVEと深刻度を先頭に置き、対象・問題・影響・出典・タグを重複なく段落にする', () => {
    expect(formatPost(intent)).toBe(
      '[High] CVE-2026-97860\n' +
        'ヤマハ YMS-VPN8／YMS-VPN8-CP\n' +
        'Windowsサービスのファイルパスの引用符不備\n\n' +
        '影響: 書き込み権限を持つユーザーにより、SYSTEM権限でコードが実行される可能性があります。\n\n' +
        '出典: https://jvn.jp/jp/JVN30675482/\n\n' +
        '#ネットワーク #パス処理 #ヤマハ #YMS_VPN8 #YMS_VPN8_CP',
    );
  });

  it('CVEのない話題では内部キーと深刻度を出さず、対象から始める', () => {
    const text = formatPost({ ...intent, key: 'jpcert:news-1' });
    expect(text.startsWith('ヤマハ YMS-VPN8／YMS-VPN8-CP\n')).toBe(true);
    expect(text).not.toContain('jpcert:news-1');
    expect(text).not.toContain('High');
    expect(text).not.toContain('影響:');
    expect(text).toContain(intent.summary.impact!.text);
  });

  it.each(['unpatched', 'workaround', 'additional_steps', 'patch_warning'] as ActionKind[])(
    '根拠を確認した例外の対策は本文に表示する: %s',
    (actionKind) => {
      const text = formatPost({
        ...intent,
        summary: { ...intent.summary, actionKind, action: claim('管理機能を無効にしてください。') },
      });
      expect(text).toContain('\n\n対策: 管理機能を無効にしてください。\n\n出典:');
    },
  );

  it('対策の種類や対策自体が不明な場合は、定型文や未提供の断定を出さない', () => {
    for (const summary of [
      { ...intent.summary, actionKind: null },
      { ...intent.summary, action: null, actionKind: null },
    ]) {
      const text = formatPost({ ...intent, summary });
      expect(text).not.toContain('対策:');
      expect(text).not.toContain('修正版未提供');
    }
  });

  it.each(['update', 'correction'] as const)('更新・訂正の表示をCVEの有無によらず維持する: %s', (kind) => {
    const label = kind === 'update' ? '更新' : '訂正';
    expect(formatPost({ ...intent, kind })).toMatch(new RegExp(`^\\[${label}\\] \\[High\\] CVE-`));
    expect(formatPost({ ...intent, kind, key: 'jvn:news' })).toMatch(new RegExp(`^\\[${label}\\] ヤマハ`));
  });

  it('旧要約では元の見出しを使い、影響と未確認事項を失わず、タグを捏造しない', () => {
    const text = formatPost({
      ...intent,
      summary: { overview: claim('問題の概要'), impact: null, action: null, uncertainties: ['対象バージョン未確認'] },
    });
    expect(text).toContain(`${intent.title}\n問題の概要`);
    expect(text).toContain('影響: 未確認');
    expect(text).toContain('未確認事項: 対象バージョン未確認');
    expect(text).not.toContain('#');
  });

  it('本文のメンション・MFM・任意タグを無効化し、抽出製品タグだけを安全に正規化する', () => {
    const text = formatPost({
      ...intent,
      summary: {
        ...intent.summary,
        subject: claim('Acme\n@everyone #任意タグ $[spin x]'),
        tags: [tag('product', 'Ａｃｍｅ-Server'), tag('product', 'acme-server'), tag('vendor', '@everyone')],
      },
    });
    expect(text).not.toContain('@everyone');
    expect(text).not.toContain('#任意タグ');
    expect(text).not.toContain('$[spin');
    expect(text).toContain('Acme @\u200beveryone');
    expect(text.split('\n\n').at(-1)).toBe('#ACME_SERVER');
  });

  it('固定候補にない分類・数値だけの名前・過剰な分類をタグとして出さない', () => {
    const text = formatPost({
      ...intent,
      summary: {
        ...intent.summary,
        tags: [
          tag('usage', '不明な分類'),
          tag('usage', 'ネットワーク'),
          tag('usage', 'OS'),
          tag('product', '12345'),
          tag('theme', '認証'),
          tag('theme', '暗号'),
          tag('theme', 'パス処理'),
        ],
      },
    });
    expect(text.split('\n\n').at(-1)).toBe('#ネットワーク #認証 #暗号');
  });

  it.each([
    ['.NET', '#NET'],
    ['AT&T', '#AT_T'],
    ['C++', '#C_PLUS_PLUS'],
    ['C#', '#C_SHARP'],
  ])('名称の記号を安全に変換し、C系の別製品を同じタグに潰さない: %s', (name, expected) => {
    const text = formatPost({ ...intent, summary: { ...intent.summary, tags: [tag('product', name)] } });
    expect(text.split('\n\n').at(-1)).toBe(expected);
  });
});
