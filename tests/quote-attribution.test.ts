import { describe, expect, it } from 'vitest';
import type { Evidence, Summary } from '../src/domain';
import { evidencePrompt } from '../src/llm/evidence';
import { validateSummary } from '../src/quality';
import { jvnArticle, jvnKey, otherKey } from './fixtures/evidence-articles';

function source(text: string, overrides: Partial<Evidence> = {}): Evidence {
  return {
    evidenceId: 'jvn:fixture',
    sourceId: 'jvn',
    id: 'fixture',
    scope: 'article',
    url: 'https://example.test/advisory',
    title: '対象の注意喚起',
    text,
    cves: [jvnKey, otherKey],
    scores: [],
    exploited: false,
    urgent: false,
    advisory: true,
    rejected: false,
    affected: null,
    impact: null,
    remediation: null,
    publishedAt: 0,
    modifiedAt: 0,
    fetchedAt: 0,
    ...overrides,
  };
}

function validate(quote: string, evidence: Evidence[], key = jvnKey) {
  const summary: Summary = {
    overview: { text: '対象の注意喚起', evidence: [{ id: evidence[0]!.evidenceId, quote }] },
    impact: null,
    action: null,
    uncertainties: [],
  };

  return validateSummary(summary, evidence, key);
}

describe('送信した原文位置からの引用帰属', () => {
  it.each(['\n', '\r\n', '\r'])('対象CVEラベル直後の番号なし説明を受理する: %j', (newline) => {
    const text = [
      '影響',
      `${jvnKey}:`,
      '細工したファイルをインポートすると任意のコードを実行される。',
      `${otherKey}: 別件。`,
    ].join(newline);
    expect(validate('細工したファイルをインポートすると任意のコードを実行される。', [source(text)]).valid).toBe(true);
  });

  it('本文抜粋から離れた対象節の番号なし引用も受理する', () => {
    const quote = 'ヒープバッファオーバーフローにより任意のコードを実行される可能性があります。';
    const evidence = source(jvnArticle);
    expect(evidencePrompt(jvnKey, [evidence]).evidence[0]!.text).not.toContain(quote);
    expect(validate(quote, [evidence]).valid).toBe(true);
  });

  it.each(['- ', '○ ', '1． ', '（2）【', '- [x] '])(
    '対象CVEの項目番号を除いて後続の設定行へ帰属を継承する: %s',
    (prefix) => {
      const text = `緩和策\n${prefix}${jvnKey}:\n- session.upload_progress.enabled=0に設定し、すべてのワーカーを再起動する\n${otherKey}: 別設定。`;
      expect(
        validate('session.upload_progress.enabled=0に設定し、すべてのワーカーを再起動する', [source(text)]).valid,
      ).toBe(true);
    },
  );

  it.each([
    `${otherKey}: ${jvnKey}と異なり、認証を無効化する。`,
    `${jvnKey}0: 別の脆弱性。`,
    `${jvnKey}と${otherKey}: 両方に関連する説明。`,
  ])('対象番号の包含だけでは他CVEや混在行の引用を受理しない: %s', (quote) => {
    expect(validate(quote, [source(`影響\n${quote}`)]).reasons).toContain('overview: ambiguous multi-CVE evidence');
  });

  it('別CVE項目内の対象参照を根拠にも新しい継承開始点にもしない', () => {
    const reference = `詳しくは ${jvnKey} を参照。`;
    const text = `影響\n${otherKey}: 別件。\n${reference}\n認証を無効化してください。`;
    for (const quote of [reference, '認証を無効化してください。']) {
      expect(validate(quote, [source(text)]).reasons).toContain('overview: ambiguous multi-CVE evidence');
    }
  });

  it.each([`${jvnKey}についての参考記事です。`, `${jvnKey} is mentioned only as a related advisory.`])(
    '他CVE項目内で対象CVEを先頭にした自然文からも帰属を奪わない: %s',
    (reference) => {
      const text = `影響\n${otherKey}: 別件。\n${reference}\n認証を無効化してください。`;
      for (const quote of [reference, '認証を無効化してください。']) {
        expect(validate(quote, [source(text)]).valid).toBe(false);
      }
    },
  );

  it.each([`${jvnKey}と${otherKey}に共通する参考情報。`, `なお、この設定は${otherKey}でも使われます。`])(
    '混在行や非先頭の他CVE参照で後続への継承を停止する: %s',
    (boundary) => {
      const text = `影響\n${jvnKey}: 対象。\n${boundary}\n認証を無効化してください。`;
      expect(validate('認証を無効化してください。', [source(text)]).valid).toBe(false);
    },
  );

  it.each(['', '  ', '対策', '## 補足', '3. 補足資料', '1. 設定変更の手順'])(
    '空行や見出しを越えて対象帰属を継承しない: %j',
    (boundary) => {
      const text = `影響\n${jvnKey}: 対象。\n${boundary}\n認証を無効化してください。`;
      expect(validate('認証を無効化してください。', [source(text)]).valid).toBe(false);
    },
  );

  it.each(['1.0.0', '1.x', '2.*'])('バージョン表記の行は番号付き見出しとして帰属を切断しない: %s', (version) => {
    expect(validate('設定を無効にする。', [source(`影響\n${jvnKey}\n${version}\n設定を無効にする。`)]).valid).toBe(
      true,
    );
  });

  it('新しい明確な対象項目からは再び帰属を継承する', () => {
    const text = `影響\n${otherKey}: 別件。\n詳しくは ${jvnKey} を参照。\n- ${jvnKey}: 対象。\n設定を無効にする。`;
    expect(validate('設定を無効にする。', [source(text)]).valid).toBe(true);
  });

  it('非先頭の対象番号を含む自然文は同一行だけの根拠にする', () => {
    const line = `開発者は${jvnKey}への対策を案内しました。`;
    const text = `緩和策\n${line}\n設定を無効にする。`;
    expect(validate(line, [source(text)]).valid).toBe(true);
    expect(validate('設定を無効にする。', [source(text)]).valid).toBe(false);
  });

  it.each([`${jvnKey}についての参考記事です。`, `${jvnKey} is mentioned as a reference.`])(
    '対象CVEで始まっても自然文から次の行へ帰属を継承しない: %s',
    (line) => {
      const text = `影響\n${line}\n認証を無効化してください。`;
      expect(validate(line, [source(text)]).valid).toBe(true);
      expect(validate('認証を無効化してください。', [source(text)]).valid).toBe(false);
    },
  );

  it.each([`${jvnKey}`, `${jvnKey}: 対象。`, `- [${jvnKey}]: 対象。`, `（2）【${jvnKey}】：対象。`])(
    '単独の番号や区切りの明確なCVE項目ラベルからだけ継承する: %s',
    (label) => {
      expect(validate('設定を無効にする。', [source(`影響\n${label}\n設定を無効にする。`)]).valid).toBe(true);
    },
  );

  it('独立した自然文の複数CVE列記を後続段落の対象帰属へ持ち越さない', () => {
    const line = `開発者は${jvnKey}への対策を案内しました。`;
    const text = `緩和策\n他の脆弱性${otherKey}とCVE-2026-8888の案内。\n${line}\n設定を無効にする。`;
    expect(validate(line, [source(text)]).valid).toBe(true);
    expect(validate('設定を無効にする。', [source(text)]).valid).toBe(false);
  });

  it('独立した自然文のCVE列記から別の自然文行への帰属ロックを開始しない', () => {
    const line = `開発者は${jvnKey}への対策を案内しました。`;
    const text = `緩和策\n別の脆弱性${otherKey}の説明。\n${line}\n設定を無効にする。`;
    expect(validate(line, [source(text)]).valid).toBe(true);
    expect(validate('設定を無効にする。', [source(text)]).valid).toBe(false);
  });

  it('対象項目中の混在行から自然文の対象参照へ継承を再開しない', () => {
    const line = `詳しくは ${jvnKey} を参照。`;
    const text = `影響\n${jvnKey}: 対象。\n両方の${jvnKey}と${otherKey}に共通する説明。\n${line}`;
    expect(validate(line, [source(text)]).valid).toBe(false);
  });

  it('同じ対象CVEの自然文が挟まっても項目所属を忘れず他CVEへの言及後は保留する', () => {
    const reference = `詳しくは ${jvnKey} を参照。`;
    const text = `影響\n${jvnKey}: 対象。\n${jvnKey}についての説明。\nなお${otherKey}も関連します。\n${reference}`;
    expect(validate(reference, [source(text)]).valid).toBe(false);
  });

  it('他CVEで始まる自然文は区切りが不明でも別項目として後続の対象参照を保留する', () => {
    const reference = `開発者は${jvnKey}への対策を案内しました。`;
    const text = `緩和策\n${otherKey} is an unrelated vulnerability.\n${reference}`;
    expect(validate(reference, [source(text)]).valid).toBe(false);
  });

  it('同じ送信フィールド内でも対象と他CVEの境界をまたぐ引用を拒否する', () => {
    const quote = `${jvnKey}: 対象。\n${otherKey}: 別件。`;
    expect(validate(quote, [source(`影響\n${quote}`)]).valid).toBe(false);
  });

  it('共通節を対象CVEの帰属確認済みとして受理しない', () => {
    const text = `影響\n${jvnKey}: 対象。\n対策\n開発者の情報を確認する。`;
    expect(validate('開発者の情報を確認する。', [source(text)]).valid).toBe(false);
  });

  it('同文の送信候補位置が対象と別CVEに存在するときは保留する', () => {
    const text = `影響\n${jvnKey}: 対象。\n同じ対策です。\n${otherKey}: 別件。\n同じ対策です。`;
    expect(validate('同じ対策です。', [source(text)]).valid).toBe(false);
  });

  it('同じ原文位置を本文と節で送っただけなら曖昧として拒否しない', () => {
    const text = `影響\n${jvnKey}: 対象。\n設定を無効にする。`;
    expect(validate('設定を無効にする。', [source(text)]).valid).toBe(true);
  });

  it('複数の送信位置がすべて対象に対応するときは同文引用を受理する', () => {
    const text = `影響\n${jvnKey}: 対象。\n同じ対策です。\n${jvnKey}: 対象。\n同じ対策です。`;
    expect(validate('同じ対策です。', [source(text)]).valid).toBe(true);
  });

  it('未送信の他CVE項目に同文があるだけでは曖昧としない', () => {
    const text = `影響\n${jvnKey}: 対象。\n同じ対策です。\n参考情報\n${'背景。'.repeat(500)}\n${otherKey}: 別件。\n同じ対策です。`;
    expect(validate('同じ対策です。', [source(text)]).valid).toBe(true);
  });

  it('抽出済み節が複数の原文位置に一致する場合は最初の対象位置だけで帰属を決めない', () => {
    const text = `影響\n${jvnKey}: 対象。\n同じ対策です。\n参考情報\n${'背景。'.repeat(500)}\n${otherKey}: 別件。\n同じ対策です。`;
    expect(validate('同じ対策です。', [source(text, { remediation: '同じ対策です。' })]).valid).toBe(false);
  });

  it('本文抜粋の先頭より前にある他CVE項目の帰属を保持する', () => {
    const reference = `詳しくは ${jvnKey} を参照。`;
    const text = `影響\n${otherKey}: ${'説明'.repeat(200)}\n${reference}`;
    expect(evidencePrompt(jvnKey, [source(text)]).evidence[0]!.text).not.toContain(otherKey);
    expect(validate(reference, [source(text)]).valid).toBe(false);
  });

  it('小文字の対象CVEラベルでも完全な識別子として照合する', () => {
    expect(validate('設定を無効にする。', [source(`影響\n${jvnKey.toLowerCase()}:\n設定を無効にする。`)]).valid).toBe(
      true,
    );
  });

  it.each(['cve', 'article'] as const)('保存全文にあっても未送信の引用を受理しない: %s', (scope) => {
    const text = `${jvnKey}: 対象。\n${'背景。'.repeat(500)}\n未送信の対策。`;
    expect(validate('未送信の対策。', [source(text, { scope })]).reasons).toContain('overview: evidence not supplied');
  });

  it('本文と節を連結しても単一の送信範囲に存在しない引用は受理しない', () => {
    const text = `${'a'.repeat(997)}XYZtail`;
    const evidence = source(text, { scope: 'cve', remediation: 'tail' });
    expect(evidencePrompt(jvnKey, [evidence]).evidence[0]!.text).toHaveLength(1000);
    expect(validate('XYZtail', [evidence]).reasons).toContain('overview: evidence not supplied');
  });

  it('本文抜粋外でも単独の節として送った単一CVEの引用を受理する', () => {
    const text = `${'背景。'.repeat(500)}\n設定を無効にする。`;
    expect(
      validate('設定を無効にする。', [source(text, { scope: 'cve', remediation: '設定を無効にする。' })]).valid,
    ).toBe(true);
  });

  it('5件目の情報源からの引用を保存全文だけで受理しない', () => {
    const evidence = Array.from({ length: 5 }, (_, index) =>
      source('対象の注意喚起。', { evidenceId: `jvn:${index}`, scope: 'cve' }),
    );
    const summary: Summary = {
      overview: { text: '対象の注意喚起', evidence: [{ id: 'jvn:4', quote: '対象の注意喚起。' }] },
      impact: null,
      action: null,
      uncertainties: [],
    };
    expect(validateSummary(summary, evidence, jvnKey).reasons).toContain('overview: evidence not supplied');
  });

  it.each(['https://example.test/advisory', '対象の注意喚起'])(
    '本文や節にないメタデータを引用として受理しない: %s',
    (quote) => {
      expect(validate(quote, [source('別の本文。', { scope: 'cve' })]).reasons).toContain(
        'overview: fabricated evidence',
      );
    },
  );

  it('抜粋末尾で切れた別CVE番号を対象番号と誤認しない', () => {
    const label = `${jvnKey}:\n`;
    const prefix = `${label}${'x'.repeat(998 - label.length - jvnKey.length)}\n`;
    const text = `${prefix}${jvnKey}0: 別件。`;
    const entry = source(text);
    expect(evidencePrompt(jvnKey, [entry]).evidence[0]!.text).not.toContain(`${jvnKey}0:`);
    expect(validate(jvnKey, [entry]).valid).toBe(false);
  });

  it('CVEのない記事では送信範囲の検査を維持しCVE帰属は要求しない', () => {
    expect(
      validate('セキュリティ動向の注意喚起。', [source('セキュリティ動向の注意喚起。', { cves: [] })], 'jvn:fixture')
        .valid,
    ).toBe(true);
  });

  it('長文に同じ抽出値が大量に存在しても入力生成や引用検査を中断しない', () => {
    const evidence = source('a'.repeat(150_000), { scope: 'cve', affected: 'aa' });
    expect(evidencePrompt(jvnKey, [evidence]).evidence[0]!.text).toHaveLength(1000);
    expect(validate('aa', [evidence]).valid).toBe(true);
  });
});
