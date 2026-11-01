import { describe, expect, it } from 'vitest';
import { normalizeItem, type Evidence } from '../src/domain';
import { evidencePrompt } from '../src/llm/evidence';
import { validateSummary } from '../src/quality';
import { enrichArticle, parseKev, parseNvd } from '../src/sources/parsers';
import { jvnArticle, jvnKey, otherKey, phpArticle, phpKey, phpMitigation } from './fixtures/evidence-articles';

function article(text: string, key = jvnKey): Evidence {
  return normalizeItem({
    sourceId: 'jvn',
    id: 'fixture',
    title: '複数CVEの注意喚起',
    url: 'https://jvn.jp/fixture',
    text,
    cves: [key, otherKey],
    scores: [{ score: 9.8, version: '3.1', issuer: 'article' }],
    exploited: true,
    urgent: true,
    advisory: true,
    rejected: false,
    affected: null,
    impact: null,
    remediation: null,
    publishedAt: 0,
    modifiedAt: 0,
    fetchedAt: 0,
  }).find((entry) => entry.key === key)!.evidence;
}

describe('記事本文から補うLLM入力', () => {
  it('入れ子の日本語引用符の内側を値全体の終端とみなさない', () => {
    const text = `緩和策\n${jvnKey}: banner=「注記「即時」を表示。 ${'x'.repeat(430)}」に設定。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it('入れ子の日本語引用符が閉じた短い設定は保持する', () => {
    const first = `${jvnKey}: banner=「注記「即時」」 に設定。`;
    expect(
      evidencePrompt(jvnKey, [article(`緩和策\n${first} ${'x'.repeat(430)}`)]).evidence[0]!.sections.remediation,
    ).toBe(first);
  });

  it('同じ段落の長い補足にかかわらず完結した短い設定・再起動指示を残す', () => {
    const first = `${jvnKey}: session.upload_progress.enabled=0に設定し、すべてのワーカーを再起動してください。`;
    const text = `${jvnKey}について\n${'背景。'.repeat(400)}\n緩和策\n${first} ${'x'.repeat(430)}`;
    const result = evidencePrompt(jvnKey, [article(text)]).evidence[0]!;
    expect(result.text).not.toContain('session.upload_progress.enabled=0');
    expect(result.sections.remediation).toBe(first);
  });

  it.each(['f"Select {mapping["Stop."]} now"', '$"Select {mapping["Stop."]} now"', '`Select ${mapping[`Stop.`]} now`'])(
    '短い補間設定値と文末までが収まる場合は値と再起動を残す: %s',
    (value) => {
      const first = `${jvnKey}: banner=${value} に設定し再起動。`;
      const text = `緩和策\n${first} ${'x'.repeat(430)}`;
      expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(first);
    },
  );

  it.each(['1.x before 1.9.0', '2.*', '1.x.y before 1.9.0'])(
    'ワイルドカードの影響バージョン行を見出しとみなさない: %s',
    (version) => {
      const body = `${jvnKey}\n${version}`;
      const text = `Affected Products\n${body}\nReferences\n資料。`;
      expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.affected).toBe(body);
    },
  );

  it('代入された補間文字列の内部引用符で設定値を切らない', () => {
    const text = `緩和策\n${jvnKey}: banner=f"Select {mapping["Stop. ${'x'.repeat(430)}"]} now" に設定。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it.each(["Don't disable authentication.", "users' authentication is not affected."])(
    'CVE行のコロンの直後でも英文の短縮形・所有格を保持する: %s',
    (sentence) => {
      const first = `${jvnKey}: ${sentence}`;
      const text = `Impact\n${first} ${'x'.repeat(430)}`;
      expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.impact).toBe(first);
    },
  );

  it.each(["'''Don't stop. ", '"""Use "Stop. ', '```Use `Stop. '])(
    '複数文字の引用符を文字列内の単独引用符で閉じない: %s',
    (quoted) => {
      const delimiter = quoted.slice(0, 3);
      const text = `緩和策\n${jvnKey}: banner = ${quoted}${'x'.repeat(430)}${delimiter} に設定してください。`;
      expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
    },
  );

  it('三重引用符の完全な値と後続文が上限内なら保持する', () => {
    const first = `${jvnKey}: banner="""Use "Stop. Don't stop.""" に設定。`;
    const text = `緩和策\n${first}\n${'x'.repeat(430)}`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(first);
  });

  it.each(['t', 'tr', 'rt'])('テンプレート設定値の接頭辞も引用符として扱う: %s', (prefix) => {
    const text = `緩和策\n${jvnKey}: Use ${prefix}'Stop. ${'x'.repeat(430)}' as the setting value.`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it.each(['r', 'E', 'fr'])('設定例の単独の接頭辞付き文字列も途中で切らない: %s', (prefix) => {
    const text = `緩和策\n${jvnKey}: Use ${prefix}'Stop. ${'x'.repeat(430)}' as the setting value.`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it.each(['r', 'rb', 'f', 'fr', 'E', 'N', 'custom'])('接頭辞付きの設定文字列を途中で切らない: %s', (prefix) => {
    const text = `緩和策\n${jvnKey}: banner=${prefix}'Stop. ${'x'.repeat(430)}' に設定し再起動してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it('英文の短縮形や所有格のアポストロフィを設定値の引用符とみなさない', () => {
    const first = `${jvnKey}: Don't disable users' authentication.`;
    const text = `Mitigations\n${first} ${'x'.repeat(430)}`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(first);
  });

  it.each([
    `settings={\n "allowlist": [\n "trusted.example",\n "${'x'.repeat(430)}"\n ]\n}`,
    `limits=[\n 10,\n ${'2'.repeat(430)}\n]`,
  ])('複数行の配列・オブジェクト設定値を途中で切らない: %s', (setting) => {
    const prefix = `${jvnKey}の対策。`;
    const text = `緩和策\n${prefix}\n${setting}\nに設定し再起動してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(prefix);
  });

  it.each([
    'I. ',
    'ii) ',
    '■ ',
    '① ',
    'a) ',
    '— [',
    '● (iv) ',
    '- [x] ',
    '- [X] ',
    '- [ ] ',
    '- [a] ',
    '(IV) [x] ',
    '- [✓] ',
  ])('項目番号や箇条書き記号にかかわらず先頭CVEで対象を選択・区切る: %s', (prefix) => {
    const target = `${prefix}${jvnKey}: 修正版を適用してください。`;
    const other = `${prefix}${otherKey}: ${jvnKey}と異なり、認証を無効化してください。`;
    const before = `緩和策\n${other}\n${target}`;
    const after = `緩和策\n${target}\n${other}`;
    expect(evidencePrompt(jvnKey, [article(before)]).evidence[0]!.sections.remediation).toBe(target);
    expect(evidencePrompt(jvnKey, [article(after)]).evidence[0]!.sections.remediation).toBe(target);
  });

  it('別CVEの項目内の対象CVE参照から対策を選ばない', () => {
    const target = `- ${jvnKey}: 修正版を適用してください。`;
    const text = `緩和策\n- ${otherKey}: ${jvnKey}と異なり、認証機能を無効化してください。\n${target}`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(target);
  });

  it('別CVE項目内の参照しかないときは対象の対策として補完しない', () => {
    const text = `緩和策\n- ${otherKey}: ${jvnKey}と異なり、認証機能を無効化してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it.each(['"', "'", '`'])('設定文字列内の文末や改行で値を途中まで抜粋しない: %s', (quote) => {
    const prefix = `${jvnKey}の対策。`;
    const text = `緩和策\n${prefix}\nbanner=${quote}Stop. \n${'x'.repeat(430)}${quote} に設定して再起動してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(prefix);
  });

  it('エスケープされた引用符を設定文字列の終わりとみなさない', () => {
    const text = `緩和策\n${jvnKey}: banner="Stop\\\". ${'x'.repeat(430)}" に設定して再起動してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it.each([
    [400, '\n'],
    [399, '\r\n'],
    [400, '\r\n'],
  ] as const)('改行を除けば上限内の設定行を残す: %i文字 %j', (length, newline) => {
    const prefix = `${jvnKey} setting=`;
    const body = `${prefix}${'x'.repeat(length - prefix.length)}`;
    const text = `緩和策\n${body}${newline}再起動してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(body);
  });

  it('番号付き見出しと区別できるバージョン行を影響範囲から落とさない', () => {
    const body = `${jvnKey}\n1.0.0\n2.0.0より前`;
    const text = `Affected Products\n${body}\nReferences\n資料。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.affected).toBe(body);
  });

  it('JVN型の離れた影響範囲・被害と共通対策を保存原文から渡す', () => {
    const source = article(jvnArticle);
    const before = structuredClone(source);
    const result = evidencePrompt(jvnKey, [source]).evidence[0]!;

    expect(result.text).not.toContain('ヒープバッファオーバーフロー');
    expect(result.sections.affected).toBe(`${jvnKey} GENESIS64およびICONICS Suite 10.97から10.97.2`);
    expect(result.sections.impact).toBe(
      `${jvnKey}：細工したファイルをインポートすると、\nヒープバッファオーバーフローにより任意のコードを実行される可能性があります。`,
    );
    expect(result.sections.remediation).toBe('開発者が提供する情報を確認し、適切な対策を実施してください。');
    expect(result.scope).toBe('article');
    expect(source).toEqual(before);
    expect(source).toMatchObject({
      affected: null,
      impact: null,
      remediation: null,
      scores: [],
      exploited: false,
      urgent: false,
    });
  });

  it.each(['\n', '\r\n', '\r'])('PHP型の番号付き緩和策から設定値と再起動を同じ連続範囲で渡す: %j', (newline) => {
    const result = evidencePrompt(phpKey, [article(phpArticle.replaceAll('\n', newline), phpKey)]).evidence[0]!;

    expect(result.text).not.toContain('session.upload_progress.enabled=0');
    expect(result.sections.remediation).toBe(phpMitigation.replaceAll('\n', newline));
  });

  it('CVE番号のない共通節より、後の節にある対象CVEを優先する', () => {
    const text = `Mitigations\n共通の案内。\nReferences\n参考。\n4. Workarounds:\n${jvnKey}\n設定を変更してください。\n5. Impact\n被害。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(
      `${jvnKey}\n設定を変更してください。`,
    );
  });

  it.each([
    `${otherKey}のみの対策。`,
    `共通のように見える案内。\n${otherKey}のみの対策。`,
    `${jvnKey}0は別のCVEです。`,
  ])('他CVEだけが記載された節を対象CVEの対策に使わない: %s', (body) => {
    const result = evidencePrompt(jvnKey, [article(`${jvnKey}の概要\n対策\n${body}`)]).evidence[0]!;
    expect(result.sections.remediation).toBeNull();
  });

  it('前方一致する別CVEを飛ばし、対象の箇条書きから次のCVE項目までを選ぶ', () => {
    const text = `影響\n- ${jvnKey}0 別の被害。\n- ${jvnKey}: 対象の被害。\n  続きの説明。\n  - 成立条件。\n- ${otherKey}: 別の被害。\n対策\n共通の案内。`;
    const result = evidencePrompt(jvnKey, [article(text)]).evidence[0]!;
    expect(result.sections.impact).toBe(`- ${jvnKey}: 対象の被害。\n  続きの説明。\n  - 成立条件。`);
  });

  it('本文の抜粋位置も前方一致する別CVEではなく対象の番号で決める', () => {
    const text = `${jvnKey}0の説明。${'背景'.repeat(700)}${jvnKey}の説明。`;
    const result = evidencePrompt(jvnKey, [article(text)]).evidence[0]!;
    expect(result.text).toContain(`${jvnKey}の説明。`);
    expect(result.text).not.toContain(`${jvnKey}0`);
  });

  it('設定値内の疑問符や感嘆符を文末とみなして途中で切らない', () => {
    const first = `${jvnKey}の対策。`;
    const text = `緩和策\n${first} endpoint=https://example.test/${'a'.repeat(330)}?mode=on!token=${'b'.repeat(100)}\n再起動してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(first);
  });

  it('原文に存在する抽出値を優先し、存在しない値は見出しから補う', () => {
    const source = {
      ...article(jvnArticle),
      affected: 'ICONICS Suite 10.97から10.97.2',
      remediation: '存在しない指示',
    };
    const result = evidencePrompt(jvnKey, [source]).evidence[0]!;
    expect(result.sections.affected).toBe('ICONICS Suite 10.97から10.97.2');
    expect(result.sections.remediation).toBe('開発者が提供する情報を確認し、適切な対策を実施してください。');
  });

  it('見出しがなければ従来の本文抜粋とnullを維持する', () => {
    const text = `${'背景'.repeat(200)}${jvnKey}の説明。${'追加説明'.repeat(400)}`;
    const result = evidencePrompt(jvnKey, [article(text)]).evidence[0]!;
    expect(result.text).toBe(text.slice(250, 1250));
    expect(result.sections).toEqual({ affected: null, impact: null, remediation: null });
  });

  it('対象CVEが遅く現れる長い節でも対象行と続く説明を選ぶ', () => {
    const text = `想定される影響\n${otherKey}の説明。\n${'他の説明。\n'.repeat(200)}${jvnKey}の被害。\n成立条件。\n更新履歴\n履歴。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.impact).toBe(`${jvnKey}の被害。\n成立条件。`);
  });

  it.each(['V. 補足資料', '## Further Reading', '3. 補足資料', '３． 補足資料', '（3） 補足資料', 'iv. 補足資料'])(
    '種類不明でも番号付き・Markdownの次の見出しを越えない: %s',
    (nextHeading) => {
      const text = `IV. 緩和策\n${jvnKey}の設定を変更してください。\n${nextHeading}\nこの節の指示を混ぜない。`;
      expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(
        `${jvnKey}の設定を変更してください。`,
      );
    },
  );

  it.each(['2． ', '２． ', '- [', '（2）【'])('別CVEの全角番号・括弧付き項目を越えない: %s', (prefix) => {
    const text = `緩和策\n1． ${jvnKey} の対策。\n${prefix}${otherKey}] の対策として認証を無効にする。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(`1． ${jvnKey} の対策。`);
  });

  it.each(['line', 'sentence'] as const)('400文字の直前の設定値は途中で切らず、直前の%s末で切る', (boundary) => {
    const first = `${jvnKey}の緩和策です。`;
    const prefix = boundary === 'line' ? `${first}\n` : first;
    const long = `${prefix}${'説明'.repeat(175)} session.upload_progress.enabled=0 に設定してください。\n${'補足'.repeat(100)}`;
    const result = evidencePrompt(jvnKey, [article(`緩和策\n${long}`)]).evidence[0]!.sections.remediation;
    expect(result).toBe(first);
  });

  it('400文字内の最後の文末を選び、CVE番号を途中で切らない', () => {
    const first = `${jvnKey}について。`;
    const text = `影響\n${first}${'被害'.repeat(182)} CVE-2026-12345678901234567890 を参照。${'補足'.repeat(50)}`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.impact).toBe(first);
  });

  it('400文字以内に行末・文末がない節は、単語を切断して渡さない', () => {
    const text = `対策\n${jvnKey} ${'x'.repeat(450)}\n再起動してください。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBeNull();
  });

  it('対象CVEが長い同一行の上限外なら、その手前を対象の節として渡さない', () => {
    const text = `影響\n${'補足説明。'.repeat(90)}${jvnKey}の被害。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.impact).toBeNull();
  });

  it('400文字以内の設定値と再起動指示は省かない', () => {
    const first = `${jvnKey}の緩和策。`;
    const setting = 'session.upload_progress.enabled=0に設定し、すべてのワーカーを再起動。';
    const body = `${first}${'補足'.repeat(155)}${setting}`;
    const text = `緩和策\n${body}\n${'追加の説明'.repeat(50)}`;
    expect(body.length).toBeLessThanOrEqual(400);
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections.remediation).toBe(body);
  });

  it('原文からの連続抜粋と各文字数・情報源数の上限を守る', () => {
    const sources = [
      article(jvnArticle),
      article(phpArticle, phpKey),
      article(jvnArticle),
      article(jvnArticle),
      article(jvnArticle),
    ];
    const result = evidencePrompt(jvnKey, sources);
    expect(result.evidence).toHaveLength(4);
    for (const [index, entry] of result.evidence.entries()) {
      expect(entry.text.length).toBeLessThanOrEqual(1000);
      let total = entry.text.length;
      for (const value of Object.values(entry.sections)) {
        expect(value?.length ?? 0).toBeLessThanOrEqual(400);
        if (value) {
          expect(sources[index]!.text).toContain(value);
          total += value.length;
        }
      }
      expect(sources[index]!.text).toContain(entry.text);
      expect(total).toBeLessThanOrEqual(2200);
    }
  });

  it('共通対策の補完だけではarticleの引用帰属検査に合格しない', () => {
    const source = article(jvnArticle);
    const quote = evidencePrompt(jvnKey, [source]).evidence[0]!.sections.remediation!;
    expect(quote).toBeTypeOf('string');
    const validation = validateSummary(
      {
        overview: null,
        impact: null,
        action: { text: '対策を実施してください。', evidence: [{ id: source.evidenceId, quote }] },
        uncertainties: [],
      },
      [source],
      jvnKey,
    );
    expect(validation.valid).toBe(false);
    expect(validation.reasons).toContain('action: ambiguous multi-CVE evidence');
  });

  it.each([
    ['影響を受けるシステム', 'affected'],
    ['影響を受ける製品', 'affected'],
    ['対象製品', 'affected'],
    ['Affected Products', 'affected'],
    ['Affected', 'affected'],
    ['想定される影響', 'impact'],
    ['影響', 'impact'],
    ['Impact', 'impact'],
    ['対策方法', 'remediation'],
    ['対策', 'remediation'],
    ['対処方法', 'remediation'],
    ['緩和策', 'remediation'],
    ['Solutions', 'remediation'],
    ['Mitigations', 'remediation'],
    ['Workarounds', 'remediation'],
  ] as const)('既存の日英見出しと緩和策を扱い、番号付きの次の節を越えない: %s', (label, kind) => {
    const text = `（2） ${label}：\n${jvnKey}の説明。\n3． References\n次の節の説明。`;
    expect(evidencePrompt(jvnKey, [article(text)]).evidence[0]!.sections[kind]).toBe(`${jvnKey}の説明。`);
  });

  it('NVDの単一CVE入力では説明と影響範囲を従来どおり渡す', () => {
    const [item] = parseNvd(
      {
        vulnerabilities: [
          {
            cve: {
              id: jvnKey,
              descriptions: [{ lang: 'en', value: 'Acme allows remote code execution.' }],
              configurations: [{ vulnerable: true }],
            },
          },
        ],
      },
      'nvd',
      0,
    );
    const source = normalizeItem(item!)[0]!.evidence;
    expect(evidencePrompt(jvnKey, [source]).evidence[0]).toEqual({
      id: `nvd:${jvnKey}`,
      scope: 'cve',
      cves: [jvnKey],
      url: source.url,
      text: `${jvnKey}\nAcme allows remote code execution.\nAffected configurations: [{"vulnerable":true}]`,
      sections: { affected: '[{"vulnerable":true}]', impact: 'Acme allows remote code execution.', remediation: null },
    });
  });

  it('KEVの単一CVE入力では製品・影響・対応指示を従来どおり渡す', () => {
    const [item] = parseKev(
      {
        vulnerabilities: [
          {
            cveID: jvnKey,
            vulnerabilityName: 'Acme flaw',
            vendorProject: 'Acme',
            product: 'Server',
            shortDescription: 'Remote execution',
            requiredAction: 'Apply vendor updates',
            dateAdded: '2026-10-26',
          },
        ],
      },
      'kev',
      0,
    );
    const source = normalizeItem(item!)[0]!.evidence;
    expect(evidencePrompt(jvnKey, [source]).evidence[0]).toEqual({
      id: `kev:${jvnKey}`,
      scope: 'cve',
      cves: [jvnKey],
      url: source.url,
      text: `${jvnKey}\nAcme Server\nRemote execution\nApply vendor updates\n`,
      sections: { affected: 'Acme Server', impact: 'Remote execution', remediation: 'Apply vendor updates' },
    });
  });

  it('単一CVEの記事では既存パーサーの抽出値を維持する', () => {
    const parsed = enrichArticle(
      { ...article(''), cves: [jvnKey] },
      `<h2>概要</h2><p>${jvnKey}の説明。</p><h2>影響を受ける製品</h2><p>Acme 1.0</p><h2>想定される影響</h2><p>任意コード実行。</p><h2>対策</h2><p>2.0へ更新。</p>`,
    );
    const source = normalizeItem(parsed)[0]!.evidence;
    const result = evidencePrompt(jvnKey, [source]).evidence[0]!;
    expect(result.scope).toBe('cve');
    expect(result.sections).toEqual({ affected: 'Acme 1.0', impact: '任意コード実行。', remediation: '2.0へ更新。' });
  });
});
