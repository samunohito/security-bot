// Issue #13の保存例の構造を再現する固定資料。実ページの全文やPoCには依存しない。
export const jvnKey = 'CVE-2023-4863';
export const phpKey = 'CVE-2026-115560';
export const otherKey = 'CVE-2026-9999';

export const jvnArticle = [
  '複数製品の脆弱性',
  '概要',
  `${jvnKey}など複数の脆弱性が報告されました。`,
  '関連する製品と背景の説明。'.repeat(120),
  '影響を受けるシステム',
  `${otherKey} 別製品 3.0`,
  `${jvnKey} GENESIS64およびICONICS Suite 10.97から10.97.2`,
  '想定される影響',
  `${otherKey} 別製品の情報漏えい。`,
  `${jvnKey}について、細工したファイルをインポートすると、`,
  'ヒープバッファオーバーフローにより任意のコードを実行される可能性があります。',
  `${otherKey} 別製品のサービス停止。`,
  '対策',
  '開発者が提供する情報を確認し、適切な対策を実施してください。',
  '参考情報',
  'ここから先は関連文献の案内です。',
].join('\n');

export const phpMitigation = [
  `開発者は、${phpKey}の修正版が提供されるまで以下の設定を推奨しています。`,
  '- session.upload_progress.enabled=0に設定し、すべてのワーカーを再起動する',
  `なお、この設定は${otherKey}の緩和策としても案内されています。`,
].join('\n');

export const phpArticle = [
  'PHPの複数の脆弱性',
  'I. 概要',
  `${phpKey}についての注意喚起。`,
  'II. 対象',
  '対象となる各バージョンの説明。'.repeat(100),
  'III. 対策',
  `${otherKey} 修正版へ更新してください。`,
  'IV. 緩和策',
  `${otherKey}については別の機能を無効にしてください。`,
  phpMitigation,
  `○ ${otherKey}については別の設定が必要です。`,
  'V. 参考情報',
  '参考資料へのリンク。',
].join('\n');
