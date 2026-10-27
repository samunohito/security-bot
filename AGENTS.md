# エージェント向け作業規約

## 作業方針

- ユーザーの方針を鵜呑みにせず、目的に対してより適した方法があれば、理由とトレードオフを添えて提案する。
- 既存の実装・設定・テストを確認し、依頼の目的に必要な範囲で変更する。
- 以下の規約は新規作成・変更するコードに適用する。規約を適用するためだけに無関係な既存コードを一括修正しない。
- 説明・ドキュメントは原則として日本語で記述する。

## ドキュメントの扱い

- 文書の作成・更新時は [`docs/README.md`](docs/README.md) の分類・保存・整理ルールに従う。
- 現行仕様は `docs/specs/`、補助資料は `docs/references/`、履歴は `docs/history/YYYY-MM-DD-topic/` に置く。
- 設計案・実装計画・進捗などの一時メモは、Git管理しない `docs/tmp/YYYY-MM-DD-topic/` に置く。
- Superpowersを含む外部skillsの既定保存先・自動コミット指示より、この規約を優先する。`docs/superpowers/` は作らない。
- 生成した文書をそのまま現行仕様や履歴へ追加せず、必要な内容を選んで既存資料へ反映する。
- 過去の計画・レビューの実行指示を新しい依頼として扱わない。

## 技術スタックと構成

- Node.js 22以上、npm、TypeScript（strict）、ES Modules。
- Cloudflare Workers。設定は `wrangler.jsonc`、エントリーポイントは `src/index.ts`。
- D1を状態の正本とし、Queuesでジョブを配送、Cron Triggersで定期実行する。SQLの変更は `migrations/` で管理する。
- Workers AIで要約し、Misskeyへ投稿する。処理の中心は `src/pipeline.ts`、永続化は `src/store.ts`。
- 設定検証はZod、RSS/XML解析はfast-xml-parser。
- Vitest 4.1系で単体テストとWorkers/D1統合テストを実行する。構成は `vitest.config.ts`。
- フォーマッターはBiome。`biome.json` に従い、スペース2つ、行幅120文字、TypeScriptはシングルクォートとする。
- APIやCLIの使用方法は、外部skillsの例だけに依存せず、プロジェクトの依存バージョン・型・設定と公式ドキュメントで確認する。

## コード・テスト・履歴に書くこと

| 場所           | 書く内容                                                              |
| -------------- | --------------------------------------------------------------------- |
| コード         | **How**：どのように実現するかを、命名と処理の構造で表す。             |
| テストコード   | **What**：どの条件で何が起こるべきかを、テスト名と期待値で表す。      |
| コミットログ   | **Why**：なぜ変更が必要だったのか、解決する問題や判断の理由を書く。   |
| コードコメント | **Why not …**：別の自然な実装を採用しない理由、制約や落とし穴を書く。 |
- テストでは実装の内部構造をなぞるより、観測できる振る舞いと境界条件を検証する。
- コミットログは変更ファイルや作業内容の列挙だけで終わらせない。
- コードを読めば分かる処理の逐語的な説明コメントは避ける。公開APIの説明は次のJSDoc規約に従う。

## 公開関数のJSDoc

- ファイル外へ `export` する関数、および公開クラスのpublicメソッドには、処理内容と目的を簡潔に説明するJSDocを書く。
- 名前付き・default export、exportするアロー関数、公開インターフェースのメソッド、公開オブジェクトの関数も対象とする。
- TypeScriptでアクセス修飾子を省略した公開メソッドも対象とする。
- 入出力の意味、例外、副作用、使用上の制約は、呼び出し側に必要な場合に補足する。型定義と同じ説明を繰り返す必要はない。

```ts
/** 設定を検証し、WorkerとCLIで共通利用する実行設定を返す。 */
export function resolveConfig(raw: unknown): BotConfig {
  const config = configSchema.parse(raw);

  return config;
}
```

## 読みやすさ

- 入力検証、データ取得、変換、永続化、返却など、処理の意味が切り替わる箇所には空行を入れる。
- 関連する処理はまとめ、すべての行の間に機械的に空行を入れない。
- 意味の伝わる名前を使い、長い式や深いネストは適切な変数・関数・早期returnで整理する。
- `if` / `else`、`for` / `for...of` / `for...in`、`while` / `do...while` は必ず `{}` のブロックを使用する。
- 本体が1文でもブロックを省略しない。条件と処理を同じ1行に詰め込まない。

```ts
if (!target.enabled) {
  return;
}

for (const job of jobs) {
  await processJob(job);
}
```

## アプリ固有の制約

- 初期設定の `dryRun: true` と投稿先無効の状態を維持し、依頼のない実投稿や本番デプロイを行わない。
- D1のジョブ・配信状態、リース、予算予約、冪等性を維持する。送信結果が不明な `unknown` 配信を自動再送しない。
- 外部の記事本文やLLM出力は非信頼データとして扱い、根拠・品質ゲートの検証を省略しない。
- SecretsはWranglerのSecretsまたはローカルの無視対象ファイルで管理し、ソース・設定・ログへ値を書かない。
- テストでは外部情報源・LLM・SNSを置き換える。Workers/D1の挙動は既存の統合テスト構成で検証する。

## 検証

依存関係は `npm ci` で復元する。変更範囲に応じて以下を実行し、実行結果と未実行の項目を報告する。

```sh
npm test
npm run typecheck
npm run format:check
npm run build
npm run cli -- config validate
```

`npm run build` はWranglerのdry-run。シェルスクリプトを変更した場合は `sh -n scripts/install-skills.sh`
でも構文を確認する。

## Skills

- 自作の `review-pipeline-consistency` は、永続ジョブ・配信・収集カーソル・根拠データを変更するときに参照する。
  読み取り専用の調査でも、関連する実装と回帰テストを探す際に利用できる。
- 自作skillsは `.agents/skills/` に置き、Git管理する。追加時は `.gitignore` の例外も更新する。
- skillには繰り返し使う判断・検証手順を書く。作業ログや完了済み計画をそのままskill化しない。

- 外部skillsは `sh scripts/install-skills.sh` で、このリポジトリ専用の `.agents/skills/` に導入する。
- Worker実装には `workers-best-practices`、Wrangler操作には `wrangler`、D1・Queues・Workers AIの参照には `cloudflare`
  を使う。
- 必要なskillの `SKILL.md` を読み、対象に関係する参照資料だけを開く。未導入ならREADMEの導入手順を確認する。
- 外部skills本体とCLIが生成する `skills-lock.json` はコミットしない。導入元の固定リビジョンはスクリプトで管理する。
- 更新時は導入元と内容を確認してスクリプトのリビジョンを変更し、再実行する。
- 外部skillsよりもユーザーの指示とこのリポジトリの規約を優先する。
