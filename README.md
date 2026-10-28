# Security Bot

JVN・JPCERT/CC・CISA KEV・NVDを収集し、日本語で脆弱性や公的な注意喚起を要約してSNSへ発信するCloudflare
Workersアプリです。D1を処理状態の正本にし、Queuesで収集・記事取得・要約・投稿を分離します。初期対応はWorkers
AIとMisskeyです。

初期状態は **`dryRun: true`、投稿先なし** です。リポジトリをビルドしただけでは投稿しません。

仕様書・補助資料・履歴・一時メモの分類と資料の索引は [`docs/README.md`](docs/README.md) を参照してください。

## 開発と検証

Node.js 22以上を使用します（開発・検証はNode.js 24）。

```sh
pnpm ci
pnpm test
pnpm run typecheck
pnpm run format:check
pnpm run build
pnpm run cli -- config validate
```

`pnpm test`は実際のWorkersランタイムとローカルD1を使う統合テストを含みます。外部情報源・LLM・SNSへのアクセスはテストでは置き換え、SNSへの実送信は行いません。`pnpm run build`もWranglerのdry-runです。

フォーマットにはBiomeを使用します。`pnpm run format`で対応ファイル全体を整形し、`pnpm run format:check`で確認します。設定は`biome.json`で管理し、インデントはスペース2つ、行幅は120文字です。生成物・Gitの無視対象・`package-lock.json`は整形対象から除外します。

## AIエージェント向けの開発環境

作業規約は [`AGENTS.md`](AGENTS.md) にまとめています。外部skillsは、Cloudflare Workers・D1・Queues・Workers
AIを使う現在の構成に合わせ、[Cloudflare公式](https://github.com/cloudflare/skills)から次の3つを選定しています。

| Skill                                                                                | 主な用途                                            | 累計インストール数（2026-10-27調査） |
| ------------------------------------------------------------------------------------ | --------------------------------------------------- | -----------------------------------: |
| [cloudflare](https://skills.sh/cloudflare/skills/cloudflare)                         | D1・Queues・Workers AI・Cronなどの参照資料          |                             約138.7K |
| [workers-best-practices](https://skills.sh/cloudflare/skills/workers-best-practices) | Workersの実装・レビュー、非同期処理、bindingsの扱い |                             約127.1K |
| [wrangler](https://skills.sh/cloudflare/skills/wrangler)                             | 既存Wrangler環境のローカル開発、設定・リソース操作  |                             約130.4K |

Cloudflare公式リポジトリは調査時点で約3.2K starsです。各skillの本文と参照資料の構成を確認したうえで選定しました。
`antfu/skills` のVitest用skillも調査しましたが、現行版はVitest
5.1のベータ版を前提としているため、このプロジェクトのVitest 4.1系には導入していません。フロントエンドやDurable
Objects向けのskillsも、現在の構成では使用しないため対象外です。

Node.js 22以上、pnpm（pnpx）、Git、GitHubとnpmへのネットワーク接続が必要です。

```sh
sh scripts/install-skills.sh
```

スクリプトの場所を基準にリポジトリルートへ移動するため、別のディレクトリから絶対パスで実行することもできます。
導入先はこのリポジトリ内の `.agents/skills/` のみで、グローバル環境やアプリの依存関係は変更しません。
導入したskillsは次のターンから利用できます。

外部skills本体とCLIが生成する `skills-lock.json` は `.gitignore` で除外しています。
自作の [`review-pipeline-consistency`](.agents/skills/review-pipeline-consistency/SKILL.md) はGit管理し、
ジョブ・配信・収集・根拠データの整合性を確認する際に利用します。外部skillsの再インストールでは上書きされません。
コミットする導入定義は [`scripts/install-skills.sh`](scripts/install-skills.sh) です。
再現性のため、Skills CLIは `1.7.4`、Cloudflareの導入元はコミット
[`86505e44f87d801aa1864a3c4109e9a8ae5c409f`](https://github.com/cloudflare/skills/tree/86505e44f87d801aa1864a3c4109e9a8ae5c409f)
に固定しています。更新する際は内容を確認してスクリプトの固定値を変更し、再実行してください。
再実行すると選定した3つのskillsを固定リビジョンの内容で上書きするため、外部skillsへのローカル編集は避けてください。

## セットアップ

以下のリソース作成とデプロイは、運用者がCloudflareアカウントで行います。

```sh
pnpm wrangler login
pnpm wrangler d1 create security-bot
pnpm wrangler queues create security-bot-jobs
```

作成結果のdatabase IDを`wrangler.jsonc`のプレースホルダーと置き換えてください。

```sh
pnpm run db:migrate:local
pnpm run db:migrate:remote
pnpm wrangler secret put ADMIN_TOKEN
pnpm wrangler secret put MISSKEY_TOKEN
# NVDのAPIキーを使う場合
pnpm wrangler secret put NVD_API_KEY
```

### DBスキーマとマイグレーション

スキーマの正本は [`src/db/schema.ts`](src/db/schema.ts) です。通常のDBアクセスにはDrizzle ORMを使い、
配信枠・予算・リースなどの複雑な原子更新にはD1のSQLとbatchを併用します。

スキーマを変更したら、Drizzle Kitで差分SQLを生成し、内容を確認してからWranglerで適用します。
初回セットアップでは生成済みの初期SQLをそのまま適用でき、再生成は不要です。

```sh
# src/db/schema.tsを編集した後
pnpm run db:generate -- --name describe_change
# migrations/の生成SQLをレビューしてからローカルD1へ適用
pnpm run db:migrate:local
pnpm test
# 運用者がリモートD1へ適用する場合
pnpm run db:migrate:remote
```

`migrations/` のSQLと `migrations/meta/` のスナップショット・生成履歴は一緒にGit管理します。
適用履歴はWranglerの `d1_migrations` で管理し、`drizzle-kit migrate` や `push` は併用しません。
統合テストも同じディレクトリのマイグレーション一式をローカルD1に適用します。
生成にCloudflareの認証情報は不要です。操作の根拠は
[Drizzle Kitの生成手順](https://orm.drizzle.team/docs/drizzle-kit-generate)と
[D1のマイグレーション仕様](https://developers.cloudflare.com/d1/reference/migrations/)です（確認日：2026-10-27）。

### 投稿先とSecrets

`ADMIN_TOKEN`は長いランダムな値にします。Misskeyのトークンはボットアカウントの設定から作成し、ノート投稿に必要な`write:notes`権限を与えます。通常版とunsafe版を別アカウントで運用する場合は、別のSecretを登録してください。

`bot.config.jsonc`に投稿先を追加します。全項目の例は[`bot.config.example.jsonc`](bot.config.example.jsonc)です。

```json
{
  "mode": "free",
  "dryRun": true,
  "targets": [
    {
      "id": "main",
      "baseUrl": "https://your-misskey.example",
      "tokenSecret": "MISSKEY_TOKEN",
      "enabled": false,
      "qualityGate": { "enabled": true }
    }
  ]
}
```

設定はJSONC形式で、`//`・`/* ... */`コメントと末尾カンマを使用できます。CLIの`--config path`では従来のJSONも読み込めます。各項目の意味・入力可能な値・省略時の既定値は設定例のコメントを参照してください。

設定ファイルはWorkerへバンドルされます。変更を反映するには再デプロイします。

```sh
pnpm wrangler deploy
```

最初はdry-runのまま動かし、CLIで`preview`状態の投稿本文と検証結果を確認します。実投稿を始める際に`dryRun: false`と対象アカウントの`enabled: true`を設定してデプロイしてください。CLIで停止したアカウントは`resume`も必要です。

ローカル起動には`.dev.vars.example`を`.dev.vars`へコピーして値を設定し、`pnpm run dev`を使用します。Workers
AIの呼び出しはローカル起動でもクラウド側の推論・利用量を伴うため、オフラインでの検証にはテストを使ってください。

## 設定

適用順は、既定値 → モードのプリセット → `bot.config.jsonc` →
対応する環境変数です。Secretsの値は設定ファイルへ書かず、名前だけを参照します。

| モード         | LLM呼び出し/UTC日 | LLM並列数 | 推定Neurons/UTC日 |
| -------------- | ----------------: | --------: | ----------------: |
| `free`（既定） |                20 |         1 |             8,000 |
| `balanced`     |               100 |         2 |            30,000 |
| `performance`  |               500 |         5 |           100,000 |

モードはCloudflareの契約プランやSNS側の制限を変更しません。モデルと品質ゲートも自動変更しません。上限は最大処理量であり、投稿件数の保証ではありません。

`budget.maxCalls`、`budget.concurrency`、`budget.neurons`を個別に上書きできます。キュー送信は通常配送1件を3操作として概算し、`budget.queueOperations`（既定8,000/UTC日）で抑制します。プラットフォーム側の再配送や他アプリの利用量、D1のアカウント合計利用量・保存容量まで保証するものではありません。

LLMは呼び出し前に入力のバイト数と最大出力数から予算を予約し、利用量を取得できれば精算します。不明・中断時は予約額を残します。日次上限では翌UTC日までD1で待機し、処理中の並列数制限では後で再実行します。通常版とunsafe版は要約を共有します。

対応する環境変数は以下です。WorkerではWranglerのvars等、CLIの設定確認ではシェルの環境変数を使います。

| 変数                    | 用途                                |
| ----------------------- | ----------------------------------- |
| `BOT_MODE`              | `free` / `balanced` / `performance` |
| `POLL_INTERVAL_SECONDS` | 全体の収集間隔（整数、60以上）      |
| `DRY_RUN`               | `true` / `false`のみ                |
| `LLM_MODEL`             | Workers AIモデル名                  |
| `LLM_MAX_CALLS`         | LLMの日次呼び出し上限               |
| `LLM_NEURON_BUDGET`     | 推定Neuronsの日次上限               |

既定モデルは`@cf/meta/llama-3.3-70b-instruct-fp8-fast`です。変更時は`llm.inputNeuronsPerMillion`と`llm.outputNeuronsPerMillion`にモデルの料金係数を明示します。`LlmProvider`を実装することで別プロバイダにも拡張できます。

LLMは `llm.provider` に `workers-ai`（省略時）または `fake`、投稿先は `provider` に `misskey`（省略時）または `fake`
を指定できます。Fakeの最小設定例は以下です。

```json
{
  "dryRun": true,
  "llm": { "provider": "fake" },
  "targets": [{ "id": "local", "provider": "fake", "enabled": false }]
}
```

Fake LLMではAIバインディング・モデル指定・料金係数の指定は不要です。Fake投稿先は `StdoutSocialProvider` を使い、
`baseUrl` と `tokenSecret` は不要です。投稿先の文字数・品質ゲートなどの共通設定は引き続き検証します。
Misskeyでは接続先とSecret名を引き続き必須とし、未知のProviderは拒否します。
通常パイプラインも設定に従ってProviderを選びますが、Fake LLMは意味検証を実装せず、品質ゲートを通過しません。
取得から投稿本文までを手軽に確認する用途には下記の単発 `preview` を使います。`preview` は設定に関わらずFake固定です。
Fake投稿先も `dryRun: true` の間は送信処理を行わず、配信を `preview` として記録します。

### 収集・配信

- RSS/KEVは900秒、NVDは7,200秒。`sources[].pollIntervalSeconds`で情報源別に上書きできます。`sources`を指定すると既定リスト全体を置き換えるので、利用する情報源をすべて記載します。
- Cronは毎分です。90秒設定の場合、90秒経過後の最初のCronで取得するため、正確な秒間隔の実行ではありません。
- 通常は3,600秒間隔・日本時間で10件/日。緊急は別枠で10件/日、全投稿間の最低間隔は300秒です。
- 悪用確認・公的な緊急情報を優先し、Criticalだけでは緊急枠にしません。投稿頻度・上限はアカウント別に設定します。
- 初回は直近24時間を対象にし、古い情報の一斉投稿を避けます。未投稿候補はイベントから72時間で期限切れになります。
- KEVの過去項目はカーソル内の基準情報として保持し、初回に全件の要約ジョブを作りません。
- 影響範囲・対策・悪用確認などの重要変更は新しい改訂を作ります。取得時刻やLLMの言い換えだけでは再投稿しません。

RSSの保持件数には上限があるため、長期停止中にフィードから消えた記事の完全な取り戻しは保証しません。NVDはページ取得をD1のカーソルから再開します。

### 正確性とunsafe版

`qualityGate.enabled: true`では概要・影響・対策の根拠が揃った投稿だけを許可します。`false`では同じ収集情報から、不足欄を「未確認」と明記した投稿も許可します。

どちらも原文にない引用・数値・バージョン、出典の矛盾、不正な構造の出力は保留します。LLMには外部操作やSecretsを与えず、取得本文を非信頼データとして渡します。別の呼び出しによる照合も行いますが、生成AIによる正確性の完全保証ではありません。導入時には実際の要約品質を確認してください。

更新投稿の過去参照はSNSアダプタが組み立てます。Misskeyは引用Renoteを使い、対象削除など明確な引用拒否が返ればURL参照へ切り替えます。HTTPタイムアウトや5xxでは、受理された可能性があるためURL形式で再送しません。

## 管理CLI

### ローカルで1件をプレビュー

```sh
pnpm run cli -- preview --source jvn
pnpm run cli -- preview --source jvn --item ITEM_ID --key CVE-2026-1111
```

設定済み情報源を1回収集し、先頭1件（`--item` 指定時はIDが一致する項目）について、記事取得→Fake要約→
根拠検証→投稿プレビューを実行します。RSSは記事本文も取得するため、HTTPリクエストは複数回になる場合があります。
複数CVEを含む記事では正規化後の先頭キーを使用し、`--key` で変更できます。
`--config path` で設定ファイルを指定できます。

`FakeLlmProvider` は本文を引用付きで抜粋し、`StdoutSocialProvider` が投稿本文を含む診断結果をJSONで出力します。
管理API認証・Cloudflare・D1・Queues・SNSトークンは不要で、実SNS投稿や永続状態の更新は行いません。
情報源の取得にはネットワーク接続が必要です。ページ巡回は行わず、KEV・NVDの対象期間は設定の `initialLookbackSeconds`
に従います。対象がなければ非ゼロ終了します。

出力の `mode: "fake"` と `semanticVerification: "not_performed"` が示すとおり、実際のAI要約や意味的な裏付け検証は
未実施です。`validation` は既存の引用・数値・複数CVEの根拠照合の結果で、不合格なら診断結果とともに非ゼロ終了します。
日付・予算・配信間隔など本番の投稿可否は判定せず、文字数上限はstdout用の3000文字です。

### 管理APIの操作

```sh
export SECURITY_BOT_URL=https://security-bot.your-subdomain.workers.dev
export SECURITY_BOT_ADMIN_TOKEN='your-admin-token'

pnpm run cli -- config validate
pnpm run cli -- config show
pnpm run cli -- status
pnpm run cli -- list sources
pnpm run cli -- list jobs --state held
pnpm run cli -- list deliveries --state unknown
pnpm run cli -- list revisions
pnpm exec tsx src/cli.ts list summaries
pnpm run cli -- show jobs JOB_ID
pnpm run cli -- show deliveries DELIVERY_ID
pnpm run cli -- show revisions REVISION_ID
pnpm run cli -- show summaries REVISION_ID
pnpm run cli -- generate-summary REVISION_ID
pnpm run cli -- dry-run REVISION_ID
pnpm run cli -- pause main
pnpm run cli -- resume main
pnpm run cli -- retry-job JOB_ID
```

`list summaries` は保存済み要約を保存日時が新しい順に直近50件返します。
各項目には `revisionId`、`key`（CVE等の脅威キー）、`evidenceHash`、`status: "generated"`、
`summary`（本文・引用根拠）、`validation`（品質検証結果）、`createdAt`（保存日時、Unixミリ秒）が含まれます。
検証不合格の要約も含むため、`validation.valid` を確認してください。
未生成の改訂と、改訂の根拠が更新されてハッシュが一致しなくなった要約は除外します。該当がなければ `[]` を返します。
管理APIでは認証付きの `GET /admin/summaries` で同じ一覧を取得できます。新規の推論・投稿は行いません。

`show revisions REVISION_ID` は収集した記事本文や出典、`show summaries REVISION_ID` は保存済みの構造化要約と
引用根拠・品質検証結果を表示します。不合格の生成結果も確認できます。要約が未生成なら `status: "not_generated"` と
`summary: null` を返し、改訂そのものが存在しない場合は404になります。

`generate-summary REVISION_ID`
は保存済み根拠を使って現在の設定で新しく生成し、要約と引用検証・意味検証の結果を返す診断操作です。
実LLMでは生成に加え、引用検証を通過した場合に意味検証も呼び出すため、最大2回の推論と利用量が発生し、既存の日次予算と並列数制限が適用されます。
Fakeの場合は本文抜粋とFakeを示す不合格結果を返し、実AIによる意味検証は行いません。
`validation.valid`
を確認してください。HTTP成功でも生成品質の合格を意味せず、生成中に根拠が更新された結果も不合格になります。
`--save`を省略すると診断のみで、保存済み要約は上書きしません。返却される`saved`は`false`です。
結果を残す場合は `pnpm exec tsx src/cli.ts generate-summary REVISION_ID > result.json` のように保存できます。

再生成した要約を保存して`list summaries`へ反映する場合は、`--save`を指定します。

```sh
pnpm cli generate-summary REVISION_ID --save
pnpm cli list summaries
```

引用検証と意味検証に合格し、保存時点でも現在改訂と根拠ハッシュが一致する場合だけ新規保存・上書きします。
保存成功時は`saved: true`、不合格・Fake・根拠更新などで保存しなかった場合は`saved: false`となり、以前の保存内容を残します。
`--save`指定時に保存できなければ、診断結果を表示してCLIは終了コード1を返します。
管理APIは`POST /admin/summaries/generate`の本文に`{"id":"REVISION_ID","save":true}`を指定します。
HTTP成功だけでは保存成功を意味しないため、`saved`と`validation`を確認してください。
この操作ではジョブ・配信の状態変更や送信を行わず、保留中の処理も自動再開しません。

`dry-run REVISION_ID` は保存済み要約を各投稿先の形式でプレビューする読み取り操作です。新規収集・推論・送信は行いません。
要約が未生成の場合は先に通常のdry-runパイプラインを動かしてください。一覧は直近50件で、詳細はIDで指定します。

要約生成では各項目の意味と引用条件を明示し、本文の概要・影響・対策の原文抜粋を優先して入力します。
JSON Modeだけで内容の正しさを保証せず、構造と引用・裏付けの検証を併用します。
参考：[Workers AI JSON Mode](https://developers.cloudflare.com/workers-ai/features/json-mode/)・
[Prompting](https://developers.cloudflare.com/workers-ai/features/prompting/)（確認日：2026-10-27）。

### 送信結果不明の復旧

SNSでの投稿とD1への記録は同一トランザクションにできません。送信開始後の応答喪失・記録失敗・処理期限切れは`unknown`とし、対象アカウントの次の投稿も止めます。まずSNS上で実投稿を確認してください。

実際には投稿されていた場合:

```sh
pnpm run cli -- resolve DELIVERY_ID --post-id NOTE_ID --post-url https://your-misskey.example/notes/NOTE_ID
```

未投稿と確認して再送する場合:

```sh
pnpm run cli -- retry-delivery DELIVERY_ID --ack-duplicate-risk
```

429など明確な未受理は待機後に再試行します。認証エラーは投稿先を停止します。トークンを修正して再デプロイした後、対象アカウントを再開し、保留した配信を再処理してください。再送時も現行の根拠・品質ゲート・鮮度を再確認します。

送信失敗時には、構造化ログ`publication_failed`に配信ID・投稿先ID・改訂ID・送信結果の分類・経過時間を残します。
`diagnostics`はD1の配信・送信試行の`error`にもJSON文字列として保存され、`status`や`show deliveries ID`から確認できます。
既存のエラーは従来の文字列のままです。

| 診断項目            | 内容                                                                                                            |
| ------------------- | --------------------------------------------------------------------------------------------------------------- |
| `phase`             | `request`（送信呼び出し）/ `response`（HTTP応答）/ `response_body`（応答解析）/ `recording`（投稿成功のD1記録） |
| `reason`            | `illegal_invocation` / `timeout` / `aborted` / `dns` / `tls` / `connection` / `network` / `unknown`             |
| `exception`・`code` | 許可した例外名と既知の通信エラーコード。実行環境から取得できる場合に記録                                        |
| `status`・`apiCode` | HTTPステータスと既知のMisskeyエラーコード。未知のAPIコードは`unrecognized`                                      |

例外メッセージ・スタック・応答本文・投稿本文・認証情報は診断ログへコピーしません。
分類できない原因は`unknown`として扱い、診断情報だけで送信済み・未送信を断定しません。
送信・応答解析・D1記録の結果が不明な配信は引き続き`unknown`となり、自動再送しません。
過去の`send_result_unknown`には診断情報を遡って追加できないため、修正版を反映した後の失敗から確認できます。

ジョブはキューへ送る前にD1へ保存します。キュー投入失敗・重複配送・24時間の保持期限切れでもCronが未完了ジョブを回収します。繰り返し処理期限が切れたジョブは、CPU上限などを確認できるよう`held`に止めます。

キューへの配送は投稿ジョブを優先し、同じ優先度では実行可能時刻が早い順に行います。
AIの日次呼び出し数またはneuronsが上限に達すると、未生成・意味検証待ちの要約ジョブは配送前に翌UTC日（日本時間9時）までまとめて延期します。
検証済み要約から配信を作る処理は続行し、実行中・直近配送済みのジョブは一括延期の対象から外します。
残予算では個別リクエストの見積もりが収まらない場合も、従来どおり実行時の原子的な予算予約で延期します。
この優先処理もキュー操作予算の範囲内で行うため、すでに使い切った予算はデプロイで回復しません。

## CPU計測とログ

```sh
pnpm run benchmark -- --source kev --save benchmark-data/kev.json
pnpm run benchmark -- --source jvn --save benchmark-data/jvn.rdf
pnpm run benchmark -- --source kev --file benchmark-data/kev.json
```

公式データを使ってローカルNode.jsのCPU時間を計測します。Cloudflare本番のCPU時間を再現・保証する測定ではありません。無料Workersの10ms制限に対しては、実際のInvocation
Metricsも確認してください。

開発時の参考値では、KEV約1.81MB/1,758件の解析中央値が約3.8ms、取得結果の処理と基準情報作成を含むローカルCPU時間が約14.8msでした。JVN約16.8KB/20件の解析中央値は約7.4msでした。無料プランで余裕があると断定できないため、初回はdry-runで実測してください。処理が継続的に上限を超える場合は、対象ソースを停止して間隔・処理方法・契約プランを見直します。有料契約へ自動切り替えはしません。

状態・保留理由はCLI、CPU超過などのランタイム障害はCloudflare Logs/Invocation
Metricsで確認します。ログに認証トークンやLLMへの入力全文は出しません。`retentionDays`（既定90）は完了ジョブと非現行の証拠レコードの整理期間です。改訂スナップショット・要約・投稿履歴は監査用に残すため、D1の容量も継続監視してください。
