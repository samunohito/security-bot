# Security Bot

JVN・JPCERT/CC・CISA KEV・NVDを収集し、日本語で脆弱性や公的な注意喚起を要約してSNSへ発信するCloudflare
Workersアプリです。D1を処理状態の正本にし、Queuesで収集・記事取得・要約・投稿を分離します。初期対応はWorkers
AIとMisskeyです。

初期状態は **`dryRun: true`、投稿先なし** です。リポジトリをビルドしただけでは投稿しません。

## 開発と検証

Node.js 22以上を使用します（開発・検証はNode.js 24）。

```sh
npm ci
npm test
npm run typecheck
npm run format:check
npm run build
npm run cli -- config validate
```

`npm test`は実際のWorkersランタイムとローカルD1を使う統合テストを含みます。外部情報源・LLM・SNSへのアクセスはテストでは置き換え、SNSへの実送信は行いません。`npm run build`もWranglerのdry-runです。

フォーマットにはBiomeを使用します。`npm run format`で対応ファイル全体を整形し、`npm run format:check`で確認します。設定は`biome.json`で管理し、インデントはスペース2つ、行幅は120文字です。生成物・Gitの無視対象・`package-lock.json`は整形対象から除外します。

## セットアップ

以下のリソース作成とデプロイは、運用者がCloudflareアカウントで行います。

```sh
npx wrangler login
npx wrangler d1 create security-bot
npx wrangler queues create security-bot-jobs
```

作成結果のdatabase IDを`wrangler.jsonc`のプレースホルダーと置き換えてください。

```sh
npm run db:migrate:local
npm run db:migrate:remote
npx wrangler secret put ADMIN_TOKEN
npx wrangler secret put MISSKEY_TOKEN
# NVDのAPIキーを使う場合
npx wrangler secret put NVD_API_KEY
```

`ADMIN_TOKEN`は長いランダムな値にします。Misskeyのトークンはボットアカウントの設定から作成し、ノート投稿に必要な`write:notes`権限を与えます。通常版とunsafe版を別アカウントで運用する場合は、別のSecretを登録してください。

`bot.config.json`に投稿先を追加します。全項目の例は[`bot.config.example.json`](bot.config.example.json)です。

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

設定ファイルはWorkerへバンドルされます。変更を反映するには再デプロイします。

```sh
npx wrangler deploy
```

最初はdry-runのまま動かし、CLIで`preview`状態の投稿本文と検証結果を確認します。実投稿を始める際に`dryRun: false`と対象アカウントの`enabled: true`を設定してデプロイしてください。CLIで停止したアカウントは`resume`も必要です。

ローカル起動には`.dev.vars.example`を`.dev.vars`へコピーして値を設定し、`npm run dev`を使用します。Workers
AIの呼び出しはローカル起動でもクラウド側の推論・利用量を伴うため、オフラインでの検証にはテストを使ってください。

## 設定

適用順は、既定値 → モードのプリセット → `bot.config.json` →
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

```sh
export SECURITY_BOT_URL=https://security-bot.your-subdomain.workers.dev
export SECURITY_BOT_ADMIN_TOKEN='your-admin-token'

npm run cli -- config validate
npm run cli -- config show
npm run cli -- status
npm run cli -- list sources
npm run cli -- list jobs --state held
npm run cli -- list deliveries --state unknown
npm run cli -- list revisions
npm run cli -- show jobs JOB_ID
npm run cli -- show deliveries DELIVERY_ID
npm run cli -- show revisions REVISION_ID
npm run cli -- dry-run REVISION_ID
npm run cli -- pause main
npm run cli -- resume main
npm run cli -- retry-job JOB_ID
```

`dry-run REVISION_ID`は保存済み要約を各投稿先の形式でプレビューする読み取り操作です。新規収集・推論・送信は行いません。要約が未生成の場合は先に通常のdry-runパイプラインを動かしてください。一覧は直近50件で、詳細はIDで指定します。

### 送信結果不明の復旧

SNSでの投稿とD1への記録は同一トランザクションにできません。送信開始後の応答喪失・記録失敗・処理期限切れは`unknown`とし、対象アカウントの次の投稿も止めます。まずSNS上で実投稿を確認してください。

実際には投稿されていた場合:

```sh
npm run cli -- resolve DELIVERY_ID --post-id NOTE_ID --post-url https://your-misskey.example/notes/NOTE_ID
```

未投稿と確認して再送する場合:

```sh
npm run cli -- retry-delivery DELIVERY_ID --ack-duplicate-risk
```

429など明確な未受理は待機後に再試行します。認証エラーは投稿先を停止します。トークンを修正して再デプロイした後、対象アカウントを再開し、保留した配信を再処理してください。再送時も現行の根拠・品質ゲート・鮮度を再確認します。

ジョブはキューへ送る前にD1へ保存します。キュー投入失敗・重複配送・24時間の保持期限切れでもCronが未完了ジョブを回収します。繰り返し処理期限が切れたジョブは、CPU上限などを確認できるよう`held`に止めます。

## CPU計測とログ

```sh
npm run benchmark -- --source kev --save benchmark-data/kev.json
npm run benchmark -- --source jvn --save benchmark-data/jvn.rdf
npm run benchmark -- --source kev --file benchmark-data/kev.json
```

公式データを使ってローカルNode.jsのCPU時間を計測します。Cloudflare本番のCPU時間を再現・保証する測定ではありません。無料Workersの10ms制限に対しては、実際のInvocation
Metricsも確認してください。

開発時の参考値では、KEV約1.81MB/1,758件の解析中央値が約3.8ms、取得結果の処理と基準情報作成を含むローカルCPU時間が約14.8msでした。JVN約16.8KB/20件の解析中央値は約7.4msでした。無料プランで余裕があると断定できないため、初回はdry-runで実測してください。処理が継続的に上限を超える場合は、対象ソースを停止して間隔・処理方法・契約プランを見直します。有料契約へ自動切り替えはしません。

状態・保留理由はCLI、CPU超過などのランタイム障害はCloudflare Logs/Invocation
Metricsで確認します。ログに認証トークンやLLMへの入力全文は出しません。`retentionDays`（既定90）は完了ジョブと非現行の証拠レコードの整理期間です。改訂スナップショット・要約・投稿履歴は監査用に残すため、D1の容量も継続監視してください。
