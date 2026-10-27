---
name: review-pipeline-consistency
description: Use when changing or reviewing Security Bot's D1-backed jobs, delivery retries, source cursors, or evidence revisions, including stale lease responses, unknown sends, multi-CVE attribution, and interrupted collection.
---

# パイプラインの整合性確認

同じジョブIDや改訂IDでも、処理の所有者や根拠データの内容は変わる。
変更に関係する項目を以下から選び、現在の実装とテストを確認するための参照資料として使う。
単純な文言変更など、永続状態や根拠データに影響しない変更で全項目を監査する必要はない。

## 確認の進め方

- 対象の状態遷移と、ネットワーク呼び出しなどの待機箇所を特定する。
- 読み取り時の確認だけでなく、待機後に実行する更新の条件を読む。成功・失敗・回復・後処理を含める。
- 疑わしい箇所は、イベントの順序と最終状態を具体化し、既存テストの期待値と照合する。
- SQLを共通化する場合も、所有者条件、状態条件、同じbatch内の実行順序を比較する。
- 過去の指摘を現在の不具合として報告しない。現在のコードで成立する再現条件と、実際に確認した範囲を示す。

## 変更対象から確認先を選ぶ

以下のパスはこのskillからの相対リンク。行番号ではなく、記載した関数名とテスト名で探す。

### 配信試行の所有権

- 実装：[Store](../../../src/store.ts) の `reserveDelivery`、`finishDelivery`、`deliveryError`、`pauseTarget` と、
  [Bot](../../../src/pipeline.ts) の `publish`。
- 配信の完了・失敗だけでなく、枠の返却、アカウント占有の解除、認証失敗時の停止にも試行トークンが関係する。
  共通ヘルパーへ移す際に所有者の条件を落とさない。
- [Store統合テスト](../../../tests/store.integration.test.ts) の `fences completion and failure` と、
  [Pipeline統合テスト](../../../tests/pipeline.integration.test.ts) の `does not pause retry B` を確認する。
- 管理操作による明示的な停止・再試行と、自動処理の所有者確認は別の入口である。自動処理の条件を管理操作へ機械的に適用しない。
- 認証失敗時は `deliveryError` で `held` にしてから `pauseTarget` を呼ぶ。停止時点でも `sending`
  を要求すると停止できなくなる。

### 収集の所有権と継続ジョブ

- 実装：Storeの `completeSource`、`sourceError`、`finishJob` と、Botの `collect`。
- ジョブ完了だけを保護しても、先に書かれるカーソルや `active_job` は守れない。
  カーソル更新と継続ジョブ作成の両方に、現在の収集ジョブと所有者の条件があるか読む。
- Store統合テストの `does not let an expired collection owner` を確認する。
- Botの `runJob` は `failJob` の後に `sourceError` を呼ぶ。`completeSource` と違い、
  `sourceError` の所有者条件へ `running` を追加すると、正当なエラー記録も拒否してしまう。

### 公開内容と根拠の鮮度

- 実装：Botの `publish`、`prepare`、Storeの `ingest`、`reserveDelivery`、`saveSummary`、`getSummary`。
- 要約・短縮の待機中に根拠が更新される。同じ改訂IDが残る場合もあるため、ID一致だけでは十分でない。
  送信権を確保する更新で、現在の改訂と期待する `evidence_hash` を照合する箇所を確認する。
- Store統合テストの `atomically rejects prepared content` を確認する。

### 訂正された情報源と古いデータの再到着

- 実装：Storeの `ingest`、`refreshThreat` と、[スキーマ](../../../migrations/0001_initial.sql)の `source_versions`。
- 同じ記事の対象がA・BからBだけに変わるとき、Bの更新だけでなくAとの関連解除も必要。
  古い版の再到着で解除した関連が復活しないか、準備済み配信や根拠の無効化も確認する。
- Store統合テストの `retires source membership` を確認する。削除された対象と古い版の再投入の期待値を読む。

### 記事全体の情報と個別CVEへの帰属

- 実装：[domain](../../../src/domain.ts) の `normalizeItem`、`snapshot`、`classify` と、
  [投稿整形](../../../src/social.ts)の `formatPost`。
- 複数CVEを含む記事全体のスコア・悪用確認を、すべてのCVEの確定情報へコピーしない。
  根拠のscopeだけでなく、最終的な投稿可否・緊急度・見出しまで追う。
- [Domainテスト](../../../tests/domain.test.ts)の `never promotes every CVE` を確認する。

### 中断後の収集再開

- 実装：[sourceProvider](../../../src/sources/index.ts) と `SourceCursor`。
- 初回のlookbackと既存の完了watermarkからの再開を区別する。ページング中の検索窓は固定し、
  未完了の窓を完了済みとして進めない。再開位置を常に「昨日」に切り詰めると停止中の更新を失う。
- [Providerテスト](../../../tests/providers.test.ts)の `keeps a fixed NVD window` と `resumes all NVD updates`
  を確認する。

### 送信結果不明・予算・優先度

- 実装：Storeの `recover`、`deliveryError`、`retryDelivery`、`reserveDelivery`、`reserveBudget` と、
  [MisskeyProvider](../../../src/social.ts)の送信結果の分類。
- 外部SNSでの受理とD1記録は同一トランザクションにならない。タイムアウトや記録失敗を、確実な未送信と混同しない。
  `unknown` と確実な失敗では、再試行・枠返却・アカウント占有の扱いが異なる。
- Store統合テストの `moves expired sending to unknown`、`reserves budgets atomically`、
  `continues the normal quota` を確認する。緊急枠が尽きた場合に通常枠まで止めないことも対象にする。
- Pipeline統合テストの `does not replay a possibly accepted send` と、Providerテストの
  `distinguishes definite rejection` で、アダプタから後続処理までの扱いを確認する。

## 順序を固定する検証例

配信の所有者を変更する修正なら、次の順序をタイマー待ちではなく時刻の引数と制御可能なPromiseで再現する。

1. Aが配信を予約し、応答を待つ。
2. Aの期限が切れ、運用者の明示的な再試行でBが同じ配信IDを予約する。
3. Aの成功応答、失敗応答、認証エラーのいずれかを後から返す。
4. Bの状態・トークン・枠・アカウント占有がAの結果で変わらないことを確認する。

期限切れと所有者の交代は別の条件。まだ同じ試行が所有している `unknown` 配信の遅延成功を、
別の試行に置き換わったAの結果と混同しない。

## 検証範囲

関連するテストファイルだけを既存の構成で実行する。たとえば配信・収集の所有権変更なら次を使う。

```sh
npm test -- tests/store.integration.test.ts tests/pipeline.integration.test.ts
```

テストを読んだことと実行して通ったことを区別する。モックされた外部応答を使うテストから、実SNS・実AI・本番CPU・料金を保証しない。
このskillはデプロイや実投稿を許可するものではない。新しい修正で関数・テスト名が変わった際は、関連する案内も更新する。
