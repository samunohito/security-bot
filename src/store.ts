import { and, asc, desc, eq, inArray, lt, lte, ne, or, sql } from 'drizzle-orm';
import { drizzle, type DrizzleD1Database } from 'drizzle-orm/d1';
import * as tables from './db/schema';
import type { Config, SourceConfig, TargetConfig } from './config';
import {
  classify,
  digest,
  materialKey,
  normalizeItem,
  publicationDay,
  snapshot,
  utcDay,
  type Evidence,
  type PublishedPost,
  type SourceItem,
  type Summary,
  type ThreatSnapshot,
  type Validation,
} from './domain';
import type { PreparedPost } from './social/provider';
import type { SourceCursor } from './sources/provider';
import { PublicationStore } from './publication-store';
import { severityLevel, digestWindow } from './publication';

export type Job = typeof tables.jobs.$inferSelect;
export type Revision = Omit<typeof tables.revisions.$inferSelect, 'snapshot'> & { snapshot: ThreatSnapshot };
export type Delivery = typeof tables.deliveries.$inferSelect;

const eventCutoffQuery = "COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key='event_cutoff'),0)";
const eventTimeQuery = (alias: string) =>
  `COALESCE((SELECT CASE WHEN o.nvd_only=1 AND COALESCE(json_extract(${alias}.snapshot,'$.rejected'),0)=0 THEN MAX(COALESCE(o.exploited_at,0),COALESCE(CASE WHEN o.current_level=3 THEN o.critical_at ELSE o.high_at END,0),COALESCE(json_extract(${alias}.snapshot,'$.eventAt'),${alias}.event_at)) END FROM publication_observations o WHERE o.threat_key=${alias}.threat_key),json_extract(${alias}.snapshot,'$.eventAt'),${alias}.event_at)`;

type ListedRows = {
  summaries: {
    revisionId: string;
    key: string;
    evidenceHash: string;
    status: 'generated';
    summary: Summary;
    validation: Validation;
    createdAt: number;
  };
  jobs: Pick<Job, 'id' | 'type' | 'state' | 'available_at' | 'attempts' | 'error' | 'created_at' | 'lease_until'>;
  deliveries: Delivery;
  sources: Pick<
    typeof tables.sources.$inferSelect,
    'id' | 'next_poll_at' | 'active_job' | 'last_success_at' | 'last_error'
  >;
  targets: typeof tables.targets.$inferSelect;
  revisions: Pick<
    Revision,
    'id' | 'threat_key' | 'kind' | 'event_at' | 'priority' | 'urgent' | 'eligible' | 'evidence_hash'
  >;
};

export class Store {
  private orm: DrizzleD1Database<typeof tables>;
  readonly publications: PublicationStore;

  /** D1データベースを使ってジョブ・根拠・配信状態を管理する。 */
  constructor(
    public db: D1Database,
    private config?: Config,
  ) {
    this.orm = drizzle(db, { schema: tables });
    this.publications = new PublicationStore(db, config);
  }

  private statement(sql: string, ...params: unknown[]) {
    return this.db.prepare(sql).bind(...params);
  }

  private skipJobsStatement(id?: string) {
    const payload = "CASE WHEN json_valid(jobs.payload) THEN jobs.payload ELSE '{}' END";

    return this.statement(
      `UPDATE jobs SET state='done',error='skipped_before_cutoff',lease_token=NULL,lease_until=NULL,dispatched_at=NULL,dispatch_token=NULL,dispatch_until=NULL
       WHERE state IN ('pending','deferred','held','failed') ${id === undefined ? '' : 'AND id=?'} AND (
         (type='ingest' AND json_type(${payload},'$.item.modifiedAt') IN ('integer','real')
           AND json_extract(${payload},'$.item.modifiedAt')<${eventCutoffQuery}
           AND (COALESCE(json_extract(${payload},'$.sourceId'),json_extract(${payload},'$.item.sourceId'),'') NOT IN (SELECT value FROM json_each(?))
             OR (${this.publications.enabled ? 1 : 0}=0 AND NOT EXISTS(SELECT 1 FROM settings WHERE key='publication_initialized'))))
         OR (type='analyze' AND EXISTS(SELECT 1 FROM revisions r
           WHERE r.id=json_extract(${payload},'$.revisionId') AND ${eventTimeQuery('r')}<${eventCutoffQuery}))
         OR (type='publish' AND EXISTS(SELECT 1 FROM deliveries d JOIN revisions r ON r.id=d.revision_id
           WHERE d.id=json_extract(${payload},'$.deliveryId') AND COALESCE(d.event_at,${eventTimeQuery('r')})<${eventCutoffQuery}))
         OR (type='publish' AND EXISTS(SELECT 1 FROM deliveries d WHERE d.mode='digest' AND d.id=json_extract(${payload},'$.deliveryId') AND d.event_at<${eventCutoffQuery}))
       )`,
      ...(id === undefined ? [] : [id]),
      JSON.stringify(this.config?.sources.filter((source) => source.kind === 'nvd').map((source) => source.id) ?? []),
    );
  }

  private skipDeliveriesStatement(now: number) {
    return this.statement(
      `UPDATE deliveries SET state='stale',error='skipped_before_cutoff',updated_at=?
       WHERE state IN ('ready','held','preview') AND ((mode='digest' AND event_at<${eventCutoffQuery}) OR EXISTS(
         SELECT 1 FROM revisions r WHERE r.id=deliveries.revision_id AND COALESCE(deliveries.event_at,${eventTimeQuery('r')})<${eventCutoffQuery}
       ))`,
      now,
    );
  }

  /** 初回滞留などを除外する固定境界を返す。未設定時は0。 */
  async eventCutoff(): Promise<number> {
    return (await this.db.prepare(`SELECT ${eventCutoffQuery} AS cutoff`).first<number>('cutoff')) ?? 0;
  }

  /** 固定境界より古い公開・更新日時かを判定する。 */
  async isBeforeCutoff(eventAt: number): Promise<boolean> {
    return eventAt < (await this.eventCutoff());
  }

  /** 固定境界を前進させ、古い未実行ジョブと未送信配信を原子的に対象外にする。 */
  async skipBefore(cutoff: number, now: number) {
    if (!Number.isSafeInteger(cutoff) || cutoff < 0 || cutoff > now) {
      throw new Error('invalid_event_cutoff');
    }

    const rebuildWindows = (await this.publications.isTracking())
      ? [
          this.statement(
            `DELETE FROM digest_windows
      WHERE window_end=? AND target_id IN (SELECT d.target_id FROM deliveries d
        WHERE d.mode='digest' AND d.state IN ('ready','held','preview')
        AND EXISTS(SELECT 1 FROM delivery_items i WHERE i.delivery_id=d.id AND i.event_at<${eventCutoffQuery})
        AND EXISTS(SELECT 1 FROM delivery_items i WHERE i.delivery_id=d.id AND i.event_at>=MAX(${eventCutoffQuery},?)))`,
            digestWindow(now, this.config!.publishing.digestIntervalSeconds).end,
            now - this.config!.freshnessSeconds * 1000,
          ),
        ]
      : [];
    const result = await this.db.batch([
      this.statement(
        "INSERT INTO settings(key,value) VALUES('event_cutoff',?) ON CONFLICT(key) DO UPDATE SET value=CAST(MAX(CAST(settings.value AS INTEGER),CAST(excluded.value AS INTEGER)) AS TEXT)",
        String(cutoff),
      ),
      this.skipJobsStatement(),
      ...rebuildWindows,
      this.skipDeliveriesStatement(now),
    ]);

    return {
      cutoff: await this.eventCutoff(),
      jobsSkipped: result[1]!.meta.changes,
      deliveriesSkipped: result[2 + rebuildWindows.length]!.meta.changes,
    };
  }

  /** 境界保存後に再投入された古い未実行ジョブと未送信配信も対象外にする。 */
  async skipOldWork(now: number) {
    await this.db.batch([this.skipJobsStatement(), this.skipDeliveriesStatement(now)]);
  }

  /** ジョブを冪等に登録し、設定待ちや現行要約の欠落から解析を再開する。 */
  async enqueue(id: string, type: string, payload: unknown, now: number, availableAt = now) {
    await this.orm
      .insert(tables.jobs)
      .values({
        id,
        type,
        payload: JSON.stringify(payload),
        available_at: availableAt,
        created_at: now,
      })
      .onConflictDoUpdate({
        target: tables.jobs.id,
        set: {
          state: 'pending',
          available_at: availableAt,
          dispatched_at: null,
          dispatch_token: null,
          dispatch_until: null,
          lease_until: null,
          lease_token: null,
          attempts: 0,
          error: null,
        },
        setWhere: and(
          eq(tables.jobs.type, 'analyze'),
          or(
            and(eq(tables.jobs.state, 'held'), eq(tables.jobs.error, 'analysis_policy_changed')),
            and(
              eq(tables.jobs.state, 'done'),
              sql`EXISTS(SELECT 1 FROM settings WHERE key='publication_initialized')
              AND EXISTS(SELECT 1 FROM revisions r JOIN threats t ON t.revision_id=r.id
                WHERE r.id=json_extract(${tables.jobs.payload},'$.revisionId')
                AND substr(${tables.jobs.id},1,length('analyze:'||r.id||':'||r.evidence_hash||':'))='analyze:'||r.id||':'||r.evidence_hash||':'
                AND NOT EXISTS(SELECT 1 FROM summaries s WHERE s.revision_id=r.id AND s.evidence_hash=r.evidence_hash))`,
            ),
          ),
        ),
      })
      .run();
  }

  /** 投稿を優先し、同じ優先度では実行可能時刻順にOutboxジョブを取得する。 */
  async outbox(now: number, limit = 20): Promise<Job[]> {
    return this.orm
      .select()
      .from(tables.jobs)
      .where(
        and(
          inArray(tables.jobs.state, ['pending', 'deferred']),
          lte(tables.jobs.available_at, now),
          sql`COALESCE(${tables.jobs.dispatch_until},${tables.jobs.dispatched_at}+${this.dispatchWaitMs()},0)<=${now}`,
        ),
      )
      .orderBy(sql`CASE WHEN ${tables.jobs.type}='publish' THEN 0 ELSE 1 END`, asc(tables.jobs.available_at))
      .limit(limit)
      .all();
  }

  /** 当日のAI予算切れで生成・検証が必要な未配送ジョブを翌UTC日まで延期する。 */
  async deferAiJobs(now: number, budget: Config['budget'], fakeLlm: boolean) {
    if (fakeLlm) {
      return;
    }

    const until = Math.floor(now / 86400000) * 86400000 + 86400000;
    await this.statement(
      `UPDATE jobs SET state='deferred',error='AI_daily_budget_exhausted',available_at=?,dispatched_at=NULL,dispatch_token=NULL,dispatch_until=NULL
       WHERE type='analyze' AND state IN ('pending','deferred') AND available_at<=?
       AND COALESCE(dispatch_until,dispatched_at+?,0)<=?
       AND EXISTS(SELECT 1 FROM budgets WHERE day=? AND (calls>=? OR neurons>=?))
       AND EXISTS(
         SELECT 1 FROM revisions r LEFT JOIN summaries s ON s.revision_id=r.id AND s.evidence_hash=r.evidence_hash
         WHERE r.id=json_extract(CASE WHEN json_valid(jobs.payload) THEN jobs.payload ELSE '{}' END,'$.revisionId')
         AND (s.revision_id IS NULL OR EXISTS(
           SELECT 1 FROM json_each(s.validation,'$.reasons') WHERE value IN ('verification_pending','fake_provider')
         ))
       )`,
      until,
      now,
      this.dispatchWaitMs(),
      now,
      utcDay(now),
      budget.maxCalls,
      budget.neurons,
    ).run();
  }

  private dispatchWaitMs() {
    // 送信開始後の中断では受理時刻が不明なため、保持期間にconsumerの最大実行時間を加える。
    return ((this.config?.queue.messageRetentionSeconds ?? 86400) + 900) * 1000;
  }

  /** 配送権と操作予算を同じトランザクションで確保し、競合した配送では予算を消費しない。 */
  async reserveDispatch(id: string, now: number, limit: number): Promise<string | null> {
    const token = crypto.randomUUID();
    const result = await this.db.batch([
      this.statement('INSERT OR IGNORE INTO budgets(day) VALUES(?)', utcDay(now)),
      this.statement(
        `UPDATE jobs SET dispatch_token=?,dispatch_until=?,dispatched_at=NULL
        WHERE id=? AND state IN ('pending','deferred') AND available_at<=?
        AND COALESCE(dispatch_until,dispatched_at+?,0)<=?
        AND EXISTS(SELECT 1 FROM budgets WHERE day=? AND queue_ops+3<=?) RETURNING dispatch_token`,
        token,
        now + 180000,
        id,
        now,
        this.dispatchWaitMs(),
        now,
        utcDay(now),
        limit,
      ),
      this.statement(
        `UPDATE budgets SET queue_ops=queue_ops+3 WHERE day=?
        AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND dispatch_token=?)`,
        utcDay(now),
        id,
        token,
      ),
    ]);

    return result[1]!.results.length > 0 ? token : null;
  }

  /** 所有中の配送だけ送信開始を許可し、記録中断時もQueueの保持期間まで再投入を抑える。 */
  async beginDispatch(id: string, token: string, now: number): Promise<boolean> {
    const row = await this.statement(
      `UPDATE jobs SET dispatch_until=? WHERE id=? AND dispatch_token=?
      AND dispatch_until>? AND state IN ('pending','deferred') RETURNING id`,
      now + this.dispatchWaitMs(),
      id,
      token,
      now,
    ).first();

    return row !== null;
  }

  /** 同じ配送所有者の送信成功だけを記録し、consumerが進めた状態を上書きしない。 */
  async markDispatched(id: string, now: number, token: string) {
    await this.statement(
      `UPDATE jobs SET dispatched_at=?,dispatch_until=? WHERE id=? AND dispatch_token=?
      AND state IN ('pending','deferred')`,
      now,
      now + this.dispatchWaitMs(),
      id,
      token,
    ).run();
  }

  /** Queueが未受理と明示した配送だけを所有者条件付きで延期し、再試行を可能にする。 */
  async retryDispatch(id: string, token: string, until: number) {
    await this.statement(
      `UPDATE jobs SET dispatch_token=NULL,dispatch_until=NULL,dispatched_at=NULL,available_at=MAX(available_at,?)
       WHERE id=? AND dispatch_token=? AND state IN ('pending','deferred')`,
      until,
      id,
      token,
    ).run();
  }

  /** 実行可能なジョブをリース付きで取得する。 */
  async claimJob(id: string, now: number): Promise<Job | null> {
    await this.skipJobsStatement(id).run();

    return (
      (await this.orm
        .update(tables.jobs)
        .set({
          state: 'running',
          dispatch_token: null,
          dispatch_until: null,
          dispatched_at: null,
          lease_token: crypto.randomUUID(),
          lease_until: now + 180000,
          attempts: sql`${tables.jobs.attempts}+1`,
        })
        .where(
          and(
            eq(tables.jobs.id, id),
            inArray(tables.jobs.state, ['pending', 'deferred']),
            lte(tables.jobs.available_at, now),
          ),
        )
        .returning()
        .get()) ?? null
    );
  }

  /** リース所有者のジョブを完了状態にする。 */
  async finishJob(job: Job) {
    if (!job.lease_token) {
      return;
    }

    await this.orm
      .update(tables.jobs)
      .set({ state: 'done', lease_until: null })
      .where(and(eq(tables.jobs.id, job.id), eq(tables.jobs.lease_token, job.lease_token)))
      .run();
  }

  /** リース所有者のジョブを指定状態へ移し、次回実行時刻を記録する。 */
  async failJob(job: Job, state: 'deferred' | 'held' | 'failed', error: string, when: number) {
    if (!job.lease_token) {
      return;
    }

    await this.orm
      .update(tables.jobs)
      .set({
        state,
        error,
        available_at: when,
        dispatched_at: null,
        dispatch_token: null,
        dispatch_until: null,
        lease_until: null,
      })
      .where(and(eq(tables.jobs.id, job.id), eq(tables.jobs.lease_token, job.lease_token)))
      .run();
  }

  /** 期限切れリースを回復し、送信結果不明の配信は再送せずunknownにする。 */
  async recover(now: number) {
    await this.db.batch([
      this.statement(
        "UPDATE deliveries SET state='unknown',error='sending_lease_expired',updated_at=? WHERE state='sending' AND lease_until<?",
        now,
        now,
      ),
      this.statement(
        "UPDATE jobs SET state=CASE WHEN attempts>=5 THEN 'held' ELSE 'pending' END,error=CASE WHEN attempts>=5 THEN 'resource_limit_or_worker_lease_expired' ELSE error END,dispatched_at=NULL,dispatch_token=NULL,dispatch_until=NULL,lease_until=NULL WHERE state='running' AND lease_until<?",
        now,
      ),
      this.statement(
        "UPDATE sources SET last_error='resource_limit_or_worker_lease_expired' WHERE active_job IN (SELECT id FROM jobs WHERE state='held' AND error='resource_limit_or_worker_lease_expired')",
      ),
    ]);
  }

  /** 有効な情報源を登録し、期限到来分の収集ジョブを作成する。 */
  async syncSources(sources: SourceConfig[], now: number) {
    for (const source of sources.filter((s) => s.enabled)) {
      await this.orm.insert(tables.sources).values({ id: source.id }).onConflictDoNothing().run();
      const row = await this.orm
        .select({
          next_poll_at: tables.sources.next_poll_at,
          active_job: tables.sources.active_job,
        })
        .from(tables.sources)
        .where(eq(tables.sources.id, source.id))
        .get();

      if (!row || row.active_job || row.next_poll_at > now) {
        continue;
      }
      const id = `collect:${source.id}:${row.next_poll_at}`;
      await this.db.batch([
        this.statement(
          "INSERT OR IGNORE INTO jobs(id,type,payload,available_at,created_at) SELECT ?,'collect',?,?,? WHERE EXISTS(SELECT 1 FROM sources WHERE id=? AND active_job IS NULL AND next_poll_at=?)",
          id,
          JSON.stringify({ sourceId: source.id }),
          now,
          now,
          source.id,
          row.next_poll_at,
        ),
        this.statement(
          'UPDATE sources SET active_job=? WHERE id=? AND active_job IS NULL AND next_poll_at=?',
          id,
          source.id,
          row.next_poll_at,
        ),
      ]);
    }
  }

  /** 情報源の保存済み収集カーソルを返す。 */
  async sourceCursor(id: string): Promise<SourceCursor> {
    const row = await this.orm
      .select({ cursor: tables.sources.cursor })
      .from(tables.sources)
      .where(eq(tables.sources.id, id))
      .get();

    return JSON.parse(row?.cursor ?? '{}') as SourceCursor;
  }

  /** カーソル、実行中ジョブ、最終成功時刻を含む情報源状態を返す。 */
  async sourceState(id: string) {
    return (await this.orm.select().from(tables.sources).where(eq(tables.sources.id, id)).get()) ?? null;
  }

  /** 初回起動時刻を一度だけ保存し、保存値を返す。 */
  async bootstrapTime(now: number): Promise<number> {
    await this.orm
      .insert(tables.settings)
      .values({ key: 'started_at', value: String(now) })
      .onConflictDoNothing()
      .run();

    const row = await this.orm
      .select({ value: tables.settings.value })
      .from(tables.settings)
      .where(eq(tables.settings.key, 'started_at'))
      .get();

    return Number(row!.value);
  }

  /** 現在の収集ジョブが所有者である場合にカーソルと継続ジョブを確定する。 */
  async completeSource(
    id: string,
    cursor: SourceCursor,
    next: number,
    now: number,
    continuation: { id: string; payload: unknown } | undefined,
    owner: Pick<Job, 'id' | 'lease_token'>,
  ) {
    const statements = [
      this.statement(
        "UPDATE sources SET cursor=?,next_poll_at=?,last_success_at=?,last_error=NULL,active_job=? WHERE id=? AND active_job=? AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND lease_token=? AND state='running')",
        JSON.stringify(cursor),
        next,
        now,
        continuation?.id ?? null,
        id,
        owner.id,
        owner.id,
        owner.lease_token,
      ),
    ];

    if (continuation) {
      statements.push(
        this.statement(
          "INSERT OR IGNORE INTO jobs(id,type,payload,available_at,created_at) SELECT ?,'collect',?,?,? WHERE EXISTS(SELECT 1 FROM sources WHERE id=? AND active_job=?) AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND lease_token=? AND state='running')",
          continuation.id,
          JSON.stringify(continuation.payload),
          now,
          now,
          id,
          continuation.id,
          owner.id,
          owner.lease_token,
        ),
      );
    }

    await this.db.batch(statements);
  }

  /** 収集エラーを記録し、指定時にのみ次回ポーリングへ解放する。 */
  async sourceError(id: string, error: string, release: boolean, now: number, owner: Pick<Job, 'id' | 'lease_token'>) {
    await this.statement(
      'UPDATE sources SET last_error=?,active_job=CASE WHEN ? THEN NULL ELSE active_job END,next_poll_at=CASE WHEN ? THEN ? ELSE next_poll_at END WHERE id=? AND active_job=? AND EXISTS(SELECT 1 FROM jobs WHERE id=? AND lease_token=?)',
      error,
      release ? 1 : 0,
      release ? 1 : 0,
      now + 3600000,
      id,
      owner.id,
      owner.id,
      owner.lease_token,
    ).run();
  }

  /** 新しい情報源データを取り込み、更新された脅威改訂IDを返す。 */
  async ingest(item: SourceItem, now: number): Promise<string[]> {
    await this.publications.initialize(now);
    const revisions: string[] = [];
    const normalized = normalizeItem(item),
      keys = new Set(normalized.map((r) => r.key)),
      identity = `${item.sourceId}:${item.id}`;

    const version = await digest(JSON.stringify({ ...item, fetchedAt: 0 }));

    await this.db.batch([
      this.statement(
        'INSERT INTO source_versions(id,version_hash,modified_at,fetched_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET version_hash=excluded.version_hash,modified_at=excluded.modified_at,fetched_at=excluded.fetched_at WHERE excluded.modified_at>source_versions.modified_at OR (excluded.modified_at=source_versions.modified_at AND excluded.fetched_at>=source_versions.fetched_at)',
        identity,
        version,
        item.modifiedAt,
        item.fetchedAt,
      ),
      // 新しい情報源版の受け入れと同時に古い根拠ハッシュを変え、保存済み要約や準備済み投稿を無効化する。
      this.statement(
        'UPDATE revisions SET evidence_hash=? WHERE (threat_key IN (SELECT value FROM json_each(?)) OR threat_key IN (SELECT threat_key FROM evidence WHERE id=?)) AND EXISTS(SELECT 1 FROM source_versions WHERE id=? AND version_hash=?)',
        `updating:${version}`,
        JSON.stringify([...keys]),
        identity,
        identity,
        version,
      ),
    ]);

    const ownsVersion = async () =>
      Boolean(
        await this.orm
          .select({ id: tables.sourceVersions.id })
          .from(tables.sourceVersions)
          .where(and(eq(tables.sourceVersions.id, identity), eq(tables.sourceVersions.version_hash, version)))
          .get(),
      );
    if (!(await ownsVersion())) {
      return [];
    }

    const memberships = await this.orm
      .select({ threat_key: tables.evidence.threat_key })
      .from(tables.evidence)
      .where(
        and(
          eq(tables.evidence.id, identity),
          eq(tables.evidence.current, 1),
          lte(tables.evidence.modified_at, item.modifiedAt),
        ),
      )
      .all();
    for (const member of memberships) {
      if (keys.has(member.threat_key)) {
        continue;
      }
      await this.db.batch([
        this.statement(
          'UPDATE evidence SET current=0 WHERE threat_key=? AND id=? AND modified_at<=? AND EXISTS(SELECT 1 FROM source_versions WHERE id=? AND version_hash=?)',
          member.threat_key,
          identity,
          item.modifiedAt,
          identity,
          version,
        ),
        this.statement(
          "UPDATE deliveries SET state='held',error='source_association_removed',updated_at=? WHERE state IN ('ready','preview','held') AND revision_id IN (SELECT id FROM revisions WHERE threat_key=?) AND EXISTS(SELECT 1 FROM source_versions WHERE id=? AND version_hash=?)",
          now,
          member.threat_key,
          identity,
          version,
        ),
      ]);
      if (!(await ownsVersion())) {
        return revisions;
      }

      const changed = await this.refreshThreat(member.threat_key, now);
      if (changed) {
        revisions.push(changed);
      }
    }
    for (const { key, evidence } of normalized) {
      const hash = await digest(JSON.stringify({ ...evidence, fetchedAt: 0 }));
      const existing = await this.orm
        .select({ hash: tables.evidence.hash, modified_at: tables.evidence.modified_at })
        .from(tables.evidence)
        .where(
          and(
            eq(tables.evidence.threat_key, key),
            eq(tables.evidence.id, evidence.evidenceId),
            eq(tables.evidence.current, 1),
          ),
        )
        .get();
      if (existing?.hash !== hash && (!existing || existing.modified_at <= item.modifiedAt)) {
        await this.db.batch([
          this.statement('INSERT OR IGNORE INTO threats(key) VALUES(?)', key),
          this.statement(
            'UPDATE evidence SET current=0 WHERE threat_key=? AND id=? AND modified_at<=? AND EXISTS(SELECT 1 FROM source_versions WHERE id=? AND version_hash=?)',
            key,
            evidence.evidenceId,
            item.modifiedAt,
            identity,
            version,
          ),
          this.statement(
            'INSERT INTO evidence(threat_key,id,hash,source_version,current,modified_at,fetched_at,data) SELECT ?,?,?,?,1,?,?,? WHERE NOT EXISTS(SELECT 1 FROM evidence WHERE threat_key=? AND id=? AND current=1) AND EXISTS(SELECT 1 FROM source_versions WHERE id=? AND version_hash=?) ON CONFLICT(threat_key,id,hash) DO UPDATE SET current=1,fetched_at=excluded.fetched_at,source_version=excluded.source_version',
            key,
            evidence.evidenceId,
            hash,
            version,
            item.modifiedAt,
            item.fetchedAt,
            JSON.stringify(evidence),
            key,
            evidence.evidenceId,
            identity,
            version,
          ),
        ]);
      }
      await this.statement(
        'UPDATE evidence SET source_version=? WHERE threat_key=? AND id=? AND hash=? AND current=1 AND EXISTS(SELECT 1 FROM source_versions WHERE id=? AND version_hash=?)',
        version,
        key,
        identity,
        hash,
        identity,
        version,
      ).run();
      if (!(await ownsVersion())) {
        return revisions;
      }

      const revision = await this.refreshThreat(key, now);
      if (revision) {
        revisions.push(revision);
      }
    }
    return revisions;
  }

  private async refreshThreat(key: string, now: number): Promise<string | null> {
    const trackObservations = await this.publications.isTracking();
    for (let attempt = 0; attempt < 5; attempt++) {
      const old = await this.orm
        .select({
          revision_id: tables.threats.revision_id,
          material: tables.threats.material,
          generation: tables.threats.generation,
          priority: tables.revisions.priority,
          level: sql<number>`COALESCE((SELECT current_level FROM publication_observations WHERE threat_key=${tables.threats.key}),-1)`,
          event_at: sql<number | null>`${sql.raw(eventTimeQuery('revisions'))}`,
        })
        .from(tables.threats)
        .leftJoin(tables.revisions, eq(tables.revisions.id, tables.threats.revision_id))
        .where(eq(tables.threats.key, key))
        .get();
      if (!old) {
        return null;
      }

      const rows = await this.orm
        .select({ data: tables.evidence.data })
        .from(tables.evidence)
        .innerJoin(
          tables.sourceVersions,
          and(
            eq(tables.sourceVersions.id, tables.evidence.id),
            eq(tables.sourceVersions.version_hash, tables.evidence.source_version),
          ),
        )
        .where(and(eq(tables.evidence.threat_key, key), eq(tables.evidence.current, 1)))
        .orderBy(asc(tables.evidence.id))
        .all();

      const current = snapshot(
        key,
        rows.map((r) => JSON.parse(r.data) as Evidence),
      );
      const material = materialKey(current);
      const cutoff = await this.eventCutoff();
      const crossesCutoff = old.event_at !== null && old.event_at < cutoff && current.eventAt >= cutoff;
      const classification = classify(current);
      const nvdPolicy = trackObservations && this.publications.nvdOnly(current);
      const classificationChanged =
        nvdPolicy && (old.priority !== classification.priority || old.level !== severityLevel(current.scores));
      const changed = !old.revision_id || material !== old.material || crossesCutoff || classificationChanged;
      const identity = `${key}:${material}:${current.eventAt}${nvdPolicy ? `:${classification.priority}:${old.generation + 1}` : ''}`;
      const id = changed ? await digest(identity) : old.revision_id!;
      const evidenceHash = await digest(
        JSON.stringify(current.evidence.map((e) => ({ ...e, fetchedAt: 0, modifiedAt: 0 }))),
      );
      const kind = old.revision_id ? (current.rejected ? 'correction' : 'update') : 'new';

      const result = await this.db.batch([
        this.statement(
          `INSERT INTO revisions(id,threat_key,snapshot,evidence_hash,kind,event_at,priority,urgent,eligible,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM threats WHERE key=? AND generation=?) AND ${eventCutoffQuery}=? ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot,evidence_hash=excluded.evidence_hash,priority=excluded.priority,urgent=excluded.urgent,eligible=excluded.eligible`,
          id,
          key,
          JSON.stringify(current),
          evidenceHash,
          kind,
          current.eventAt,
          classification.priority,
          classification.urgent ? 1 : 0,
          classification.eligible || (current.rejected && Boolean(old.revision_id)) ? 1 : 0,
          now,
          key,
          old.generation,
          cutoff,
        ),
        this.statement(
          `UPDATE threats SET revision_id=?,material=?,generation=generation+1 WHERE key=? AND generation=? AND ${eventCutoffQuery}=?`,
          id,
          material,
          key,
          old.generation,
          cutoff,
        ),
        this.statement(
          `UPDATE deliveries SET state='stale',error='superseded',updated_at=? WHERE state IN ('ready','held','preview') AND revision_id IN (SELECT id FROM revisions WHERE threat_key=? AND id<>?) AND EXISTS(SELECT 1 FROM threats WHERE key=? AND revision_id=?) AND ${eventCutoffQuery}=?`,
          now,
          key,
          id,
          key,
          id,
          cutoff,
        ),
        ...(trackObservations
          ? [
              this.publications.observationStatement(
                { id, threat_key: key, snapshot: current, evidence_hash: evidenceHash },
                now,
              ),
            ]
          : []),
      ]);
      if (result[1]?.meta.changes) {
        return id;
      }
    }
    throw new Error('threat_concurrency_retry');
  }

  /** 改訂IDに対応する脅威スナップショットを取得する。 */
  async getRevision(id: string): Promise<Revision | null> {
    const row = await this.orm.select().from(tables.revisions).where(eq(tables.revisions.id, id)).get();

    return row ? { ...row, snapshot: JSON.parse(row.snapshot) as ThreatSnapshot } : null;
  }

  /** 現在有効な改訂を優先度順に取得する。 */
  async currentRevisions(limit = 50, analysisPolicy?: string): Promise<{ id: string; evidence_hash: string }[]> {
    if (this.publications.enabled) {
      const targets = this.config!.targets.filter((target) => target.enabled || this.config!.dryRun).map(
        (target) => target.id,
      );
      return (
        await this.statement(
          `SELECT r.id,r.evidence_hash FROM revisions r JOIN threats t ON t.revision_id=r.id
        LEFT JOIN publication_observations o ON o.threat_key=r.threat_key
        WHERE r.eligible=1 AND r.evidence_hash NOT LIKE 'updating:%' AND (o.nvd_only=0 OR r.urgent=1 OR json_extract(r.snapshot,'$.rejected')=1 OR
          ((CASE WHEN o.current_level=3 THEN o.critical_at ELSE o.high_at END)>=${eventCutoffQuery} AND EXISTS(SELECT 1 FROM json_each(?) target WHERE NOT EXISTS(
            SELECT 1 FROM delivery_items i JOIN deliveries d ON d.id=i.delivery_id WHERE d.target_id=target.value AND i.threat_key=r.threat_key
            AND i.level>=CASE WHEN o.current_level=3 THEN 3 ELSE 2 END AND (d.state IN ('sent','sending','unknown') OR (d.state='ready' AND i.revision_id=r.id AND i.evidence_hash=r.evidence_hash AND EXISTS(SELECT 1 FROM summaries cs WHERE cs.revision_id=r.id AND cs.evidence_hash=r.evidence_hash)))))))
        AND EXISTS(SELECT 1 FROM json_each(?) target WHERE NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.target_id=target.value AND d.revision_id=r.id AND (d.state IN ('sent','sending','unknown') OR (d.state='ready' AND EXISTS(SELECT 1 FROM delivery_items i WHERE i.delivery_id=d.id AND i.evidence_hash=r.evidence_hash) AND EXISTS(SELECT 1 FROM summaries cs WHERE cs.revision_id=r.id AND cs.evidence_hash=r.evidence_hash)))))
        AND (r.priority<>2 OR o.nvd_only<>1 OR NOT EXISTS(SELECT 1 FROM summaries s WHERE s.revision_id=r.id AND s.evidence_hash=r.evidence_hash AND json_extract(s.validation,'$.valid')=1))
        AND (? IS NULL OR NOT EXISTS(SELECT 1 FROM jobs j WHERE j.id='analyze:'||r.id||':'||r.evidence_hash||':'||? AND NOT (j.state='held' AND COALESCE(j.error,'')='analysis_policy_changed') AND NOT (j.state='done' AND NOT EXISTS(SELECT 1 FROM summaries cs WHERE cs.revision_id=r.id AND cs.evidence_hash=r.evidence_hash))))
        ORDER BY r.priority,COALESCE(CASE WHEN o.current_level=3 THEN o.critical_at ELSE o.high_at END,r.event_at),r.id LIMIT ?`,
          JSON.stringify(targets),
          JSON.stringify(targets),
          analysisPolicy ?? null,
          analysisPolicy ?? null,
          limit,
        ).all<{ id: string; evidence_hash: string }>()
      ).results;
    }
    return this.orm
      .select({ id: tables.revisions.id, evidence_hash: tables.revisions.evidence_hash })
      .from(tables.revisions)
      .innerJoin(tables.threats, eq(tables.threats.revision_id, tables.revisions.id))
      .where(
        and(
          eq(tables.revisions.eligible, 1),
          sql`${tables.revisions.evidence_hash} NOT LIKE 'updating:%'`,
          sql`${sql.raw(eventTimeQuery('revisions'))}>=${sql.raw(eventCutoffQuery)}`,
        ),
      )
      .orderBy(asc(tables.revisions.priority), desc(tables.revisions.event_at))
      .limit(limit)
      .all();
  }

  /** 指定改訂が脅威の現在改訂かを判定する。 */
  async isCurrent(id: string) {
    return Boolean(
      await this.orm
        .select({ key: tables.threats.key })
        .from(tables.threats)
        .where(eq(tables.threats.revision_id, id))
        .get(),
    );
  }

  /** 要約と検証結果を改訂の根拠ハッシュにひも付けて保存する。 */
  async saveSummary(revision: Revision, summary: Summary, validation: Validation, now: number) {
    const values = {
      evidence_hash: revision.evidence_hash,
      summary: JSON.stringify(summary),
      validation: JSON.stringify(validation),
      created_at: now,
    };

    await this.orm
      .insert(tables.summaries)
      .values({ revision_id: revision.id, ...values })
      .onConflictDoUpdate({ target: tables.summaries.revision_id, set: values })
      .run();
  }

  /** 検証合格の要約を、根拠ハッシュと現在改訂が保存時点でも一致する場合だけ保存する。 */
  async saveCurrentSummary(
    revision: Revision,
    summary: Summary,
    validation: Validation,
    now: number,
  ): Promise<boolean> {
    if (!validation.valid) {
      return false;
    }

    // 事前の読み取りだけでは、保存直前の収集更新を排除できない。
    const row = await this.statement(
      `INSERT INTO summaries(revision_id,evidence_hash,summary,validation,created_at)
       SELECT r.id,r.evidence_hash,?,?,? FROM revisions r JOIN threats t ON t.revision_id=r.id
       WHERE r.id=? AND r.evidence_hash=?
       ON CONFLICT(revision_id) DO UPDATE SET evidence_hash=excluded.evidence_hash,
         summary=excluded.summary,validation=excluded.validation,created_at=excluded.created_at
       RETURNING revision_id`,
      JSON.stringify(summary),
      JSON.stringify(validation),
      now,
      revision.id,
      revision.evidence_hash,
    ).first<{ revision_id: string }>();

    return row !== null;
  }

  /** 根拠ハッシュが一致する要約と検証結果だけを返す。 */
  async getSummary(revision: Revision): Promise<{ summary: Summary; validation: Validation } | null> {
    const row = await this.orm
      .select({ summary: tables.summaries.summary, validation: tables.summaries.validation })
      .from(tables.summaries)
      .where(
        and(eq(tables.summaries.revision_id, revision.id), eq(tables.summaries.evidence_hash, revision.evidence_hash)),
      )
      .get();

    return row
      ? {
          summary: JSON.parse(row.summary) as Summary,
          validation: JSON.parse(row.validation) as Validation,
        }
      : null;
  }

  /** 投稿先をデータベースへ登録する。 */
  async syncTargets(targets: TargetConfig[]) {
    if (targets.length) {
      const statements = targets.map((target) =>
        this.orm.insert(tables.targets).values({ id: target.id }).onConflictDoNothing(),
      );
      await this.orm.batch([statements[0]!, ...statements.slice(1)]);
    }
  }

  /** 投稿先を停止または再開し、必要なら配信リースの所有者を確認する。 */
  async pauseTarget(
    id: string,
    paused: boolean,
    reason: string | null = null,
    owner?: { deliveryId: string; token: string },
  ) {
    await this.statement(
      "UPDATE targets SET paused=?,reason=? WHERE id=? AND (? IS NULL OR EXISTS(SELECT 1 FROM deliveries WHERE id=? AND target_id=targets.id AND lease_token=? AND state='held'))",
      paused ? 1 : 0,
      reason,
      id,
      owner?.deliveryId ?? null,
      owner?.deliveryId ?? null,
      owner?.token ?? null,
    ).run();
  }

  /** 投稿先と改訂の組に対する配信を作成または再評価する。 */
  async createDelivery(
    id: string,
    target: string,
    revision: string,
    urgent: boolean,
    now: number,
    state = 'ready',
    reason: string | null = null,
    publicationEventAt?: number,
  ) {
    await this.db.batch([
      this.statement(
        `INSERT INTO deliveries(id,target_id,revision_id,state,urgent,available_at,error,created_at,updated_at,event_at)
       SELECT ?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM revisions r WHERE r.id=? AND ${eventTimeQuery('r')}<${eventCutoffQuery})
       ON CONFLICT(target_id,revision_id) DO UPDATE SET
         state=CASE WHEN deliveries.state IN ('held','preview') THEN excluded.state ELSE deliveries.state END,
         error=CASE WHEN deliveries.state IN ('held','preview') THEN excluded.error ELSE deliveries.error END,
         event_at=CASE WHEN deliveries.state IN ('ready','held','preview') THEN excluded.event_at ELSE deliveries.event_at END,
         urgent=CASE WHEN deliveries.state IN ('ready','held','preview') THEN excluded.urgent ELSE deliveries.urgent END`,
        id,
        target,
        revision,
        state,
        urgent ? 1 : 0,
        now,
        reason,
        now,
        now,
        publicationEventAt ?? null,
        revision,
      ),
      this.publications.individualItemStatement(id),
    ]);
  }

  /** 配信状態をIDで取得する。 */
  async getDelivery(id: string): Promise<Delivery | null> {
    return (await this.orm.select().from(tables.deliveries).where(eq(tables.deliveries.id, id)).get()) ?? null;
  }

  /** 未送信配信を無効化し、その所属を後続のまとめで再判定可能にする。 */
  async staleDelivery(id: string, reason: string, now: number) {
    await this.statement(
      "UPDATE deliveries SET state='stale',error=?,updated_at=? WHERE id=? AND state IN ('ready','held','preview')",
      reason,
      now,
      id,
    ).run();
  }

  /** ジョブの詳細をIDで取得し、存在しない場合はnullを返す。 */
  async getJob(id: string): Promise<Job | null> {
    return (await this.orm.select().from(tables.jobs).where(eq(tables.jobs.id, id)).get()) ?? null;
  }

  /** 現在実行可能な配信を取得する。 */
  async dueDeliveries(now: number): Promise<Delivery[]> {
    return this.orm
      .select()
      .from(tables.deliveries)
      .where(
        and(
          eq(tables.deliveries.state, 'ready'),
          lte(tables.deliveries.available_at, now),
          sql`NOT EXISTS(SELECT 1 FROM jobs j WHERE j.type='publish' AND j.state IN ('pending','deferred','running')
          AND json_extract(j.payload,'$.deliveryId')=${tables.deliveries.id})`,
        ),
      )
      .orderBy(desc(tables.deliveries.urgent), asc(tables.deliveries.created_at))
      .limit(50)
      .all();
  }

  /** 投稿間隔・日次枠と既知の送信中リースから、次に予約を試せる時刻を返す。 */
  async nextPublicationAt(
    delivery: Pick<Delivery, 'target_id' | 'urgent'>,
    target: TargetConfig,
    now: number,
  ): Promise<number> {
    const account = await this.orm.select().from(tables.targets).where(eq(tables.targets.id, delivery.target_id)).get();
    const quotas = await this.orm
      .select()
      .from(tables.quotas)
      .where(and(eq(tables.quotas.target_id, delivery.target_id), eq(tables.quotas.day, publicationDay(now))))
      .all();
    const used = (bucket: string) => quotas.find((quota) => quota.bucket === bucket)?.used ?? 0;
    const last = delivery.urgent ? account?.last_urgent_at : account?.last_normal_at;
    const interval = delivery.urgent ? target.urgentIntervalSeconds : target.normalIntervalSeconds;
    const limit = delivery.urgent ? target.urgentDailyLimit : target.normalDailyLimit;
    const midnight = (Math.floor((now + 9 * 3600000) / 86400000) + 1) * 86400000 - 9 * 3600000;
    let next = Math.max(
      now + 60000,
      account?.last_attempt_at == null ? 0 : account.last_attempt_at + target.minimumIntervalSeconds * 1000,
      last == null ? 0 : last + interval * 1000,
      used(delivery.urgent ? 'urgent' : 'normal') >= limit ? midnight : 0,
    );

    if (account?.paused) {
      next = Math.max(next, now + 300000);
    }
    if (account?.active_delivery) {
      const active = await this.getDelivery(account.active_delivery);
      next = Math.max(next, active?.state === 'sending' ? (active.lease_until ?? now + 300000) : now + 300000);
    }
    if (!delivery.urgent && used('urgent') < target.urgentDailyLimit) {
      const urgent = await this.db
        .prepare(
          "SELECT 1 FROM deliveries WHERE target_id=? AND urgent=1 AND state='ready' AND available_at<=? LIMIT 1",
        )
        .bind(delivery.target_id, now)
        .first();
      if (urgent && account?.last_urgent_at != null) {
        next = Math.max(next, account.last_urgent_at + target.urgentIntervalSeconds * 1000);
      }
    }

    return next;
  }

  /** 予約前の配信を延期し、Cronが同じ候補を短周期で再登録しないようにする。 */
  async deferDelivery(id: string, until: number, now: number) {
    await this.statement(
      "UPDATE deliveries SET available_at=MAX(available_at,?),updated_at=? WHERE id=? AND state='ready'",
      until,
      now,
      id,
    ).run();
  }

  /** 同じ脅威について投稿先へ最後に送信した投稿を返す。 */
  async previousPost(target: string, key: string): Promise<PublishedPost | undefined> {
    const row = await this.db
      .prepare(`SELECT d.post_id,d.post_url FROM deliveries d
      LEFT JOIN revisions r ON r.id=d.revision_id
      WHERE d.target_id=? AND d.state='sent' AND (r.threat_key=? OR EXISTS(SELECT 1 FROM delivery_items i WHERE i.delivery_id=d.id AND i.threat_key=?))
      ORDER BY d.updated_at DESC LIMIT 1`)
      .bind(target, key, key)
      .first<{ post_id: string; post_url: string }>();

    return row ? { id: row.post_id!, url: row.post_url! } : undefined;
  }

  /** 送信前の配信を理由付きで保留にする。 */
  async holdDelivery(id: string, reason: string, now: number) {
    await this.orm
      .update(tables.deliveries)
      .set({ state: 'held', error: reason, updated_at: now })
      .where(and(eq(tables.deliveries.id, id), inArray(tables.deliveries.state, ['ready', 'preview', 'held'])))
      .run();
  }

  /** dry-run用の整形済み投稿を配信レコードへ保存する。 */
  async previewDelivery(id: string, prepared: PreparedPost, now: number) {
    await this.orm
      .update(tables.deliveries)
      .set({ state: 'preview', prepared: JSON.stringify(prepared), updated_at: now })
      .where(and(eq(tables.deliveries.id, id), inArray(tables.deliveries.state, ['ready', 'preview'])))
      .run();
  }

  /** 根拠ハッシュが一致する短縮要約と検証結果を取得する。 */
  async getShortened(id: string, hash: string): Promise<{ summary: Summary; validation: Validation } | null> {
    const row = await this.orm
      .select({
        summary: tables.shortenedSummaries.summary,
        validation: tables.shortenedSummaries.validation,
      })
      .from(tables.shortenedSummaries)
      .where(and(eq(tables.shortenedSummaries.delivery_id, id), eq(tables.shortenedSummaries.evidence_hash, hash)))
      .get();

    return row
      ? {
          summary: JSON.parse(row.summary) as Summary,
          validation: JSON.parse(row.validation) as Validation,
        }
      : null;
  }

  /** 短縮要約を根拠ハッシュとともに保存する。 */
  async saveShortened(id: string, hash: string, summary: Summary, validation: Validation) {
    const values = { evidence_hash: hash, summary: JSON.stringify(summary), validation: JSON.stringify(validation) };

    await this.orm
      .insert(tables.shortenedSummaries)
      .values({ delivery_id: id, ...values })
      .onConflictDoUpdate({ target: tables.shortenedSummaries.delivery_id, set: values })
      .run();
  }

  /** 実行中でないジョブを運用者の再試行対象として初期化する。 */
  async retryJob(id: string, now: number) {
    await this.orm
      .update(tables.jobs)
      .set({
        state: 'pending',
        available_at: now,
        dispatched_at: null,
        dispatch_token: null,
        dispatch_until: null,
        lease_until: null,
        attempts: 0,
        error: null,
      })
      .where(and(eq(tables.jobs.id, id), ne(tables.jobs.state, 'running')))
      .run();
  }

  /** 現在版の要約キャッシュが失われた場合に、完了済み解析だけを再開する。 */
  async reopenCompletedAnalysis(id: string, now: number) {
    await this.orm
      .update(tables.jobs)
      .set({
        state: 'pending',
        available_at: now,
        dispatched_at: null,
        dispatch_token: null,
        dispatch_until: null,
        lease_until: null,
        lease_token: null,
        attempts: 0,
        error: null,
      })
      .where(and(eq(tables.jobs.id, id), eq(tables.jobs.type, 'analyze'), eq(tables.jobs.state, 'done')))
      .run();
  }

  /** 現在改訂・投稿先枠・配信リースを原子的に確保する。 */
  async reserveDelivery(
    id: string,
    target: TargetConfig,
    now: number,
    expectedEvidenceHash?: string,
    prepared?: PreparedPost,
  ): Promise<Delivery | null> {
    const token = crypto.randomUUID(),
      day = publicationDay(now);

    await this.db.batch([
      this.statement(
        "INSERT OR IGNORE INTO quotas(target_id,day,bucket) VALUES(?,?,'normal'),(?,?,'urgent')",
        target.id,
        day,
        target.id,
        day,
      ),
      this.statement(
        `UPDATE deliveries SET state='sending',lease_token=?,lease_until=?,reserved_day=?,updated_at=?,prepared=COALESCE(?,prepared) WHERE id=? AND target_id=? AND state='ready' AND available_at<=? AND NOT EXISTS(SELECT 1 FROM revisions cr WHERE cr.id=deliveries.revision_id AND COALESCE(deliveries.event_at,${eventTimeQuery('cr')})<${eventCutoffQuery}) AND (deliveries.mode<>'digest' OR (deliveries.event_at>=${eventCutoffQuery} AND EXISTS(SELECT 1 FROM delivery_items i WHERE i.delivery_id=deliveries.id) AND NOT EXISTS(SELECT 1 FROM delivery_items i LEFT JOIN threats t ON t.key=i.threat_key LEFT JOIN revisions r ON r.id=t.revision_id LEFT JOIN publication_observations o ON o.threat_key=i.threat_key LEFT JOIN summaries s ON s.revision_id=r.id WHERE i.delivery_id=deliveries.id AND (r.id IS NULL OR r.id<>i.revision_id OR r.evidence_hash<>i.evidence_hash OR r.urgent=1 OR json_extract(r.snapshot,'$.rejected')=1 OR COALESCE(o.nvd_only,0)<>1 OR o.high_at IS NULL OR o.high_at<>i.event_at OR s.evidence_hash IS NULL OR s.evidence_hash<>i.evidence_hash OR i.summary_json IS NULL OR s.summary<>i.summary_json OR COALESCE(json_extract(s.validation,'$.valid'),0)<>1 OR (?=1 AND COALESCE(json_extract(s.validation,'$.complete'),0)<>1) OR (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores')) NOT BETWEEN 7 AND 8.999999 OR EXISTS(SELECT 1 FROM delivery_items other JOIN deliveries od ON od.id=other.delivery_id WHERE other.threat_key=i.threat_key AND other.level>=2 AND od.target_id=deliveries.target_id AND od.id<>deliveries.id AND od.state IN ('sent','sending','unknown')))))) AND (? IS NULL OR EXISTS(SELECT 1 FROM revisions r JOIN threats t ON t.revision_id=r.id WHERE r.id=deliveries.revision_id AND r.evidence_hash=?)) AND (urgent=1 OR NOT EXISTS(SELECT 1 FROM deliveries u WHERE u.target_id=deliveries.target_id AND u.urgent=1 AND u.state='ready' AND u.available_at<=? AND EXISTS(SELECT 1 FROM quotas uq WHERE uq.target_id=u.target_id AND uq.day=? AND uq.bucket='urgent' AND uq.used<?))) AND EXISTS(SELECT 1 FROM targets t WHERE t.id=? AND t.paused=0 AND t.active_delivery IS NULL AND (t.last_attempt_at IS NULL OR t.last_attempt_at<=?) AND (CASE WHEN deliveries.urgent=1 THEN t.last_urgent_at ELSE t.last_normal_at END IS NULL OR CASE WHEN deliveries.urgent=1 THEN t.last_urgent_at ELSE t.last_normal_at END<=? - CASE WHEN deliveries.urgent=1 THEN ? ELSE ? END)) AND EXISTS(SELECT 1 FROM quotas q WHERE q.target_id=? AND q.day=? AND q.bucket=CASE WHEN deliveries.urgent=1 THEN 'urgent' ELSE 'normal' END AND q.used<CASE WHEN deliveries.urgent=1 THEN ? ELSE ? END)`,
        token,
        now + 300000,
        day,
        now,
        prepared ? JSON.stringify(prepared) : null,
        id,
        target.id,
        now,
        target.qualityGate.enabled ? 1 : 0,
        expectedEvidenceHash ?? null,
        expectedEvidenceHash ?? null,
        now,
        day,
        target.urgentDailyLimit,
        target.id,
        now - target.minimumIntervalSeconds * 1000,
        now,
        target.urgentIntervalSeconds * 1000,
        target.normalIntervalSeconds * 1000,
        target.id,
        day,
        target.urgentDailyLimit,
        target.normalDailyLimit,
      ),
      this.publications.individualItemStatement(id, token),
      this.statement(
        "UPDATE targets SET active_delivery=?,last_attempt_at=? WHERE id=? AND EXISTS(SELECT 1 FROM deliveries WHERE id=? AND state='sending' AND lease_token=?)",
        id,
        now,
        target.id,
        id,
        token,
      ),
      this.statement(
        "UPDATE quotas SET used=used+1 WHERE target_id=? AND day=? AND bucket=(SELECT CASE WHEN urgent=1 THEN 'urgent' ELSE 'normal' END FROM deliveries WHERE id=?) AND EXISTS(SELECT 1 FROM deliveries WHERE id=? AND state='sending' AND lease_token=?)",
        target.id,
        day,
        id,
        id,
        token,
      ),
      this.statement(
        "INSERT INTO attempts(delivery_id,token,state,at) SELECT ?,?,'sending',? WHERE EXISTS(SELECT 1 FROM deliveries WHERE id=? AND state='sending' AND lease_token=?)",
        id,
        token,
        now,
        id,
        token,
      ),
    ]);

    return (
      (await this.orm
        .select()
        .from(tables.deliveries)
        .where(and(eq(tables.deliveries.id, id), eq(tables.deliveries.lease_token, token)))
        .get()) ?? null
    );
  }

  /** 送信成功を記録し、所有中のリースと試行を完了させる。 */
  async finishDelivery(id: string, post: PublishedPost, now: number, token: string) {
    await this.db.batch([
      this.statement(
        "UPDATE deliveries SET state='sent',post_id=?,post_url=?,updated_at=?,error=NULL WHERE id=? AND lease_token=? AND state IN ('sending','unknown')",
        post.id,
        post.url,
        now,
        id,
        token,
      ),
      this.statement(
        "UPDATE targets SET active_delivery=NULL,last_normal_at=CASE WHEN (SELECT urgent FROM deliveries WHERE id=?)=0 THEN ? ELSE last_normal_at END,last_urgent_at=CASE WHEN (SELECT urgent FROM deliveries WHERE id=?)=1 THEN ? ELSE last_urgent_at END WHERE active_delivery=? AND EXISTS(SELECT 1 FROM deliveries WHERE id=? AND state='sent' AND lease_token=?)",
        id,
        now,
        id,
        now,
        id,
        id,
        token,
      ),
      this.statement(
        "UPDATE attempts SET state='sent' WHERE delivery_id=? AND token=? AND EXISTS(SELECT 1 FROM deliveries WHERE id=? AND lease_token=? AND state='sent')",
        id,
        token,
        id,
        token,
      ),
    ]);
  }

  /** 送信結果と所有トークンに応じて配信を確定、再試行、保留する。 */
  async deliveryError(
    id: string,
    kind: 'unknown' | 'retry' | 'held',
    error: string,
    now: number,
    next: number,
    token: string,
  ) {
    const state = kind === 'retry' ? 'ready' : kind;
    await this.db.batch([
      this.statement(
        "UPDATE quotas SET used=MAX(0,used-1) WHERE ?<>'unknown' AND target_id=(SELECT target_id FROM deliveries WHERE id=? AND state='sending' AND lease_token=?) AND day=(SELECT reserved_day FROM deliveries WHERE id=?) AND bucket=(SELECT CASE WHEN urgent=1 THEN 'urgent' ELSE 'normal' END FROM deliveries WHERE id=?)",
        kind,
        id,
        token,
        id,
        id,
      ),
      this.statement(
        "UPDATE deliveries SET state=?,error=?,available_at=?,updated_at=? WHERE id=? AND lease_token=? AND state='sending'",
        state,
        error,
        next,
        now,
        id,
        token,
      ),
      this.statement(
        "UPDATE targets SET active_delivery=NULL WHERE active_delivery=? AND ?<>'unknown' AND EXISTS(SELECT 1 FROM deliveries WHERE id=? AND lease_token=? AND state IN ('ready','held'))",
        id,
        kind,
        id,
        token,
      ),
      this.statement(
        "UPDATE attempts SET state=?,error=? WHERE delivery_id=? AND token=? AND state='sending' AND EXISTS(SELECT 1 FROM deliveries WHERE id=? AND lease_token=?)",
        state,
        error,
        id,
        token,
        id,
        token,
      ),
    ]);
  }

  /** 運用者がunknown・held・preview配信を明示的に再試行可能にする。 */
  async retryDelivery(id: string, now: number) {
    await this.db.batch([
      this.statement(
        "UPDATE targets SET active_delivery=NULL WHERE active_delivery=? AND EXISTS(SELECT 1 FROM deliveries WHERE id=? AND state IN ('unknown','held','preview'))",
        id,
        id,
      ),
      this.statement(
        "UPDATE deliveries SET state='ready',error=NULL,available_at=?,updated_at=? WHERE id=? AND state IN ('unknown','held','preview')",
        now,
        now,
        id,
      ),
    ]);
  }

  /** AI予算と同時実行枠を予約する。 */
  async reserveBudget(
    id: string,
    now: number,
    amount: number,
    budget: Pick<Config['budget'], 'maxCalls' | 'neurons' | 'concurrency'>,
  ): Promise<boolean> {
    const day = utcDay(now);
    await this.db.batch([
      this.statement('INSERT OR IGNORE INTO budgets(day) VALUES(?)', day),
      this.statement(
        "INSERT OR IGNORE INTO budget_reservations(id,day,amount,lease_until) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM budgets WHERE day=? AND calls<? AND neurons+?<=?) AND (SELECT COUNT(*) FROM budget_reservations WHERE state='reserved' AND lease_until>?)<?",
        id,
        day,
        amount,
        now + 120000,
        day,
        budget.maxCalls,
        amount,
        budget.neurons,
        now,
        budget.concurrency,
      ),
      this.statement(
        'UPDATE budgets SET calls=calls+1,neurons=neurons+? WHERE day=? AND EXISTS(SELECT 1 FROM budget_reservations WHERE id=? AND charged=0)',
        amount,
        day,
        id,
      ),
      this.statement('UPDATE budget_reservations SET charged=1 WHERE id=?', id),
    ]);
    return Boolean(
      await this.orm
        .select({ id: tables.budgetReservations.id })
        .from(tables.budgetReservations)
        .where(eq(tables.budgetReservations.id, id))
        .get(),
    );
  }

  /** AI実使用量で予約予算を精算する。 */
  async settleBudget(id: string, actual: number) {
    if (!Number.isFinite(actual) || actual < 0) {
      throw new Error('invalid_usage');
    }

    await this.db.batch([
      this.statement(
        "UPDATE budgets SET neurons=MAX(0,neurons+?-(SELECT amount FROM budget_reservations WHERE id=?)) WHERE day=(SELECT day FROM budget_reservations WHERE id=? AND state='reserved')",
        actual,
        id,
        id,
      ),
      this.statement("UPDATE budget_reservations SET state='settled' WHERE id=? AND state='reserved'", id),
    ]);
  }

  /** 指定日のAI・キュー使用状況を返す。 */
  async budgetStatus(now: number) {
    return (
      (await this.orm
        .select()
        .from(tables.budgets)
        .where(eq(tables.budgets.day, utcDay(now)))
        .get()) ?? null
    );
  }

  /** 運用画面向けに許可されたテーブルの行を上限付きで取得する。 */
  async list<Table extends keyof ListedRows>(table: Table, limit = 50): Promise<ListedRows[Table][]> {
    return (await this.listRows(table, limit)) as ListedRows[Table][];
  }

  private async listRows(table: keyof ListedRows, limit: number) {
    const rowLimit = Math.min(100, limit);

    switch (table) {
      case 'summaries': {
        const rows = await this.orm
          .select({
            revisionId: tables.summaries.revision_id,
            key: tables.revisions.threat_key,
            evidenceHash: tables.summaries.evidence_hash,
            summary: tables.summaries.summary,
            validation: tables.summaries.validation,
            createdAt: tables.summaries.created_at,
          })
          .from(tables.summaries)
          .innerJoin(
            tables.revisions,
            and(
              eq(tables.summaries.revision_id, tables.revisions.id),
              eq(tables.summaries.evidence_hash, tables.revisions.evidence_hash),
            ),
          )
          .orderBy(desc(tables.summaries.created_at), asc(tables.summaries.revision_id))
          .limit(rowLimit)
          .all();

        return rows.map((row) => ({
          ...row,
          status: 'generated' as const,
          summary: JSON.parse(row.summary) as Summary,
          validation: JSON.parse(row.validation) as Validation,
        }));
      }
      case 'sources':
        return this.orm
          .select({
            id: tables.sources.id,
            next_poll_at: tables.sources.next_poll_at,
            active_job: tables.sources.active_job,
            last_success_at: tables.sources.last_success_at,
            last_error: tables.sources.last_error,
          })
          .from(tables.sources)
          .orderBy(asc(tables.sources.id))
          .limit(rowLimit)
          .all();
      case 'jobs':
        return this.orm
          .select({
            id: tables.jobs.id,
            type: tables.jobs.type,
            state: tables.jobs.state,
            available_at: tables.jobs.available_at,
            attempts: tables.jobs.attempts,
            error: tables.jobs.error,
            created_at: tables.jobs.created_at,
            lease_until: tables.jobs.lease_until,
          })
          .from(tables.jobs)
          .orderBy(desc(tables.jobs.created_at))
          .limit(rowLimit)
          .all();
      case 'revisions':
        return this.orm
          .select({
            id: tables.revisions.id,
            threat_key: tables.revisions.threat_key,
            kind: tables.revisions.kind,
            event_at: tables.revisions.event_at,
            priority: tables.revisions.priority,
            urgent: tables.revisions.urgent,
            eligible: tables.revisions.eligible,
            evidence_hash: tables.revisions.evidence_hash,
          })
          .from(tables.revisions)
          .orderBy(desc(tables.revisions.created_at))
          .limit(rowLimit)
          .all();
      case 'deliveries':
        return this.orm
          .select()
          .from(tables.deliveries)
          .orderBy(desc(tables.deliveries.created_at))
          .limit(rowLimit)
          .all();
      case 'targets':
        return this.orm.select().from(tables.targets).orderBy(asc(tables.targets.id)).limit(rowLimit).all();
    }
  }

  /** 古い非現行根拠と完了ジョブを少量ずつ削除する。 */
  async cleanup(now: number, days: number) {
    const cutoff = now - days * 86400000;
    await this.db.batch([
      this.statement(
        'DELETE FROM evidence WHERE rowid IN (SELECT rowid FROM evidence WHERE current=0 AND fetched_at<? LIMIT 100)',
        cutoff,
      ),
      this.statement(
        "DELETE FROM jobs WHERE id IN (SELECT id FROM jobs WHERE state='done' AND created_at<? LIMIT 100)",
        cutoff,
      ),
    ]);
  }
}
