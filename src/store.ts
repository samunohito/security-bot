import { and, asc, desc, eq, inArray, isNull, lt, lte, ne, or, sql } from 'drizzle-orm';
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
import type { SourceCursor } from './sources';
import type { PreparedPost } from './social';

export type Job = typeof tables.jobs.$inferSelect;
export type Revision = Omit<typeof tables.revisions.$inferSelect, 'snapshot'> & { snapshot: ThreatSnapshot };
export type Delivery = typeof tables.deliveries.$inferSelect;

type ListedRows = {
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

  /** D1データベースを使ってジョブ・根拠・配信状態を管理する。 */
  constructor(public db: D1Database) {
    this.orm = drizzle(db, { schema: tables });
  }

  private statement(sql: string, ...params: unknown[]) {
    return this.db.prepare(sql).bind(...params);
  }

  /** 同一IDのジョブは再登録せず、指定した実行時刻でジョブを登録する。 */
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
      .onConflictDoNothing()
      .run();
  }

  /** 配信待ちのOutboxジョブを実行可能時刻順に取得する。 */
  async outbox(now: number, limit = 20): Promise<Job[]> {
    return this.orm
      .select()
      .from(tables.jobs)
      .where(
        and(
          inArray(tables.jobs.state, ['pending', 'deferred']),
          lte(tables.jobs.available_at, now),
          or(isNull(tables.jobs.dispatched_at), lt(tables.jobs.dispatched_at, now - 120000)),
        ),
      )
      .orderBy(asc(tables.jobs.available_at))
      .limit(limit)
      .all();
  }

  /** 未完了ジョブをキューへ送ったことを記録する。 */
  async markDispatched(id: string, now: number) {
    await this.orm
      .update(tables.jobs)
      .set({ dispatched_at: now })
      .where(and(eq(tables.jobs.id, id), inArray(tables.jobs.state, ['pending', 'deferred'])))
      .run();
  }

  /** 実行可能なジョブをリース付きで取得する。 */
  async claimJob(id: string, now: number): Promise<Job | null> {
    return (
      (await this.orm
        .update(tables.jobs)
        .set({
          state: 'running',
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
        "UPDATE jobs SET state=CASE WHEN attempts>=5 THEN 'held' ELSE 'pending' END,error=CASE WHEN attempts>=5 THEN 'resource_limit_or_worker_lease_expired' ELSE error END,dispatched_at=NULL,lease_until=NULL WHERE state='running' AND lease_until<?",
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
    for (let attempt = 0; attempt < 5; attempt++) {
      const old = await this.orm
        .select({
          revision_id: tables.threats.revision_id,
          material: tables.threats.material,
          generation: tables.threats.generation,
        })
        .from(tables.threats)
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
      const changed = !old.revision_id || material !== old.material;
      const id = changed ? await digest(`${key}:${material}:${current.eventAt}`) : old.revision_id!;
      const evidenceHash = await digest(
        JSON.stringify(current.evidence.map((e) => ({ ...e, fetchedAt: 0, modifiedAt: 0 }))),
      );
      const classification = classify(current);
      const kind = old.revision_id ? (current.rejected ? 'correction' : 'update') : 'new';

      const result = await this.db.batch([
        this.statement(
          'INSERT INTO revisions(id,threat_key,snapshot,evidence_hash,kind,event_at,priority,urgent,eligible,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM threats WHERE key=? AND generation=?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot,evidence_hash=excluded.evidence_hash,priority=excluded.priority,urgent=excluded.urgent,eligible=excluded.eligible',
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
        ),
        this.statement(
          'UPDATE threats SET revision_id=?,material=?,generation=generation+1 WHERE key=? AND generation=?',
          id,
          material,
          key,
          old.generation,
        ),
        this.statement(
          "UPDATE deliveries SET state='stale',error='superseded',updated_at=? WHERE state IN ('ready','held','preview') AND revision_id IN (SELECT id FROM revisions WHERE threat_key=? AND id<>?) AND EXISTS(SELECT 1 FROM threats WHERE key=? AND revision_id=?)",
          now,
          key,
          id,
          key,
          id,
        ),
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
  async currentRevisions(limit = 50): Promise<{ id: string; evidence_hash: string }[]> {
    return this.orm
      .select({ id: tables.revisions.id, evidence_hash: tables.revisions.evidence_hash })
      .from(tables.revisions)
      .innerJoin(tables.threats, eq(tables.threats.revision_id, tables.revisions.id))
      .where(eq(tables.revisions.eligible, 1))
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
  ) {
    await this.orm
      .insert(tables.deliveries)
      .values({
        id,
        target_id: target,
        revision_id: revision,
        state,
        urgent: urgent ? 1 : 0,
        available_at: now,
        error: reason,
        created_at: now,
        updated_at: now,
      })
      .onConflictDoUpdate({
        target: [tables.deliveries.target_id, tables.deliveries.revision_id],
        set: {
          state: sql`CASE WHEN ${tables.deliveries.state} IN ('held','preview') THEN ${state} ELSE ${tables.deliveries.state} END`,
          error: sql`CASE WHEN ${tables.deliveries.state} IN ('held','preview') THEN ${reason} ELSE ${tables.deliveries.error} END`,
        },
      })
      .run();
  }

  /** 配信状態をIDで取得する。 */
  async getDelivery(id: string): Promise<Delivery | null> {
    return (await this.orm.select().from(tables.deliveries).where(eq(tables.deliveries.id, id)).get()) ?? null;
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
      .where(and(eq(tables.deliveries.state, 'ready'), lte(tables.deliveries.available_at, now)))
      .orderBy(desc(tables.deliveries.urgent), asc(tables.deliveries.created_at))
      .limit(50)
      .all();
  }

  /** 同じ脅威について投稿先へ最後に送信した投稿を返す。 */
  async previousPost(target: string, key: string): Promise<PublishedPost | undefined> {
    const row = await this.orm
      .select({ post_id: tables.deliveries.post_id, post_url: tables.deliveries.post_url })
      .from(tables.deliveries)
      .innerJoin(tables.revisions, eq(tables.revisions.id, tables.deliveries.revision_id))
      .where(
        and(
          eq(tables.deliveries.target_id, target),
          eq(tables.revisions.threat_key, key),
          eq(tables.deliveries.state, 'sent'),
        ),
      )
      .orderBy(desc(tables.deliveries.updated_at))
      .limit(1)
      .get();

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
        lease_until: null,
        attempts: 0,
        error: null,
      })
      .where(and(eq(tables.jobs.id, id), ne(tables.jobs.state, 'running')))
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
        `UPDATE deliveries SET state='sending',lease_token=?,lease_until=?,reserved_day=?,updated_at=?,prepared=COALESCE(?,prepared) WHERE id=? AND target_id=? AND state='ready' AND available_at<=? AND (? IS NULL OR EXISTS(SELECT 1 FROM revisions r JOIN threats t ON t.revision_id=r.id WHERE r.id=deliveries.revision_id AND r.evidence_hash=?)) AND (urgent=1 OR NOT EXISTS(SELECT 1 FROM deliveries u WHERE u.target_id=deliveries.target_id AND u.urgent=1 AND u.state='ready' AND u.available_at<=? AND EXISTS(SELECT 1 FROM quotas uq WHERE uq.target_id=u.target_id AND uq.day=? AND uq.bucket='urgent' AND uq.used<?))) AND EXISTS(SELECT 1 FROM targets t WHERE t.id=? AND t.paused=0 AND t.active_delivery IS NULL AND (t.last_attempt_at IS NULL OR t.last_attempt_at<=?) AND (CASE WHEN deliveries.urgent=1 THEN t.last_urgent_at ELSE t.last_normal_at END IS NULL OR CASE WHEN deliveries.urgent=1 THEN t.last_urgent_at ELSE t.last_normal_at END<=? - CASE WHEN deliveries.urgent=1 THEN ? ELSE ? END)) AND EXISTS(SELECT 1 FROM quotas q WHERE q.target_id=? AND q.day=? AND q.bucket=CASE WHEN deliveries.urgent=1 THEN 'urgent' ELSE 'normal' END AND q.used<CASE WHEN deliveries.urgent=1 THEN ? ELSE ? END)`,
        token,
        now + 300000,
        day,
        now,
        prepared ? JSON.stringify(prepared) : null,
        id,
        target.id,
        now,
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

  /** キュー操作予算を予約できたかを返す。 */
  async reserveQueueOperations(now: number, limit: number): Promise<boolean> {
    await this.orm
      .insert(tables.budgets)
      .values({ day: utcDay(now) })
      .onConflictDoNothing()
      .run();
    const row = await this.orm
      .update(tables.budgets)
      .set({ queue_ops: sql`${tables.budgets.queue_ops}+3` })
      .where(and(eq(tables.budgets.day, utcDay(now)), sql`${tables.budgets.queue_ops}+3<=${limit}`))
      .returning({ queue_ops: tables.budgets.queue_ops })
      .get();

    return Boolean(row);
  }

  /** 運用画面向けに許可されたテーブルの行を上限付きで取得する。 */
  async list<Table extends keyof ListedRows>(table: Table, limit = 50): Promise<ListedRows[Table][]> {
    return (await this.listRows(table, limit)) as ListedRows[Table][];
  }

  private async listRows(table: keyof ListedRows, limit: number) {
    const rowLimit = Math.min(100, limit);

    switch (table) {
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
