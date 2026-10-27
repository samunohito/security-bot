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
  type PostIntent,
  type PublishedPost,
  type SourceItem,
  type Summary,
  type ThreatSnapshot,
  type Validation,
} from './domain';
import type { SourceCursor } from './sources';
import type { PreparedPost } from './social';

export interface Job {
  id: string;
  type: string;
  payload: string;
  state: string;
  attempts: number;
  lease_token: string;
  available_at: number;
}
export interface Revision {
  id: string;
  threat_key: string;
  snapshot: ThreatSnapshot;
  evidence_hash: string;
  kind: PostIntent['kind'];
  event_at: number;
  priority: number;
  urgent: number;
  eligible: number;
  created_at: number;
}
export interface Delivery {
  id: string;
  target_id: string;
  revision_id: string;
  state: string;
  urgent: number;
  lease_token: string | null;
  post_id: string | null;
  post_url: string | null;
  prepared: string | null;
  error: string | null;
  available_at: number;
}
export class Store {
  constructor(public db: D1Database) {}
  private statement(sql: string, ...params: unknown[]) {
    return this.db.prepare(sql).bind(...params);
  }
  async enqueue(id: string, type: string, payload: unknown, now: number, availableAt = now) {
    await this.statement(
      'INSERT OR IGNORE INTO jobs(id,type,payload,available_at,created_at) VALUES(?,?,?,?,?)',
      id,
      type,
      JSON.stringify(payload),
      availableAt,
      now,
    ).run();
  }
  async outbox(now: number, limit = 20): Promise<Job[]> {
    return (
      await this.statement(
        "SELECT * FROM jobs WHERE state IN ('pending','deferred') AND available_at<=? AND (dispatched_at IS NULL OR dispatched_at<?) ORDER BY available_at LIMIT ?",
        now,
        now - 120000,
        limit,
      ).all<Job>()
    ).results;
  }
  async markDispatched(id: string, now: number) {
    await this.statement(
      "UPDATE jobs SET dispatched_at=? WHERE id=? AND state IN ('pending','deferred')",
      now,
      id,
    ).run();
  }
  async claimJob(id: string, now: number): Promise<Job | null> {
    return this.statement(
      "UPDATE jobs SET state='running',lease_token=?,lease_until=?,attempts=attempts+1 WHERE id=? AND state IN ('pending','deferred') AND available_at<=? RETURNING *",
      crypto.randomUUID(),
      now + 180000,
      id,
      now,
    ).first<Job>();
  }
  async finishJob(job: Job) {
    await this.statement(
      "UPDATE jobs SET state='done',lease_until=NULL WHERE id=? AND lease_token=?",
      job.id,
      job.lease_token,
    ).run();
  }
  async failJob(job: Job, state: 'deferred' | 'held' | 'failed', error: string, when: number) {
    await this.statement(
      'UPDATE jobs SET state=?,error=?,available_at=?,dispatched_at=NULL,lease_until=NULL WHERE id=? AND lease_token=?',
      state,
      error,
      when,
      job.id,
      job.lease_token,
    ).run();
  }
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
  async syncSources(sources: SourceConfig[], now: number) {
    for (const source of sources.filter((s) => s.enabled)) {
      await this.statement('INSERT OR IGNORE INTO sources(id) VALUES(?)', source.id).run();
      const row = await this.statement('SELECT next_poll_at,active_job FROM sources WHERE id=?', source.id).first<{
        next_poll_at: number;
        active_job: string | null;
      }>();
      if (!row || row.active_job || row.next_poll_at > now) continue;
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
  async sourceCursor(id: string): Promise<SourceCursor> {
    const row = await this.statement('SELECT cursor FROM sources WHERE id=?', id).first<{ cursor: string }>();
    return JSON.parse(row?.cursor ?? '{}') as SourceCursor;
  }
  async sourceState(id: string) {
    return this.statement('SELECT * FROM sources WHERE id=?', id).first<{
      cursor: string;
      active_job: string | null;
      last_success_at: number | null;
    }>();
  }
  async bootstrapTime(now: number): Promise<number> {
    await this.statement("INSERT OR IGNORE INTO settings(key,value) VALUES('started_at',?)", String(now)).run();
    return Number(
      (await this.statement("SELECT value FROM settings WHERE key='started_at'").first<{ value: string }>())!.value,
    );
  }
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
    if (continuation)
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
    await this.db.batch(statements);
  }
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
      // Invalidate prepared/verified content atomically with accepting a source version.
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
        await this.statement('SELECT 1 FROM source_versions WHERE id=? AND version_hash=?', identity, version).first(),
      );
    if (!(await ownsVersion())) return [];
    const memberships = (
      await this.statement(
        'SELECT threat_key FROM evidence WHERE id=? AND current=1 AND modified_at<=?',
        identity,
        item.modifiedAt,
      ).all<{ threat_key: string }>()
    ).results;
    for (const member of memberships) {
      if (keys.has(member.threat_key)) continue;
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
      if (!(await ownsVersion())) return revisions;
      const changed = await this.refreshThreat(member.threat_key, now);
      if (changed) revisions.push(changed);
    }
    for (const { key, evidence } of normalized) {
      const hash = await digest(JSON.stringify({ ...evidence, fetchedAt: 0 }));
      const existing = await this.statement(
        'SELECT hash,modified_at FROM evidence WHERE threat_key=? AND id=? AND current=1',
        key,
        evidence.evidenceId,
      ).first<{ hash: string; modified_at: number }>();
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
      if (!(await ownsVersion())) return revisions;
      const revision = await this.refreshThreat(key, now);
      if (revision) revisions.push(revision);
    }
    return revisions;
  }
  private async refreshThreat(key: string, now: number): Promise<string | null> {
    for (let attempt = 0; attempt < 5; attempt++) {
      const old = await this.statement('SELECT revision_id,material,generation FROM threats WHERE key=?', key).first<{
        revision_id: string | null;
        material: string;
        generation: number;
      }>();
      if (!old) return null;
      const rows = (
        await this.statement(
          'SELECT e.data FROM evidence e JOIN source_versions s ON s.id=e.id AND s.version_hash=e.source_version WHERE e.threat_key=? AND e.current=1 ORDER BY e.id',
          key,
        ).all<{ data: string }>()
      ).results;
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
      if (result[1]?.meta.changes) return id;
    }
    throw new Error('threat_concurrency_retry');
  }
  async getRevision(id: string): Promise<Revision | null> {
    const row = await this.statement('SELECT * FROM revisions WHERE id=?', id).first<
      Omit<Revision, 'snapshot'> & { snapshot: string }
    >();
    return row ? { ...row, snapshot: JSON.parse(row.snapshot) as ThreatSnapshot } : null;
  }
  async currentRevisions(limit = 50): Promise<{ id: string; evidence_hash: string }[]> {
    return (
      await this.statement(
        'SELECT r.id,r.evidence_hash FROM revisions r JOIN threats t ON t.revision_id=r.id WHERE r.eligible=1 ORDER BY r.priority,r.event_at DESC LIMIT ?',
        limit,
      ).all<{ id: string; evidence_hash: string }>()
    ).results;
  }
  async isCurrent(id: string) {
    return Boolean(await this.statement('SELECT 1 FROM threats WHERE revision_id=?', id).first());
  }
  async saveSummary(revision: Revision, summary: Summary, validation: Validation, now: number) {
    await this.statement(
      'INSERT INTO summaries(revision_id,evidence_hash,summary,validation,created_at) VALUES(?,?,?,?,?) ON CONFLICT(revision_id) DO UPDATE SET evidence_hash=excluded.evidence_hash,summary=excluded.summary,validation=excluded.validation,created_at=excluded.created_at',
      revision.id,
      revision.evidence_hash,
      JSON.stringify(summary),
      JSON.stringify(validation),
      now,
    ).run();
  }
  async getSummary(revision: Revision): Promise<{ summary: Summary; validation: Validation } | null> {
    const row = await this.statement(
      'SELECT summary,validation FROM summaries WHERE revision_id=? AND evidence_hash=?',
      revision.id,
      revision.evidence_hash,
    ).first<{ summary: string; validation: string }>();
    return row
      ? {
          summary: JSON.parse(row.summary) as Summary,
          validation: JSON.parse(row.validation) as Validation,
        }
      : null;
  }
  async syncTargets(targets: TargetConfig[]) {
    if (targets.length)
      await this.db.batch(targets.map((t) => this.statement('INSERT OR IGNORE INTO targets(id) VALUES(?)', t.id)));
  }
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
  async createDelivery(
    id: string,
    target: string,
    revision: string,
    urgent: boolean,
    now: number,
    state = 'ready',
    reason: string | null = null,
  ) {
    await this.statement(
      "INSERT INTO deliveries(id,target_id,revision_id,state,urgent,available_at,error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(target_id,revision_id) DO UPDATE SET state=CASE WHEN deliveries.state IN ('held','preview') THEN excluded.state ELSE deliveries.state END,error=CASE WHEN deliveries.state IN ('held','preview') THEN excluded.error ELSE deliveries.error END",
      id,
      target,
      revision,
      state,
      urgent ? 1 : 0,
      now,
      reason,
      now,
      now,
    ).run();
  }
  async getDelivery(id: string) {
    return this.statement('SELECT * FROM deliveries WHERE id=?', id).first<Delivery>();
  }
  async dueDeliveries(now: number) {
    return (
      await this.statement(
        "SELECT * FROM deliveries WHERE state='ready' AND available_at<=? ORDER BY urgent DESC,created_at LIMIT 50",
        now,
      ).all<Delivery>()
    ).results;
  }
  async previousPost(target: string, key: string): Promise<PublishedPost | undefined> {
    const row = await this.statement(
      "SELECT d.post_id,d.post_url FROM deliveries d JOIN revisions r ON r.id=d.revision_id WHERE d.target_id=? AND r.threat_key=? AND d.state='sent' ORDER BY d.updated_at DESC LIMIT 1",
      target,
      key,
    ).first<{ post_id: string; post_url: string }>();
    return row ? { id: row.post_id, url: row.post_url } : undefined;
  }
  async holdDelivery(id: string, reason: string, now: number) {
    await this.statement(
      "UPDATE deliveries SET state='held',error=?,updated_at=? WHERE id=? AND state IN ('ready','preview','held')",
      reason,
      now,
      id,
    ).run();
  }
  async previewDelivery(id: string, prepared: PreparedPost, now: number) {
    await this.statement(
      "UPDATE deliveries SET state='preview',prepared=?,updated_at=? WHERE id=? AND state IN ('ready','preview')",
      JSON.stringify(prepared),
      now,
      id,
    ).run();
  }
  async getShortened(id: string, hash: string): Promise<{ summary: Summary; validation: Validation } | null> {
    const row = await this.statement(
      'SELECT summary,validation FROM shortened_summaries WHERE delivery_id=? AND evidence_hash=?',
      id,
      hash,
    ).first<{ summary: string; validation: string }>();
    return row
      ? {
          summary: JSON.parse(row.summary) as Summary,
          validation: JSON.parse(row.validation) as Validation,
        }
      : null;
  }
  async saveShortened(id: string, hash: string, summary: Summary, validation: Validation) {
    await this.statement(
      'INSERT INTO shortened_summaries(delivery_id,evidence_hash,summary,validation) VALUES(?,?,?,?) ON CONFLICT(delivery_id) DO UPDATE SET evidence_hash=excluded.evidence_hash,summary=excluded.summary,validation=excluded.validation',
      id,
      hash,
      JSON.stringify(summary),
      JSON.stringify(validation),
    ).run();
  }
  async retryJob(id: string, now: number) {
    await this.statement(
      "UPDATE jobs SET state='pending',available_at=?,dispatched_at=NULL,lease_until=NULL,attempts=0,error=NULL WHERE id=? AND state<>'running'",
      now,
      id,
    ).run();
  }
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
    return this.statement('SELECT * FROM deliveries WHERE id=? AND lease_token=?', id, token).first<Delivery>();
  }
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
    return Boolean(await this.statement('SELECT 1 FROM budget_reservations WHERE id=?', id).first());
  }
  async settleBudget(id: string, actual: number) {
    if (!Number.isFinite(actual) || actual < 0) throw new Error('invalid_usage');
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
  async budgetStatus(now: number) {
    return this.statement('SELECT * FROM budgets WHERE day=?', utcDay(now)).first<{
      calls: number;
      neurons: number;
      queue_ops: number;
    }>();
  }
  async reserveQueueOperations(now: number, limit: number): Promise<boolean> {
    await this.statement('INSERT OR IGNORE INTO budgets(day) VALUES(?)', utcDay(now)).run();
    const row = await this.statement(
      'UPDATE budgets SET queue_ops=queue_ops+3 WHERE day=? AND queue_ops+3<=? RETURNING queue_ops',
      utcDay(now),
      limit,
    ).first();
    return Boolean(row);
  }
  async list(table: 'jobs' | 'deliveries' | 'sources' | 'targets' | 'revisions', limit = 50) {
    const columns =
      table === 'sources'
        ? 'id,next_poll_at,active_job,last_success_at,last_error'
        : table === 'jobs'
          ? 'id,type,state,available_at,attempts,error,created_at,lease_until'
          : table === 'revisions'
            ? 'id,threat_key,kind,event_at,priority,urgent,eligible,evidence_hash'
            : '*';
    const order = ['jobs', 'deliveries', 'revisions'].includes(table) ? 'created_at DESC' : 'id';
    return (
      await this.statement(`SELECT ${columns} FROM ${table} ORDER BY ${order} LIMIT ?`, Math.min(100, limit)).all()
    ).results;
  }
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
