import type { Config } from './config';
import { classify, digest, type ThreatSnapshot, type Summary } from './domain';
import { publicationRoute, severityLevel, digestWindow } from './publication';
import type { Revision, Delivery } from './store';

export interface PublicationDecision {
  route: 'individual' | 'digest';
  level: number;
  eventAt: number;
  reason: string;
}
export interface DigestMember {
  revision: Revision;
  decision: PublicationDecision;
  summary: Summary;
}

export class PublicationStore {
  /** 根拠の観測と投稿先別の掲載履歴をD1で管理する。 */
  constructor(
    private db: D1Database,
    private config?: Config,
  ) {}

  /** 新方式を明示した設定かを返す。 */
  get enabled(): boolean {
    return this.config?.publishing.mode === 'nvd-high-digest';
  }

  /** まとめ方式の導入後は、方式を切り替えても重大度の観測を継続する。 */
  async isTracking(): Promise<boolean> {
    return (
      this.enabled || !!(await this.db.prepare("SELECT 1 FROM settings WHERE key='publication_initialized'").first())
    );
  }

  /** スコア最大値と情報源のkindから現在の発信方法を判定する。 */
  nvdOnly(snapshot: ThreatSnapshot): boolean {
    return (
      snapshot.evidence.length > 0 &&
      snapshot.evidence.every(
        (entry) => this.config?.sources.find((source) => source.id === entry.sourceId)?.kind === 'nvd',
      )
    );
  }

  /** 導入前の現在状態と成功済み配信を一度だけ観測・掲載の基準に移す。 */
  async initialize(now: number): Promise<void> {
    if (!this.enabled) {
      return;
    }
    const initialized = await this.db.prepare("SELECT value FROM settings WHERE key='publication_initialized'").first();
    if (initialized) {
      return;
    }
    const statements: D1PreparedStatement[] = [
      this.db
        .prepare(`INSERT OR IGNORE INTO publication_observations(threat_key,highest_level,current_level,nvd_only,current_exploited)
      SELECT r.threat_key,
      CASE WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>=9 THEN 3
      WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>=7 THEN 2
      WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>0 THEN 1 ELSE 0 END,
      CASE WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>=9 THEN 3
      WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>=7 THEN 2
      WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>0 THEN 1 ELSE 0 END,
      CASE WHEN json_array_length(r.snapshot,'$.evidence')>0 AND NOT EXISTS(
        SELECT 1 FROM json_each(r.snapshot,'$.evidence') e WHERE NOT EXISTS(
          SELECT 1 FROM json_each(?) s WHERE json_extract(s.value,'$.id')=json_extract(e.value,'$.sourceId') AND json_extract(s.value,'$.kind')='nvd')) THEN 1 ELSE 0 END,COALESCE(json_extract(r.snapshot,'$.exploited'),0)
      FROM revisions r JOIN threats t ON t.revision_id=r.id WHERE NOT EXISTS(SELECT 1 FROM settings WHERE key='publication_initialized')`)
        .bind(JSON.stringify(this.config!.sources)),
    ];
    // 既存の配信待ちは掲載済みにはしない。送信当時の本文がある場合だけ重大度を移す。
    statements.push(
      this.db.prepare(`INSERT OR IGNORE INTO delivery_items(delivery_id,threat_key,revision_id,evidence_hash,level,exploited,event_at)
      SELECT d.id,r.threat_key,r.id,r.evidence_hash,
      CASE WHEN instr(COALESCE(json_extract(d.prepared,'$.text'),''),'[Critical]')>0 THEN 3 WHEN instr(COALESCE(json_extract(d.prepared,'$.text'),''),'[High]')>0 THEN 2 ELSE 0 END,
      COALESCE(json_extract(r.snapshot,'$.exploited'),0),COALESCE(d.event_at,r.event_at)
      FROM deliveries d JOIN revisions r ON r.id=d.revision_id WHERE d.state IN ('sent','sending','unknown') AND NOT EXISTS(SELECT 1 FROM settings WHERE key='publication_initialized')`),
    );
    statements.push(
      this.db
        .prepare("INSERT OR IGNORE INTO settings(key,value) VALUES('publication_initialized',?)")
        .bind(String(now)),
    );
    await this.db.batch(statements);
  }

  /** 現在版を所有する更新に付随する重大度観測SQLを作る。 */
  observationStatement(
    revision: Pick<Revision, 'id' | 'threat_key' | 'snapshot' | 'evidence_hash'>,
    now: number,
  ): D1PreparedStatement {
    const level = severityLevel(revision.snapshot.scores);
    const published = Math.max(0, ...revision.snapshot.evidence.map((entry) => entry.publishedAt));
    const isNew = published >= now - (this.config?.initialLookbackSeconds ?? 86400) * 1000 && published <= now;
    return this.db
      .prepare(`INSERT INTO publication_observations(threat_key,highest_level,current_level,high_at,critical_at,high_reason,nvd_only,current_exploited,exploited_at)
      SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM threats t JOIN revisions r ON r.id=t.revision_id WHERE t.key=? AND r.id=? AND r.evidence_hash=?)
      ON CONFLICT(threat_key) DO UPDATE SET
      exploited_at=CASE WHEN publication_observations.current_exploited=0 AND excluded.current_exploited=1 THEN ? ELSE publication_observations.exploited_at END,
      current_exploited=excluded.current_exploited,
      high_at=CASE WHEN publication_observations.current_level<2 AND excluded.current_level>=2 THEN ? ELSE publication_observations.high_at END,
      critical_at=CASE WHEN publication_observations.current_level<3 AND excluded.current_level>=3 THEN ? ELSE publication_observations.critical_at END,
      high_reason=CASE WHEN publication_observations.current_level<2 AND excluded.current_level>=2 THEN CASE WHEN publication_observations.current_level=0 THEN '初評価' ELSE 'High昇格' END ELSE publication_observations.high_reason END,
      highest_level=MAX(publication_observations.highest_level,excluded.highest_level),current_level=excluded.current_level,nvd_only=excluded.nvd_only`)
      .bind(
        revision.threat_key,
        level,
        level,
        isNew && level >= 2 ? now : null,
        isNew && level >= 3 ? now : null,
        isNew && level >= 2 ? '新規' : null,
        this.nvdOnly(revision.snapshot) ? 1 : 0,
        revision.snapshot.exploited ? 1 : 0,
        revision.snapshot.exploited ? now : null,
        revision.threat_key,
        revision.id,
        revision.evidence_hash,
        now,
        now,
        now,
      );
  }

  /** 掲載済み・結果不明の通知を除き、投稿先に必要な掲載理由を返す。 */
  async decision(revision: Revision, target: string, includeInFlight = true): Promise<PublicationDecision | null> {
    const level = severityLevel(revision.snapshot.scores);
    const classification = classify(revision.snapshot);
    const base = { route: 'individual' as const, level, eventAt: revision.snapshot.eventAt, reason: revision.kind };
    if (!this.enabled) {
      const covered = await this.db
        .prepare(`SELECT 1 FROM delivery_items i JOIN deliveries d ON d.id=i.delivery_id
        WHERE i.revision_id=? AND d.target_id=? AND d.mode='digest'
        AND (d.state='sent' OR (?=1 AND d.state IN ('sending','unknown'))) LIMIT 1`)
        .bind(revision.id, target, includeInFlight ? 1 : 0)
        .first();
      return covered ? null : base;
    }
    if (!this.nvdOnly(revision.snapshot)) {
      return base;
    }
    const history = await this.db
      .prepare(`SELECT COALESCE(MAX(i.level),0) AS level,COALESCE(MAX(i.exploited),0) AS exploited
      FROM delivery_items i JOIN deliveries d ON d.id=i.delivery_id
      WHERE i.threat_key=? AND d.target_id=? AND (d.state='sent' OR (?=1 AND d.state IN ('sending','unknown')))`)
      .bind(revision.threat_key, target, includeInFlight ? 1 : 0)
      .first<{ level: number; exploited: number }>();
    if (revision.snapshot.rejected) {
      return base;
    }
    const observation = await this.db
      .prepare('SELECT high_at,critical_at,high_reason,exploited_at FROM publication_observations WHERE threat_key=?')
      .bind(revision.threat_key)
      .first<{
        high_at: number | null;
        critical_at: number | null;
        high_reason: string | null;
        exploited_at: number | null;
      }>();
    if (classification.urgent && !history?.exploited) {
      return { ...base, eventAt: observation?.exploited_at ?? base.eventAt, reason: '悪用確認' };
    }
    const eventAt = level === 3 ? observation?.critical_at : level === 2 ? observation?.high_at : null;
    if (eventAt == null || (history?.level ?? 0) >= level || !classification.eligible) {
      return null;
    }
    return {
      route: publicationRoute(level, true, classification.urgent),
      level,
      eventAt,
      reason: level === 3 ? 'Critical昇格・初評価' : (observation?.high_reason ?? 'High昇格'),
    };
  }

  /** 個別配信の所属CVEと送信時点の通知段階を保存するSQLを作る。 */
  individualItemStatement(id: string, token?: string): D1PreparedStatement {
    return this.db
      .prepare(`INSERT INTO delivery_items(delivery_id,threat_key,revision_id,evidence_hash,level,exploited,event_at)
      SELECT d.id,r.threat_key,r.id,r.evidence_hash,
      CASE WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>=9 THEN 3 WHEN (SELECT MAX(json_extract(value,'$.score')) FROM json_each(r.snapshot,'$.scores'))>=7 THEN 2 ELSE 0 END,
      COALESCE(json_extract(r.snapshot,'$.exploited'),0),COALESCE(d.event_at,r.event_at) FROM deliveries d JOIN revisions r ON r.id=d.revision_id
      WHERE d.id=? AND ((? IS NULL AND d.state NOT IN ('sent','sending','unknown')) OR (d.state='sending' AND d.lease_token=?))
      ON CONFLICT(delivery_id,threat_key) DO UPDATE SET revision_id=excluded.revision_id,evidence_hash=excluded.evidence_hash,level=excluded.level,exploited=excluded.exploited,event_at=excluded.event_at`)
      .bind(id, token ?? null, token ?? null);
  }

  /** まとめの所属を取得し、整形時の根拠版を返す。 */
  async members(id: string): Promise<
    {
      threat_key: string;
      revision_id: string;
      evidence_hash: string;
      level: number;
      exploited: number;
      event_at: number;
    }[]
  > {
    return (
      await this.db.prepare('SELECT * FROM delivery_items WHERE delivery_id=? ORDER BY threat_key').bind(id).all<{
        threat_key: string;
        revision_id: string;
        evidence_hash: string;
        level: number;
        exploited: number;
        event_at: number;
      }>()
    ).results;
  }

  /** 観測段階と未準備・品質保留の理由を運用者へ返す。 */
  async status() {
    const rows = await this.db
      .prepare(`SELECT o.*,r.id AS revision_id,s.validation,
      CASE WHEN s.evidence_hash=r.evidence_hash THEN 1 ELSE 0 END AS summary_current
      FROM publication_observations o JOIN threats t ON t.key=o.threat_key JOIN revisions r ON r.id=t.revision_id
      LEFT JOIN summaries s ON s.revision_id=r.id
      ORDER BY MAX(COALESCE(o.critical_at,0),COALESCE(o.high_at,0),COALESCE(o.exploited_at,0)) DESC,o.threat_key LIMIT 100`)
      .all();
    return rows.results.map((row) => ({
      ...row,
      validation: row.summary_current && typeof row.validation === 'string' ? JSON.parse(row.validation) : null,
    }));
  }

  /** 未送信配信を現在の発信方法へ切り替え、方式休止による保留を再開する。 */
  async reconcileDeliveries(now: number): Promise<void> {
    const activeTargets =
      this.config?.targets.filter((target) => target.enabled || this.config?.dryRun).map((target) => target.id) ?? [];
    await this.db
      .prepare(`UPDATE deliveries SET state='ready',error=NULL,available_at=MAX(available_at,?),updated_at=?
      WHERE mode='individual' AND state='stale' AND error='individual_to_digest'
      AND target_id IN (SELECT value FROM json_each(?))
      AND EXISTS(SELECT 1 FROM threats t JOIN revisions r ON r.id=t.revision_id LEFT JOIN publication_observations o ON o.threat_key=t.key
        WHERE r.id=deliveries.revision_id AND (?=0 OR COALESCE(o.nvd_only,0)=0 OR r.priority<>2 OR r.urgent=1 OR json_extract(r.snapshot,'$.rejected')=1))
      AND (?=1 OR NOT EXISTS(SELECT 1 FROM delivery_items i JOIN deliveries d ON d.id=i.delivery_id
        WHERE i.revision_id=deliveries.revision_id AND d.target_id=deliveries.target_id AND d.mode='digest' AND d.state IN ('sent','sending','unknown')))`)
      .bind(now, now, JSON.stringify(activeTargets), this.enabled ? 1 : 0, this.enabled ? 1 : 0)
      .run();
    if (!this.enabled) {
      return;
    }
    const cutoff =
      (await this.db
        .prepare("SELECT CAST(value AS INTEGER) AS cutoff FROM settings WHERE key='event_cutoff'")
        .first<number>('cutoff')) ?? 0;
    const deadline = Math.max(cutoff, now - (this.config?.freshnessSeconds ?? 259200) * 1000);
    const expired = await this.db
      .prepare(`UPDATE deliveries SET state='stale',error='digest_members_expired',updated_at=?
      WHERE mode='digest' AND state IN ('ready','held','preview')
      AND EXISTS(SELECT 1 FROM delivery_items i WHERE i.delivery_id=deliveries.id AND i.event_at<?)
      AND EXISTS(SELECT 1 FROM delivery_items i WHERE i.delivery_id=deliveries.id AND i.event_at>=?)`)
      .bind(now, deadline, deadline)
      .run();
    if (expired.meta.changes > 0) {
      const window = digestWindow(now, this.config?.publishing.digestIntervalSeconds ?? 21600);
      await this.db
        .prepare(`DELETE FROM digest_windows WHERE window_end=? AND target_id IN (
        SELECT target_id FROM deliveries WHERE state='stale' AND error='digest_members_expired' AND updated_at=?)`)
        .bind(window.end, now)
        .run();
    }
    await this.db
      .prepare(`UPDATE deliveries SET state='stale',error='individual_to_digest',updated_at=?
      WHERE mode='individual' AND state IN ('ready','held','preview')
      AND COALESCE(error,'') NOT IN ('digest_item_too_long','publication_event_expired')
      AND EXISTS(SELECT 1 FROM threats t JOIN revisions r ON r.id=t.revision_id JOIN publication_observations o ON o.threat_key=t.key
        WHERE r.id=deliveries.revision_id AND o.nvd_only=1 AND r.priority=2 AND r.urgent=0 AND json_extract(r.snapshot,'$.rejected')=0)`)
      .bind(now)
      .run();
    await this.db
      .prepare(`UPDATE deliveries SET state='stale',error='digest_members_changed',updated_at=?
      WHERE mode='digest' AND state IN ('ready','held','preview') AND EXISTS(
        SELECT 1 FROM delivery_items i LEFT JOIN threats t ON t.key=i.threat_key LEFT JOIN revisions r ON r.id=t.revision_id
        LEFT JOIN publication_observations o ON o.threat_key=i.threat_key LEFT JOIN summaries s ON s.revision_id=r.id
        WHERE i.delivery_id=deliveries.id AND (r.id IS NULL OR r.id<>i.revision_id OR r.evidence_hash<>i.evidence_hash
          OR r.priority<>2 OR r.urgent=1 OR COALESCE(o.nvd_only,0)<>1 OR o.high_at IS NULL OR o.high_at<>i.event_at
          OR s.evidence_hash IS NULL OR s.evidence_hash<>i.evidence_hash OR i.summary_json IS NULL OR s.summary<>i.summary_json))`)
      .bind(now)
      .run();
    const targets =
      this.config?.targets.filter((target) => target.enabled || this.config?.dryRun).map((target) => target.id) ?? [];
    await this.db
      .prepare(`UPDATE deliveries SET state='ready',error=NULL,available_at=MAX(available_at,?),updated_at=?
      WHERE mode='digest' AND ((state='held' AND error='digest_disabled') OR (state='preview' AND ?=0)) AND target_id IN (SELECT value FROM json_each(?))`)
      .bind(now, now, this.config?.dryRun ? 1 : 0, JSON.stringify(targets))
      .run();
  }

  /** 一つの期間の全分割と所属を、他の実行による二重作成なしで確定する。 */
  async createWindow(
    target: string,
    window: { start: number; end: number },
    pages: { members: DigestMember[]; text: string }[],
    now: number,
  ): Promise<void> {
    const token = crypto.randomUUID();
    const earliest = Math.min(now, ...pages.flatMap((page) => page.members.map((member) => member.decision.eventAt)));
    const statements = [
      this.db
        .prepare(`INSERT OR IGNORE INTO digest_windows(target_id,window_end,token) SELECT ?,?,?
          WHERE ?>=COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key='event_cutoff'),0)`)
        .bind(target, window.end, token, earliest),
    ];
    for (const page of pages) {
      const id = await digest(
        `digest:${target}:${window.end}:${JSON.stringify(page.members.map((member) => [member.revision.id, member.revision.evidence_hash, member.decision.eventAt]))}`,
      );
      statements.push(
        this.db
          .prepare(`INSERT OR IGNORE INTO deliveries(id,target_id,mode,window_start,window_end,event_at,state,urgent,available_at,prepared,created_at,updated_at)
        SELECT ?,?,'digest',?,?,?,'ready',0,?,?,?,? WHERE EXISTS(SELECT 1 FROM digest_windows WHERE target_id=? AND window_end=? AND token=?)`)
          .bind(
            id,
            target,
            window.start,
            window.end,
            Math.min(...page.members.map((member) => member.decision.eventAt)),
            now,
            JSON.stringify({ text: page.text }),
            now,
            now,
            target,
            window.end,
            token,
          ),
      );
      statements.push(
        this.db
          .prepare(`INSERT OR IGNORE INTO delivery_items(delivery_id,threat_key,revision_id,evidence_hash,level,exploited,event_at,summary_json)
        SELECT ?,json_extract(value,'$.key'),json_extract(value,'$.revision'),json_extract(value,'$.hash'),json_extract(value,'$.level'),0,json_extract(value,'$.eventAt'),json_extract(value,'$.summary') FROM json_each(?)
        WHERE EXISTS(SELECT 1 FROM digest_windows WHERE target_id=? AND window_end=? AND token=?)`)
          .bind(
            id,
            JSON.stringify(
              page.members.map((member) => ({
                key: member.revision.threat_key,
                revision: member.revision.id,
                hash: member.revision.evidence_hash,
                level: member.decision.level,
                eventAt: member.decision.eventAt,
                summary: JSON.stringify(member.summary),
              })),
            ),
            target,
            window.end,
            token,
          ),
      );
    }
    await this.db.batch(statements);
  }

  /** まとめの全項目が現在も送信可能かを確認する。 */
  async digestCurrent(delivery: Delivery): Promise<boolean> {
    const members = await this.members(delivery.id);
    if (!members.length) {
      return false;
    }
    for (const member of members) {
      const row = await this.db
        .prepare('SELECT r.* FROM revisions r JOIN threats t ON t.revision_id=r.id WHERE r.id=? AND r.evidence_hash=?')
        .bind(member.revision_id, member.evidence_hash)
        .first<Omit<Revision, 'snapshot'> & { snapshot: string }>();
      if (!row) {
        return false;
      }
      const quality = await this.db
        .prepare(
          'SELECT s.summary,s.validation,i.summary_json FROM summaries s JOIN delivery_items i ON i.revision_id=s.revision_id AND i.evidence_hash=s.evidence_hash WHERE i.delivery_id=? AND i.threat_key=?',
        )
        .bind(delivery.id, member.threat_key)
        .first<{ summary: string; validation: string; summary_json: string | null }>();
      const validation = quality ? (JSON.parse(quality.validation) as { valid: boolean; complete: boolean }) : null;
      const strict =
        this.config?.targets.find((target) => target.id === delivery.target_id)?.qualityGate.enabled ?? true;
      if (
        !quality ||
        quality.summary !== quality.summary_json ||
        !validation?.valid ||
        (strict && !validation.complete)
      ) {
        return false;
      }
      const decision = await this.decision(
        { ...row, snapshot: JSON.parse(row.snapshot) as ThreatSnapshot },
        delivery.target_id,
      );
      if (decision?.route !== 'digest' || decision.eventAt !== member.event_at) {
        return false;
      }
    }
    return true;
  }
}
