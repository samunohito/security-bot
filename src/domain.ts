export interface Score {
  score: number;
  version: string;
  issuer: string;
}

export interface SourceItem {
  sourceId: string;
  id: string;
  url: string;
  title: string;
  text: string;
  publishedAt: number;
  modifiedAt: number;
  fetchedAt: number;
  cves: string[];
  scores: Score[];
  exploited: boolean;
  advisory: boolean;
  urgent: boolean;
  affected: string | null;
  remediation: string | null;
  impact?: string | null;
  rejected: boolean;
}

export interface Evidence extends SourceItem {
  evidenceId: string;
  scope: 'cve' | 'article';
}

export interface ThreatSnapshot {
  key: string;
  evidence: Evidence[];
  title: string;
  scores: Score[];
  exploited: boolean;
  advisory: boolean;
  urgent: boolean;
  rejected: boolean;
  affected: string | null;
  remediation: string | null;
  impact?: string | null;
  eventAt: number;
}

export interface Claim {
  text: string;
  evidence: { id: string; quote: string }[];
}

export type ActionKind = 'routine_update' | 'unpatched' | 'workaround' | 'additional_steps' | 'patch_warning';

export interface SummaryTag extends Claim {
  kind: 'usage' | 'theme' | 'vendor' | 'product';
}

export interface Summary {
  overview: Claim | null;
  impact: Claim | null;
  action: Claim | null;
  uncertainties: string[];
  subject?: Claim | null;
  actionKind?: ActionKind | null;
  tags?: SummaryTag[];
}

export interface Validation {
  valid: boolean;
  complete: boolean;
  reasons: string[];
}

export interface PublishedPost {
  id: string;
  url: string;
}

export interface PostIntent {
  kind: 'new' | 'update' | 'correction';
  key: string;
  title: string;
  severity: string;
  summary: Summary;
  sources: string[];
  previousPost?: PublishedPost;
}

/** 1件の収集データを脅威キー単位に分け、根拠として正規化する。 */
export function normalizeItem(item: SourceItem): { key: string; evidence: Evidence }[] {
  const cves = [...new Set(item.cves.filter((c) => /^CVE-\d{4}-\d{4,}$/i.test(c)).map((c) => c.toUpperCase()))].sort();
  const keys = cves.length ? cves : [`${item.sourceId}:${item.id}`];

  return keys.map((key) => ({
    key,
    evidence: {
      ...item,
      ...(cves.length > 1
        ? {
            scores: [],
            exploited: false,
            urgent: false,
            affected: null,
            remediation: null,
            impact: null,
          }
        : {}),
      cves,
      evidenceId: `${item.sourceId}:${item.id}`,
      scope: cves.length === 1 ? 'cve' : 'article',
    },
  }));
}

/** 脅威の適格性、優先度、重大度を根拠情報から判定する。 */
export function classify(t: {
  scores: { score: number }[];
  exploited: boolean;
  urgent: boolean;
  advisory: boolean;
  rejected: boolean;
}) {
  const score = Math.max(0, ...t.scores.map((s) => s.score));
  const urgent = t.exploited || t.urgent;

  return {
    eligible: !t.rejected && (score >= 7 || urgent || t.advisory),
    priority: urgent ? 0 : score >= 9 ? 1 : score >= 7 ? 2 : 3,
    severity: score >= 9 ? 'Critical' : score >= 7 ? 'High' : score > 0 ? 'Medium/Low' : '未評価',
    urgent,
  };
}

/** 投稿内容の変更判定に使う、重要な属性の正規化キーを作る。 */
export function materialKey<
  T extends {
    affected: string | null;
    remediation: string | null;
    exploited: boolean;
    rejected: boolean;
    impact?: string | null;
  },
>(t: T): string {
  return JSON.stringify([
    t.affected?.replace(/\s+/g, ' ').trim() ?? null,
    t.remediation?.replace(/\s+/g, ' ').trim() ?? null,
    t.exploited,
    t.rejected,
    t.impact?.replace(/\s+/g, ' ').trim() ?? null,
  ]);
}

/** 根拠群から脅威の現在状態を集約する。 */
export function snapshot(key: string, evidence: Evidence[]): ThreatSnapshot {
  const latest = [...evidence].sort((a, b) => b.modifiedAt - a.modifiedAt || a.evidenceId.localeCompare(b.evidenceId));

  return {
    key,
    evidence: latest,
    impact: [...new Set(latest.flatMap((e) => (e.impact ? [e.impact] : [])))].sort().join('\n') || null,
    title: latest[0]?.title ?? key,
    scores: latest.flatMap((e) => e.scores),
    exploited: latest.some((e) => e.exploited),
    urgent: latest.some((e) => e.urgent),
    advisory: latest.some((e) => e.advisory),
    rejected: latest.some((e) => e.rejected),
    affected: [...new Set(latest.flatMap((e) => (e.affected ? [e.affected] : [])))].sort().join('\n') || null,
    remediation: [...new Set(latest.flatMap((e) => (e.remediation ? [e.remediation] : [])))].sort().join('\n') || null,
    eventAt: Math.max(0, ...latest.map((e) => e.modifiedAt)),
  };
}

/** ミリ秒のUnix時刻を日本時間の投稿日（YYYY-MM-DD）に変換する。 */
export function publicationDay(now: number): string {
  return new Date(now + 9 * 3600000).toISOString().slice(0, 10);
}

/** ミリ秒のUnix時刻をUTCの日付（YYYY-MM-DD）に変換する。 */
export function utcDay(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

/** 文字列のSHA-256ダイジェストを小文字16進数で返す。 */
export async function digest(value: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));

  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
