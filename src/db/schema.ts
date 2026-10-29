import { desc, sql } from 'drizzle-orm';
import {
  check,
  index,
  integer,
  primaryKey,
  real,
  sqliteTable,
  text,
  unique,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';
import type { PostIntent } from '../domain';

export const sources = sqliteTable('sources', {
  id: text().primaryKey(),
  cursor: text().notNull().default('{}'),
  next_poll_at: integer().notNull().default(0),
  active_job: text(),
  last_success_at: integer(),
  last_error: text(),
});

export const jobs = sqliteTable(
  'jobs',
  {
    id: text().primaryKey(),
    type: text().notNull(),
    payload: text().notNull(),
    state: text().notNull().default('pending'),
    available_at: integer().notNull(),
    dispatched_at: integer(),
    dispatch_token: text(),
    dispatch_until: integer(),
    lease_until: integer(),
    lease_token: text(),
    attempts: integer().notNull().default(0),
    error: text(),
    created_at: integer().notNull(),
  },
  (table) => [
    index('jobs_due').on(table.state, table.available_at, table.dispatched_at),
    index('jobs_publish_delivery').on(table.state, table.payload).where(sql`${table.type}='publish'`),
  ],
);

export const threats = sqliteTable(
  'threats',
  {
    key: text().primaryKey(),
    revision_id: text(),
    material: text().notNull().default(''),
    generation: integer().notNull().default(0),
  },
  (table) => [index('threats_revision').on(table.revision_id)],
);

export const evidence = sqliteTable(
  'evidence',
  {
    threat_key: text().notNull(),
    id: text().notNull(),
    hash: text().notNull(),
    source_version: text().notNull(),
    current: integer().notNull().default(1),
    modified_at: integer().notNull(),
    fetched_at: integer().notNull(),
    data: text().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.threat_key, table.id, table.hash] }),
    uniqueIndex('evidence_current').on(table.threat_key, table.id).where(sql`${table.current}=1`),
    index('evidence_identity').on(table.id, table.current),
  ],
);

export const sourceVersions = sqliteTable('source_versions', {
  id: text().primaryKey(),
  version_hash: text().notNull(),
  modified_at: integer().notNull(),
  fetched_at: integer().notNull(),
});

export const revisions = sqliteTable(
  'revisions',
  {
    id: text().primaryKey(),
    threat_key: text().notNull(),
    snapshot: text().notNull(),
    evidence_hash: text().notNull(),
    kind: text().$type<PostIntent['kind']>().notNull(),
    event_at: integer().notNull(),
    priority: integer().notNull(),
    urgent: integer().notNull(),
    eligible: integer().notNull(),
    created_at: integer().notNull(),
  },
  (table) => [index('revisions_priority').on(table.eligible, table.priority, desc(table.event_at))],
);

export const summaries = sqliteTable('summaries', {
  revision_id: text().primaryKey(),
  evidence_hash: text().notNull(),
  summary: text().notNull(),
  validation: text().notNull(),
  created_at: integer().notNull(),
});

export const targets = sqliteTable('targets', {
  id: text().primaryKey(),
  paused: integer().notNull().default(0),
  reason: text(),
  active_delivery: text(),
  last_attempt_at: integer(),
  last_normal_at: integer(),
  last_urgent_at: integer(),
});

export const deliveries = sqliteTable(
  'deliveries',
  {
    id: text().primaryKey(),
    target_id: text().notNull(),
    revision_id: text(),
    mode: text().notNull().default('individual'),
    window_start: integer(),
    window_end: integer(),
    event_at: integer(),
    state: text().notNull().default('ready'),
    urgent: integer().notNull(),
    available_at: integer().notNull(),
    lease_token: text(),
    lease_until: integer(),
    reserved_day: text(),
    post_id: text(),
    post_url: text(),
    prepared: text(),
    error: text(),
    created_at: integer().notNull(),
    updated_at: integer().notNull(),
  },
  (table) => [
    unique().on(table.target_id, table.revision_id),
    index('deliveries_due').on(table.state, table.available_at),
    index('deliveries_history').on(table.target_id, table.state, desc(table.updated_at)),
    check(
      'delivery_mode',
      sql`(${table.mode}='individual' AND ${table.revision_id} IS NOT NULL) OR (${table.mode}='digest' AND ${table.revision_id} IS NULL AND ${table.window_start} IS NOT NULL AND ${table.window_end} IS NOT NULL)`,
    ),
  ],
);

export const publicationObservations = sqliteTable('publication_observations', {
  threat_key: text().primaryKey(),
  highest_level: integer().notNull(),
  current_level: integer().notNull().default(0),
  high_at: integer(),
  critical_at: integer(),
  exploited_at: integer(),
  current_exploited: integer().notNull().default(0),
  high_reason: text(),
  nvd_only: integer().notNull(),
});

export const digestWindows = sqliteTable(
  'digest_windows',
  {
    target_id: text().notNull(),
    window_end: integer().notNull(),
    token: text().notNull(),
  },
  (table) => [primaryKey({ columns: [table.target_id, table.window_end] })],
);

export const deliveryItems = sqliteTable(
  'delivery_items',
  {
    delivery_id: text().notNull(),
    threat_key: text().notNull(),
    revision_id: text().notNull(),
    evidence_hash: text().notNull(),
    summary_json: text(),
    level: integer().notNull(),
    exploited: integer().notNull(),
    event_at: integer().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.delivery_id, table.threat_key] }),
    index('delivery_items_threat').on(table.threat_key),
  ],
);

export const attempts = sqliteTable('attempts', {
  id: integer().primaryKey({ autoIncrement: true }),
  delivery_id: text().notNull(),
  token: text().notNull(),
  state: text().notNull(),
  at: integer().notNull(),
  error: text(),
});

export const quotas = sqliteTable(
  'quotas',
  {
    target_id: text().notNull(),
    day: text().notNull(),
    bucket: text().notNull(),
    used: integer().notNull().default(0),
  },
  (table) => [
    primaryKey({ columns: [table.target_id, table.day, table.bucket] }),
    check('quotas_used_nonnegative', sql`${table.used}>=0`),
  ],
);

export const budgets = sqliteTable('budgets', {
  day: text().primaryKey(),
  calls: integer().notNull().default(0),
  neurons: real().notNull().default(0),
  queue_ops: integer().notNull().default(0),
});

export const budgetReservations = sqliteTable(
  'budget_reservations',
  {
    id: text().primaryKey(),
    day: text().notNull(),
    amount: real().notNull(),
    state: text().notNull().default('reserved'),
    charged: integer().notNull().default(0),
    lease_until: integer().notNull(),
  },
  (table) => [index('budget_active').on(table.state, table.lease_until)],
);

export const settings = sqliteTable('settings', {
  key: text().primaryKey(),
  value: text().notNull(),
});

export const shortenedSummaries = sqliteTable('shortened_summaries', {
  delivery_id: text().primaryKey(),
  evidence_hash: text().notNull(),
  summary: text().notNull(),
  validation: text().notNull(),
});
