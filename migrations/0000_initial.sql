CREATE TABLE `attempts` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`delivery_id` text NOT NULL,
	`token` text NOT NULL,
	`state` text NOT NULL,
	`at` integer NOT NULL,
	`error` text
);
--> statement-breakpoint
CREATE TABLE `budget_reservations` (
	`id` text PRIMARY KEY NOT NULL,
	`day` text NOT NULL,
	`amount` real NOT NULL,
	`state` text DEFAULT 'reserved' NOT NULL,
	`charged` integer DEFAULT 0 NOT NULL,
	`lease_until` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `budget_active` ON `budget_reservations` (`state`,`lease_until`);--> statement-breakpoint
CREATE TABLE `budgets` (
	`day` text PRIMARY KEY NOT NULL,
	`calls` integer DEFAULT 0 NOT NULL,
	`neurons` real DEFAULT 0 NOT NULL,
	`queue_ops` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE TABLE `deliveries` (
	`id` text PRIMARY KEY NOT NULL,
	`target_id` text NOT NULL,
	`revision_id` text NOT NULL,
	`state` text DEFAULT 'ready' NOT NULL,
	`urgent` integer NOT NULL,
	`available_at` integer NOT NULL,
	`lease_token` text,
	`lease_until` integer,
	`reserved_day` text,
	`post_id` text,
	`post_url` text,
	`prepared` text,
	`error` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `deliveries_due` ON `deliveries` (`state`,`available_at`);--> statement-breakpoint
CREATE INDEX `deliveries_history` ON `deliveries` (`target_id`,`state`,"updated_at" desc);--> statement-breakpoint
CREATE UNIQUE INDEX `deliveries_target_id_revision_id_unique` ON `deliveries` (`target_id`,`revision_id`);--> statement-breakpoint
CREATE TABLE `evidence` (
	`threat_key` text NOT NULL,
	`id` text NOT NULL,
	`hash` text NOT NULL,
	`source_version` text NOT NULL,
	`current` integer DEFAULT 1 NOT NULL,
	`modified_at` integer NOT NULL,
	`fetched_at` integer NOT NULL,
	`data` text NOT NULL,
	PRIMARY KEY(`threat_key`, `id`, `hash`)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `evidence_current` ON `evidence` (`threat_key`,`id`) WHERE "evidence"."current"=1;--> statement-breakpoint
CREATE INDEX `evidence_identity` ON `evidence` (`id`,`current`);--> statement-breakpoint
CREATE TABLE `jobs` (
	`id` text PRIMARY KEY NOT NULL,
	`type` text NOT NULL,
	`payload` text NOT NULL,
	`state` text DEFAULT 'pending' NOT NULL,
	`available_at` integer NOT NULL,
	`dispatched_at` integer,
	`lease_until` integer,
	`lease_token` text,
	`attempts` integer DEFAULT 0 NOT NULL,
	`error` text,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `jobs_due` ON `jobs` (`state`,`available_at`,`dispatched_at`);--> statement-breakpoint
CREATE TABLE `quotas` (
	`target_id` text NOT NULL,
	`day` text NOT NULL,
	`bucket` text NOT NULL,
	`used` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`target_id`, `day`, `bucket`),
	CONSTRAINT "quotas_used_nonnegative" CHECK("quotas"."used">=0)
);
--> statement-breakpoint
CREATE TABLE `revisions` (
	`id` text PRIMARY KEY NOT NULL,
	`threat_key` text NOT NULL,
	`snapshot` text NOT NULL,
	`evidence_hash` text NOT NULL,
	`kind` text NOT NULL,
	`event_at` integer NOT NULL,
	`priority` integer NOT NULL,
	`urgent` integer NOT NULL,
	`eligible` integer NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `revisions_priority` ON `revisions` (`eligible`,`priority`,"event_at" desc);--> statement-breakpoint
CREATE TABLE `settings` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `shortened_summaries` (
	`delivery_id` text PRIMARY KEY NOT NULL,
	`evidence_hash` text NOT NULL,
	`summary` text NOT NULL,
	`validation` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `source_versions` (
	`id` text PRIMARY KEY NOT NULL,
	`version_hash` text NOT NULL,
	`modified_at` integer NOT NULL,
	`fetched_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `sources` (
	`id` text PRIMARY KEY NOT NULL,
	`cursor` text DEFAULT '{}' NOT NULL,
	`next_poll_at` integer DEFAULT 0 NOT NULL,
	`active_job` text,
	`last_success_at` integer,
	`last_error` text
);
--> statement-breakpoint
CREATE TABLE `summaries` (
	`revision_id` text PRIMARY KEY NOT NULL,
	`evidence_hash` text NOT NULL,
	`summary` text NOT NULL,
	`validation` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `targets` (
	`id` text PRIMARY KEY NOT NULL,
	`paused` integer DEFAULT 0 NOT NULL,
	`reason` text,
	`active_delivery` text,
	`last_attempt_at` integer,
	`last_normal_at` integer,
	`last_urgent_at` integer
);
--> statement-breakpoint
CREATE TABLE `threats` (
	`key` text PRIMARY KEY NOT NULL,
	`revision_id` text,
	`material` text DEFAULT '' NOT NULL,
	`generation` integer DEFAULT 0 NOT NULL
);
