CREATE TABLE `delivery_items` (
	`delivery_id` text NOT NULL,
	`threat_key` text NOT NULL,
	`revision_id` text NOT NULL,
	`evidence_hash` text NOT NULL,
	`level` integer NOT NULL,
	`exploited` integer NOT NULL,
	`event_at` integer NOT NULL,
	PRIMARY KEY(`delivery_id`, `threat_key`)
);
--> statement-breakpoint
CREATE INDEX `delivery_items_threat` ON `delivery_items` (`threat_key`);--> statement-breakpoint
CREATE TABLE `publication_observations` (
	`threat_key` text PRIMARY KEY NOT NULL,
	`highest_level` integer NOT NULL,
	`high_at` integer,
	`critical_at` integer,
	`high_reason` text,
	`nvd_only` integer NOT NULL
);
--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_deliveries` (
	`id` text PRIMARY KEY NOT NULL,
	`target_id` text NOT NULL,
	`revision_id` text,
	`mode` text DEFAULT 'individual' NOT NULL,
	`window_start` integer,
	`window_end` integer,
	`event_at` integer,
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
	`updated_at` integer NOT NULL,
	CONSTRAINT "delivery_mode" CHECK(("__new_deliveries"."mode"='individual' AND "__new_deliveries"."revision_id" IS NOT NULL) OR ("__new_deliveries"."mode"='digest' AND "__new_deliveries"."revision_id" IS NULL AND "__new_deliveries"."window_start" IS NOT NULL AND "__new_deliveries"."window_end" IS NOT NULL))
);
--> statement-breakpoint
INSERT INTO `__new_deliveries`("id", "target_id", "revision_id", "mode", "window_start", "window_end", "event_at", "state", "urgent", "available_at", "lease_token", "lease_until", "reserved_day", "post_id", "post_url", "prepared", "error", "created_at", "updated_at") SELECT "id", "target_id", "revision_id", 'individual', NULL, NULL, NULL, "state", "urgent", "available_at", "lease_token", "lease_until", "reserved_day", "post_id", "post_url", "prepared", "error", "created_at", "updated_at" FROM `deliveries`;--> statement-breakpoint
DROP TABLE `deliveries`;--> statement-breakpoint
ALTER TABLE `__new_deliveries` RENAME TO `deliveries`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `deliveries_due` ON `deliveries` (`state`,`available_at`);--> statement-breakpoint
CREATE INDEX `deliveries_history` ON `deliveries` (`target_id`,`state`,"updated_at" DESC);--> statement-breakpoint
CREATE UNIQUE INDEX `deliveries_target_id_revision_id_unique` ON `deliveries` (`target_id`,`revision_id`);