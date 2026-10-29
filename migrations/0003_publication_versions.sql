ALTER TABLE `delivery_items` ADD `summary_json` text;--> statement-breakpoint
ALTER TABLE `publication_observations` ADD `current_level` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
UPDATE publication_observations SET current_level=highest_level;
