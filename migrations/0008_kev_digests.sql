ALTER TABLE `deliveries` ADD `kev_batch` text;--> statement-breakpoint
ALTER TABLE `revisions` ADD `kev_batch` text;--> statement-breakpoint
CREATE INDEX `revisions_kev_batch` ON `revisions` (`kev_batch`,`threat_key`) WHERE "revisions"."kev_batch" IS NOT NULL;