CREATE TABLE `digest_windows` (
	`target_id` text NOT NULL,
	`window_end` integer NOT NULL,
	`token` text NOT NULL,
	PRIMARY KEY(`target_id`, `window_end`)
);
