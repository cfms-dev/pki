-- Initial adoption only: existing databases must already have the latest schema.
CREATE TABLE IF NOT EXISTS `account_key_conflicts` (
	`account_id` text PRIMARY KEY NOT NULL,
	`reason` text NOT NULL,
	`public_key_fingerprint` text,
	`conflicting_account_id` text,
	`detected_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `accounts` (
	`id` text PRIMARY KEY NOT NULL,
	`jwk` text NOT NULL,
	`thumbprint` text NOT NULL,
	`public_key_fingerprint` text,
	`contact` text,
	`status` text NOT NULL,
	`created_at` integer NOT NULL,
	`terms_of_service` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `accounts_thumbprint_unique` ON `accounts` (`thumbprint`);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_accounts_public_key_fingerprint` ON `accounts` (`public_key_fingerprint`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_accounts_missing_public_key_fingerprint` ON `accounts` (`id`) WHERE "accounts"."public_key_fingerprint" IS NULL;--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `authorizations` (
	`id` text PRIMARY KEY NOT NULL,
	`order_id` text NOT NULL,
	`identifier_value` text NOT NULL,
	`identifier_type` text DEFAULT 'dns' NOT NULL,
	`status` text NOT NULL,
	`token` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_authorizations_order` ON `authorizations` (`order_id`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `certificates` (
	`id` text PRIMARY KEY NOT NULL,
	`cert_id` text NOT NULL,
	`serial_number` text NOT NULL,
	`aki` text NOT NULL,
	`subject` text NOT NULL,
	`san` text NOT NULL,
	`pem` text NOT NULL,
	`not_before` integer NOT NULL,
	`not_after` integer NOT NULL,
	`account_id` text NOT NULL,
	`created_at` integer NOT NULL,
	`revoked_at` integer,
	`revocation_reason` text,
	`replaced_by_cert_id` text,
	`ca_id` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `certificates_cert_id_unique` ON `certificates` (`cert_id`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_certificates_serial` ON `certificates` (`serial_number`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`authorization_id` text NOT NULL,
	`type` text NOT NULL,
	`token` text NOT NULL,
	`status` text NOT NULL,
	`error` text,
	`validated_at` integer,
	`processing_started_at` integer,
	`validation_generation` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_challenges_authorization` ON `challenges` (`authorization_id`);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `challenges_authorization_id_type_unique` ON `challenges` (`authorization_id`,`type`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `issuance_ledger` (
	`certificate_id` text NOT NULL,
	`bucket_key` text NOT NULL,
	`issued_at` integer NOT NULL,
	PRIMARY KEY(`certificate_id`, `bucket_key`)
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_issuance_ledger_bucket_time` ON `issuance_ledger` (`bucket_key`,`issued_at`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `nonces` (
	`nonce` text PRIMARY KEY NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_nonces_expiry` ON `nonces` (`expires_at`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `orders` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`status` text NOT NULL,
	`identifiers` text NOT NULL,
	`not_before` integer,
	`not_after` integer,
	`replaces_cert_id` text,
	`is_ari_renewal` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`certificate_id` text,
	`processing_started_at` integer,
	`finalize_generation` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_orders_account` ON `orders` (`account_id`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `rate_limits` (
	`key` text PRIMARY KEY NOT NULL,
	`counter` integer NOT NULL,
	`window_start` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `security_migrations` (
	`name` text PRIMARY KEY NOT NULL,
	`completed_at` integer NOT NULL
);

--> statement-breakpoint
-- Never declare an existing certificate history ready without its original ledger.
INSERT OR IGNORE INTO security_migrations (name, completed_at)
SELECT 'issuance-ledger-v1', unixepoch() WHERE NOT EXISTS (SELECT 1 FROM certificates);
