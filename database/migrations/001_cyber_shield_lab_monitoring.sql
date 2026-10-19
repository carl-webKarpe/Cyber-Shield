-- =====================================================================
-- Cyber-Shield migration 001 - Lab monitoring, VirusTotal scans, roles, audit log
--
-- Run in MySQL Workbench AFTER users.sql (the original Cyber-Shield schema):
--   File > Open SQL Script... > select this file > Execute (lightning bolt).
--
-- Safe to run more than once. Existing tables and rows are preserved:
-- this script only ADDS tables, columns, indexes and enum values.
-- Requires MySQL Server 8.0 or newer.
-- =====================================================================

USE cyber_shield;

DROP PROCEDURE IF EXISTS cs_add_column;
DROP PROCEDURE IF EXISTS cs_add_index;

DELIMITER $$
CREATE PROCEDURE cs_add_column(IN p_table VARCHAR(64), IN p_column VARCHAR(64), IN p_definition TEXT)
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND COLUMN_NAME = p_column
	) THEN
		SET @cs_sql = CONCAT('ALTER TABLE `', p_table, '` ADD COLUMN `', p_column, '` ', p_definition);
		PREPARE cs_statement FROM @cs_sql;
		EXECUTE cs_statement;
		DEALLOCATE PREPARE cs_statement;
	END IF;
END $$

CREATE PROCEDURE cs_add_index(IN p_table VARCHAR(64), IN p_index VARCHAR(64), IN p_definition TEXT)
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table AND INDEX_NAME = p_index
	) THEN
		SET @cs_sql = CONCAT('ALTER TABLE `', p_table, '` ADD ', p_definition);
		PREPARE cs_statement FROM @cs_sql;
		EXECUTE cs_statement;
		DEALLOCATE PREPARE cs_statement;
	END IF;
END $$
DELIMITER ;

-- ---------------------------------------------------------------------
-- 1. Roles: add Super Admin. Existing 'analyst' accounts keep Admin permissions.
-- ---------------------------------------------------------------------
ALTER TABLE users
	MODIFY role ENUM('analyst', 'admin', 'superadmin') NOT NULL DEFAULT 'admin';
CALL cs_add_column('users', 'is_active', 'TINYINT(1) NOT NULL DEFAULT 1 AFTER role');

-- The original demo account ships with a password printed on the old sign-in page.
-- Disable it only while that public password is still unchanged.
UPDATE users SET is_active = 0
WHERE email = 'analyst@cybershield.local'
	AND password_hash = '$2y$10$m0Paxg7TKZFyyw4ho4gRMe.NrVXzW5TdGMhFgZUvd467OoYLSBK3K';

-- ---------------------------------------------------------------------
-- 2. Scan history: allow "pending" and "unknown" so unscanned files are never shown as safe.
-- ---------------------------------------------------------------------
ALTER TABLE scans
	MODIFY status ENUM('safe', 'suspicious', 'threat', 'pending', 'unknown') NOT NULL;
CALL cs_add_column('scans', 'scan_request_id', 'BIGINT UNSIGNED DEFAULT NULL AFTER user_id');
CALL cs_add_index('scans', 'idx_scans_request', 'KEY idx_scans_request (scan_request_id)');

-- ---------------------------------------------------------------------
-- 3. Authorized laboratory computers (registered by the Python agent)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS lab_computers (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	agent_uuid CHAR(36) NOT NULL,
	hostname VARCHAR(255) NOT NULL,
	lab_location VARCHAR(120) DEFAULT NULL,
	ip_address VARCHAR(45) DEFAULT NULL,
	mac_address VARCHAR(17) DEFAULT NULL,
	os_version VARCHAR(160) DEFAULT NULL,
	agent_version VARCHAR(20) DEFAULT NULL,
	connection_type ENUM('ethernet', 'wifi', 'hotspot', 'unknown') NOT NULL DEFAULT 'unknown',
	agent_secret CHAR(64) NOT NULL,
	watched_paths TEXT DEFAULT NULL,
	is_authorized TINYINT(1) NOT NULL DEFAULT 0,
	authorized_by INT UNSIGNED DEFAULT NULL,
	authorized_at DATETIME DEFAULT NULL,
	registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_heartbeat DATETIME DEFAULT NULL,
	PRIMARY KEY (id),
	UNIQUE KEY lab_computers_agent_uuid (agent_uuid),
	KEY idx_lab_computers_heartbeat (last_heartbeat),
	CONSTRAINT fk_lab_computers_authorized_by FOREIGN KEY (authorized_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 4. File events reported by agents
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_events (
	id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	computer_id INT UNSIGNED NOT NULL,
	event_uid CHAR(36) NOT NULL,
	event_type ENUM('created', 'modified', 'deleted', 'moved') NOT NULL,
	file_path VARCHAR(1024) NOT NULL,
	file_name VARCHAR(255) NOT NULL,
	file_extension VARCHAR(32) DEFAULT NULL,
	file_size BIGINT UNSIGNED DEFAULT NULL,
	sha256 CHAR(64) DEFAULT NULL,
	detected_at DATETIME NOT NULL,
	received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE KEY file_events_computer_uid (computer_id, event_uid),
	KEY idx_file_events_detected (detected_at),
	KEY idx_file_events_computer_detected (computer_id, detected_at),
	KEY idx_file_events_sha256 (sha256),
	CONSTRAINT fk_file_events_computer FOREIGN KEY (computer_id) REFERENCES lab_computers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 5. Scan requests (who asked for which file/URL to be scanned) and VirusTotal results
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_requests (
	id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	requested_by INT UNSIGNED DEFAULT NULL,
	source ENUM('upload', 'file_event', 'url') NOT NULL,
	computer_id INT UNSIGNED DEFAULT NULL,
	file_event_id BIGINT UNSIGNED DEFAULT NULL,
	target_name VARCHAR(500) NOT NULL,
	file_path VARCHAR(1024) DEFAULT NULL,
	sha256 CHAR(64) DEFAULT NULL,
	status ENUM('pending', 'awaiting_upload', 'submitted', 'completed', 'not_found', 'failed') NOT NULL DEFAULT 'pending',
	vt_analysis_id VARCHAR(255) DEFAULT NULL,
	error_message VARCHAR(500) DEFAULT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	KEY idx_scan_requests_status (status),
	KEY idx_scan_requests_sha256 (sha256),
	KEY idx_scan_requests_computer_status (computer_id, status),
	KEY idx_scan_requests_event (file_event_id),
	CONSTRAINT fk_scan_requests_user FOREIGN KEY (requested_by) REFERENCES users (id) ON DELETE SET NULL,
	CONSTRAINT fk_scan_requests_computer FOREIGN KEY (computer_id) REFERENCES lab_computers (id) ON DELETE SET NULL,
	CONSTRAINT fk_scan_requests_event FOREIGN KEY (file_event_id) REFERENCES file_events (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_results (
	id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	scan_request_id BIGINT UNSIGNED NOT NULL,
	sha256 CHAR(64) DEFAULT NULL,
	sha1 CHAR(40) DEFAULT NULL,
	md5 CHAR(32) DEFAULT NULL,
	malicious INT UNSIGNED NOT NULL DEFAULT 0,
	suspicious INT UNSIGNED NOT NULL DEFAULT 0,
	harmless INT UNSIGNED NOT NULL DEFAULT 0,
	undetected INT UNSIGNED NOT NULL DEFAULT 0,
	total_engines INT UNSIGNED NOT NULL DEFAULT 0,
	detection_ratio VARCHAR(20) NOT NULL,
	risk_level ENUM('clean', 'low', 'medium', 'high', 'critical', 'unknown') NOT NULL,
	threat_label VARCHAR(255) DEFAULT NULL,
	file_type VARCHAR(120) DEFAULT NULL,
	recommended_action VARCHAR(500) NOT NULL,
	vt_link VARCHAR(500) DEFAULT NULL,
	analysis_date DATETIME DEFAULT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE KEY scan_results_request (scan_request_id),
	KEY idx_scan_results_sha256 (sha256),
	KEY idx_scan_results_risk (risk_level),
	CONSTRAINT fk_scan_results_request FOREIGN KEY (scan_request_id) REFERENCES scan_requests (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 6. Audit log (sign-ins, scans, agent registrations, approvals)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
	id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	actor_type ENUM('user', 'agent', 'system') NOT NULL,
	user_id INT UNSIGNED DEFAULT NULL,
	computer_id INT UNSIGNED DEFAULT NULL,
	action VARCHAR(64) NOT NULL,
	details TEXT DEFAULT NULL,
	ip_address VARCHAR(45) DEFAULT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	KEY idx_audit_logs_created (created_at),
	KEY idx_audit_logs_ip_action (ip_address, action, created_at),
	CONSTRAINT fk_audit_logs_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
	CONSTRAINT fk_audit_logs_computer FOREIGN KEY (computer_id) REFERENCES lab_computers (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

DROP PROCEDURE IF EXISTS cs_add_column;
DROP PROCEDURE IF EXISTS cs_add_index;

INSERT INTO audit_logs (actor_type, action, details) VALUES ('system', 'migration.applied', 'Cyber-Shield migration 001 applied');
