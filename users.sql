CREATE DATABASE IF NOT EXISTS cyber_shield
	CHARACTER SET utf8mb4
	COLLATE utf8mb4_unicode_ci;

USE cyber_shield;

CREATE TABLE IF NOT EXISTS users (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	name VARCHAR(100) NOT NULL,
	email VARCHAR(190) NOT NULL,
	password_hash VARCHAR(255) NOT NULL,
	role ENUM('analyst', 'admin') NOT NULL DEFAULT 'analyst',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_login DATETIME DEFAULT NULL,
	PRIMARY KEY (id),
	UNIQUE KEY users_email_unique (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scans (
	id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
	user_id INT UNSIGNED NOT NULL,
	name VARCHAR(500) NOT NULL,
	scan_type ENUM('File', 'URL') NOT NULL,
	result VARCHAR(255) NOT NULL,
	status ENUM('safe', 'suspicious', 'threat') NOT NULL,
	details TEXT DEFAULT NULL,
	file_size BIGINT UNSIGNED DEFAULT NULL,
	sha256 CHAR(64) DEFAULT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	KEY idx_scans_user_date (user_id, created_at),
	KEY idx_scans_status (status),
	CONSTRAINT fk_scans_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS endpoints (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	device_name VARCHAR(120) NOT NULL,
	owner_name VARCHAR(120) NOT NULL,
	platform VARCHAR(80) NOT NULL,
	last_seen DATETIME DEFAULT NULL,
	protection ENUM('protected', 'update_needed', 'at_risk', 'offline') NOT NULL DEFAULT 'protected',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE KEY endpoints_device_name (device_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS incidents (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	incident_code VARCHAR(30) NOT NULL,
	title VARCHAR(200) NOT NULL,
	description TEXT NOT NULL,
	severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
	category VARCHAR(100) NOT NULL,
	status ENUM('open', 'in_progress', 'resolved') NOT NULL DEFAULT 'open',
	detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	resolved_at DATETIME DEFAULT NULL,
	PRIMARY KEY (id),
	UNIQUE KEY incidents_code (incident_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_settings (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	user_id INT UNSIGNED NOT NULL,
	realtime_protection TINYINT(1) NOT NULL DEFAULT 1,
	deep_scan TINYINT(1) NOT NULL DEFAULT 0,
	auto_quarantine TINYINT(1) NOT NULL DEFAULT 1,
	email_alerts TINYINT(1) NOT NULL DEFAULT 1,
	weekly_summary TINYINT(1) NOT NULL DEFAULT 0,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE KEY user_settings_user (user_id),
	CONSTRAINT fk_settings_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS network_stats (
	id TINYINT UNSIGNED NOT NULL,
	connected_devices INT UNSIGNED NOT NULL DEFAULT 0,
	active_connections INT UNSIGNED NOT NULL DEFAULT 0,
	blocked_requests INT UNSIGNED NOT NULL DEFAULT 0,
	inbound_tb DECIMAL(10,2) NOT NULL DEFAULT 0.00,
	outbound_tb DECIMAL(10,2) NOT NULL DEFAULT 0.00,
	network_health ENUM('Healthy', 'Degraded', 'Offline') NOT NULL DEFAULT 'Healthy',
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS threat_regions (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	region_name VARCHAR(100) NOT NULL,
	count_24h INT UNSIGNED NOT NULL DEFAULT 0,
	count_7d INT UNSIGNED NOT NULL DEFAULT 0,
	count_30d INT UNSIGNED NOT NULL DEFAULT 0,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE KEY threat_regions_name (region_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO users (name, email, password_hash, role)
VALUES ('Demo Analyst', 'analyst@cybershield.local', '$2y$10$m0Paxg7TKZFyyw4ho4gRMe.NrVXzW5TdGMhFgZUvd467OoYLSBK3K', 'analyst')
ON DUPLICATE KEY UPDATE name = VALUES(name), password_hash = VALUES(password_hash);

INSERT INTO endpoints (device_name, owner_name, platform, last_seen, protection) VALUES
	('FINANCE-LT-024', 'M. Santos', 'Windows 11', NOW(), 'protected'),
	('DESIGN-MBP-08', 'A. Reyes', 'macOS 15', NOW() - INTERVAL 4 MINUTE, 'protected'),
	('OPS-WS-117', 'J. Cruz', 'Windows 10', NOW() - INTERVAL 18 MINUTE, 'update_needed'),
	('ENG-LINUX-032', 'K. Lim', 'Ubuntu 24.04', NOW() - INTERVAL 31 MINUTE, 'protected'),
	('HR-LT-015', 'R. Garcia', 'Windows 11', NOW() - INTERVAL 2 HOUR, 'offline'),
	('SALES-MBP-11', 'P. Dela Cruz', 'macOS 14', NOW() - INTERVAL 1 DAY, 'at_risk')
ON DUPLICATE KEY UPDATE owner_name = VALUES(owner_name), platform = VALUES(platform), last_seen = VALUES(last_seen), protection = VALUES(protection);

INSERT INTO incidents (incident_code, title, description, severity, category, status, detected_at) VALUES
	('INC-2409', 'Ransomware-like behavior blocked', 'Repeated file encryption behavior detected on FINANCE-LT-024.', 'critical', 'Endpoint protection', 'open', NOW() - INTERVAL 12 MINUTE),
	('INC-2408', 'Suspicious DNS traffic', 'Repeated lookups to a newly registered domain from Guest WiFi.', 'medium', 'Network monitoring', 'open', NOW() - INTERVAL 46 MINUTE),
	('INC-2407', 'Phishing page reported', 'Credential-harvesting page blocked for 3 users in the Sales group.', 'high', 'URL protection', 'in_progress', NOW() - INTERVAL 3 HOUR),
	('INC-2405', 'Endpoint signatures out of date', 'OPS-WS-117 has missed two scheduled signature updates.', 'low', 'Endpoint health', 'open', NOW() - INTERVAL 1 DAY)
ON DUPLICATE KEY UPDATE title = VALUES(title), description = VALUES(description), severity = VALUES(severity), category = VALUES(category);

INSERT INTO user_settings (user_id) SELECT id FROM users WHERE email = 'analyst@cybershield.local'
ON DUPLICATE KEY UPDATE user_id = VALUES(user_id);

INSERT INTO network_stats (id, connected_devices, active_connections, blocked_requests, inbound_tb, outbound_tb, network_health)
VALUES (1, 248, 1826, 37, 3.18, 5.24, 'Healthy')
ON DUPLICATE KEY UPDATE connected_devices = VALUES(connected_devices), active_connections = VALUES(active_connections), blocked_requests = VALUES(blocked_requests), inbound_tb = VALUES(inbound_tb), outbound_tb = VALUES(outbound_tb), network_health = VALUES(network_health);

INSERT INTO threat_regions (region_name, count_24h, count_7d, count_30d) VALUES
	('North America', 1284, 8240, 28410),
	('Eastern Europe', 936, 6932, 21244),
	('East Asia', 712, 5210, 17803),
	('South America', 408, 3176, 10691)
ON DUPLICATE KEY UPDATE count_24h = VALUES(count_24h), count_7d = VALUES(count_7d), count_30d = VALUES(count_30d);
