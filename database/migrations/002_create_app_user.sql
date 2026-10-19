-- =====================================================================
-- Cyber-Shield migration 002 - Least-privilege MySQL account for the web server
--
-- Run in MySQL Workbench while connected as root (or another admin account).
-- 1. Replace CHANGE_ME_STRONG_PASSWORD below with a long random password.
-- 2. Execute the script.
-- 3. Put the same user name and password in config.local.php (db_user / db_password).
--
-- The account can read and write Cyber-Shield data but cannot drop tables,
-- change the schema, or touch any other database.
-- =====================================================================

CREATE USER IF NOT EXISTS 'cyber_shield_app'@'localhost' IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON cyber_shield.* TO 'cyber_shield_app'@'localhost';
FLUSH PRIVILEGES;
