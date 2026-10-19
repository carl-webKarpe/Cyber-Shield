<?php
declare(strict_types=1);

/**
 * Cyber-Shield database check, run by START_CYBER_SHIELD.bat.
 * Exit code 0 = connected and migrated, 1 = connection failed, 2 = migration missing.
 */
if (PHP_SAPI !== 'cli') {
    exit(1);
}
try {
    require dirname(__DIR__) . '/includes/config.php';
    require dirname(__DIR__) . '/db.php';
    $version = $pdo->query('SELECT VERSION()')->fetchColumn();
    echo "[Cyber-Shield] Connected to MySQL Server {$version} (database " . cs_config('db_name') . ")\n";
    $missing = [];
    foreach (['users', 'scans', 'lab_computers', 'file_events', 'scan_requests', 'scan_results', 'audit_logs'] as $table) {
        $statement = $pdo->prepare('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t');
        $statement->execute(['t' => $table]);
        if (!(int) $statement->fetchColumn()) {
            $missing[] = $table;
        }
    }
    if ($missing) {
        echo "[Cyber-Shield] Missing tables: " . implode(', ', $missing) . "\n";
        echo "[Cyber-Shield] Run users.sql and database/migrations/001_cyber_shield_lab_monitoring.sql in MySQL Workbench.\n";
        exit(2);
    }
    if (trim((string) cs_config('virustotal_api_key')) === '') {
        echo "[Cyber-Shield] WARNING: virustotal_api_key is empty - file and URL scanning will be unavailable.\n";
    }
    if (strlen((string) cs_config('agent_enrollment_key')) < 16) {
        echo "[Cyber-Shield] WARNING: agent_enrollment_key is not set - lab computer agents cannot register.\n";
    }
    exit(0);
} catch (Throwable $error) {
    $previous = $error->getPrevious();
    echo "[Cyber-Shield] Database connection FAILED: " . ($previous ? $previous->getMessage() : $error->getMessage()) . "\n";
    echo "[Cyber-Shield] Check that MySQL Server is running and the db_* settings in config.local.php are correct.\n";
    exit(1);
}
