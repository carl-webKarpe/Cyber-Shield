<?php
/**
 * Cyber-Shield
 * MySQL Server connection (database administered with MySQL Workbench).
 *
 * Connection settings come from config.local.php or the DB_HOST, DB_PORT,
 * DB_NAME, DB_USER and DB_PASSWORD environment variables.
 */

require_once __DIR__ . '/includes/config.php';

$host = (string) cs_config('db_host');
$port = (int) cs_config('db_port');
$dbname = (string) cs_config('db_name');
$username = (string) cs_config('db_user');
$password = (string) cs_config('db_password');

try {

    $pdo = new PDO(
        "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
    $pdo->exec("SET time_zone = '" . date('P') . "'");

} catch (PDOException $e) {
    throw new RuntimeException("Cyber-Shield database connection failed.", 0, $e);
}
