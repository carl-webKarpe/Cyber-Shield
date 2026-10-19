<?php
/**
 * Cyber Shield
 * MySQL Database Connection
 *
 * XAMPP:
 * Host     = localhost
 * Database = cyber_shield
 * Username = root
 * Password = empty by default
 */

$host = getenv("DB_HOST") ?: "127.0.0.1";
$dbname = getenv("DB_NAME") ?: "cyber_shield";
$username = getenv("DB_USER") ?: "root";
$password = getenv("DB_PASSWORD") ?: "";

try {

    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $username,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );

} catch (PDOException $e) {
    throw new RuntimeException("Database connection failed.", 0, $e);
}
?>
