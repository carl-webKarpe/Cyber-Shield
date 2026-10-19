<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();
header('Content-Type: application/json; charset=utf-8');

function respond(array $data, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

try {
    require __DIR__ . '/db.php';
    $action = $_GET['action'] ?? '';
    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');
        $statement = $pdo->prepare('SELECT id, email, name, role, password_hash FROM users WHERE email = :email LIMIT 1');
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            respond(['ok' => false, 'message' => 'Email or password is incorrect.'], 401);
        }

        session_regenerate_id(true);
        $updateLogin = $pdo->prepare('UPDATE users SET last_login = NOW() WHERE id = :user_id');
        $updateLogin->execute(['user_id' => $user['id']]);
        $_SESSION['user'] = [
            'id' => (int) $user['id'],
            'email' => $user['email'],
            'name' => $user['name'],
            'role' => $user['role'],
        ];
        $_SESSION['last_activity'] = time();
        respond(['ok' => true, 'user' => $_SESSION['user']]);
    }

    if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $name = trim((string) ($input['name'] ?? ''));
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        if ($name === '' || strlen($name) > 100 || !filter_var($email, FILTER_VALIDATE_EMAIL)
            || strlen($email) > 190 || strlen($password) < 8 || strlen($password) > 4096) {
            respond(['ok' => false, 'message' => 'Enter a valid name and email, and a password of at least 8 characters.'], 422);
        }

        try {
            $statement = $pdo->prepare(
                "INSERT INTO users (name, email, password_hash, role) VALUES (:name, :email, :password_hash, 'analyst')"
            );
            $statement->execute([
                'name' => $name,
                'email' => $email,
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            ]);
        } catch (PDOException $error) {
            if ($error->getCode() === '23000') {
                respond(['ok' => false, 'message' => 'An account with this email already exists. Sign in instead.'], 409);
            }
            throw $error;
        }

        session_regenerate_id(true);
        $_SESSION['user'] = [
            'id' => (int) $pdo->lastInsertId(),
            'email' => $email,
            'name' => $name,
            'role' => 'analyst',
        ];
        $_SESSION['last_activity'] = time();
        respond(['ok' => true, 'user' => $_SESSION['user']]);
    }

    if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $cookie = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $cookie['path'], $cookie['domain'], $cookie['secure'], $cookie['httponly']);
        }
        session_destroy();
        respond(['ok' => true]);
    }

    if ($action === 'session' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        if (empty($_SESSION['user']['id']) || time() - (int) ($_SESSION['last_activity'] ?? 0) > 28800) {
            $_SESSION = [];
            session_destroy();
            respond(['ok' => true, 'user' => null]);
        }
        $_SESSION['last_activity'] = time();
        respond(['ok' => true, 'user' => $_SESSION['user']]);
    }

    if (empty($_SESSION['user']['id']) || time() - (int) ($_SESSION['last_activity'] ?? 0) > 28800) {
        $_SESSION = [];
        session_destroy();
        respond(['ok' => false, 'message' => 'Please sign in again.'], 401);
    }
    $_SESSION['last_activity'] = time();
    $userId = (int) $_SESSION['user']['id'];

    if ($action === 'profile' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $statement = $pdo->prepare(
            "SELECT name, email, role, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS createdAt,
                    DATE_FORMAT(last_login, '%Y-%m-%d %H:%i') AS lastLogin
             FROM users WHERE id = :user_id LIMIT 1"
        );
        $statement->execute(['user_id' => $userId]);
        $profile = $statement->fetch();
        if (!$profile) {
            respond(['ok' => false, 'message' => 'Account not found.'], 404);
        }
        respond(['ok' => true, 'user' => $profile]);
    }

    if ($action === 'incidents' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $incidents = $pdo->query(
            'SELECT id, incident_code AS code, title, description, severity, category, status, detected_at AS detectedAt
             FROM incidents
             ORDER BY detected_at DESC, id DESC'
        )->fetchAll();
        $counts = $pdo->query(
            "SELECT
                SUM(status IN ('open', 'in_progress')) AS open_count,
                SUM(severity = 'critical' AND status <> 'resolved') AS critical_count,
                SUM(status = 'in_progress') AS progress_count,
                SUM(status = 'resolved') AS resolved_count
             FROM incidents"
        )->fetch();

        respond([
            'ok' => true,
            'incidents' => $incidents,
            'incidentCounts' => $counts,
        ]);
    }

    if ($action === 'history' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $statement = $pdo->prepare(
            "SELECT id, name, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS date, scan_type AS type, result, status
             FROM scans WHERE user_id = :user_id ORDER BY created_at DESC, id DESC"
        );
        $statement->execute(['user_id' => $userId]);
        respond(['ok' => true, 'history' => $statement->fetchAll()]);
    }

    if ($action === 'delete-scan' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $scanId = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT);
        if (!$scanId) {
            respond(['ok' => false, 'message' => 'Invalid scan record.'], 422);
        }

        $statement = $pdo->prepare('DELETE FROM scans WHERE id = :id AND user_id = :user_id');
        $statement->execute([
            'id' => $scanId,
            'user_id' => $userId,
        ]);

        respond(['ok' => true]);
    }

    if ($action === 'dashboard' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $endpoints = $pdo->query(
            "SELECT device_name AS device, owner_name AS owner, platform, last_seen AS lastSeen, protection
             FROM endpoints ORDER BY device_name"
        )->fetchAll();
        $incidents = $pdo->query(
            "SELECT id, incident_code AS code, title, description, severity, category, status, detected_at AS detectedAt
             FROM incidents ORDER BY detected_at DESC"
        )->fetchAll();
        $incidentCounts = $pdo->query(
            "SELECT SUM(status IN ('open','in_progress')) AS open_count,
                    SUM(severity = 'critical' AND status <> 'resolved') AS critical_count,
                    SUM(status = 'in_progress') AS progress_count,
                    SUM(status = 'resolved' AND DATE(resolved_at) = CURDATE()) AS resolved_today
             FROM incidents"
        )->fetch();
        $network = $pdo->query('SELECT connected_devices, active_connections, blocked_requests, inbound_tb, outbound_tb, network_health FROM network_stats WHERE id = 1')->fetch();
        $regions = $pdo->query('SELECT region_name AS name, count_24h AS count24h, count_7d AS count7d, count_30d AS count30d FROM threat_regions ORDER BY count_24h DESC')->fetchAll();
        $activity = $pdo->prepare(
            'SELECT DATE_FORMAT(created_at, \'%Y-%m-%d\') AS scan_date, COUNT(*) AS scan_count
             FROM scans WHERE user_id = :user_id AND created_at >= CURDATE() - INTERVAL 6 DAY
             GROUP BY DATE(created_at) ORDER BY DATE(created_at)'
        );
        $activity->execute(['user_id' => $userId]);
        $settings = $pdo->prepare('SELECT realtime_protection, deep_scan, auto_quarantine, email_alerts, weekly_summary FROM user_settings WHERE user_id = :user_id LIMIT 1');
        $settings->execute(['user_id' => $userId]);
        $lastFileScan = $pdo->prepare("SELECT MAX(created_at) FROM scans WHERE user_id = :user_id AND scan_type = 'File'");
        $lastFileScan->execute(['user_id' => $userId]);
        respond([
            'ok' => true,
            'endpoints' => $endpoints,
            'incidents' => $incidents,
            'incidentCounts' => $incidentCounts,
            'network' => $network,
            'regions' => $regions,
            'scanActivity' => $activity->fetchAll(),
            'lastFileScan' => $lastFileScan->fetchColumn() ?: null,
            'settings' => $settings->fetch() ?: [],
        ]);
    }

    if ($action === 'threat-map' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        $range = strtolower(trim((string) ($_GET['range'] ?? '24h')));
        $allowedRanges = [
            '24h' => 'count_24h',
            '7d' => 'count_7d',
            '30d' => 'count_30d',
        ];
        $column = $allowedRanges[$range] ?? 'count_24h';
        $statement = $pdo->query(
            "SELECT region_name AS name, {$column} AS count
             FROM threat_regions
             ORDER BY {$column} DESC, region_name ASC"
        );

        $regions = [];
        foreach ($statement->fetchAll() as $row) {
            $regions[] = [
                'name' => (string) $row['name'],
                'count' => (int) $row['count'],
            ];
        }

        respond(['ok' => true, 'range' => $range, 'regions' => $regions]);
    }

    if ($action === 'save-scan' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $name = trim((string) ($input['name'] ?? ''));
        $type = (string) ($input['type'] ?? '');
        $result = trim((string) ($input['result'] ?? ''));
        $status = (string) ($input['status'] ?? '');

        $details = $input['details'] ?? null;
        if ($details !== null && !is_string($details)) {
            $details = json_encode($details, JSON_UNESCAPED_SLASHES);
        }

        if ($name === '' || mb_strlen($name) > 500 || !in_array($type, ['File', 'URL'], true)
            || $result === '' || mb_strlen($result) > 255
            || ($details !== null && strlen($details) > 65535)
            || !in_array($status, ['safe', 'suspicious', 'threat'], true)) {
            respond(['ok' => false, 'message' => 'Invalid scan record.'], 422);
        }

        $statement = $pdo->prepare(
            'INSERT INTO scans (user_id, name, scan_type, result, status, details) VALUES (:user_id, :name, :type, :result, :status, :details)'
        );
        $statement->execute([
            'user_id' => $userId,
            'name' => $name,
            'type' => $type,
            'result' => $result,
            'status' => $status,
            'details' => $details,
        ]);
        respond(['ok' => true]);
    }

    if ($action === 'resolve-incident' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $incidentId = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT);
        if (!$incidentId) {
            respond(['ok' => false, 'message' => 'Invalid incident.'], 422);
        }
        $statement = $pdo->prepare("UPDATE incidents SET status = 'resolved', resolved_at = NOW() WHERE id = :id AND status <> 'resolved'");
        $statement->execute(['id' => $incidentId]);
        respond(['ok' => true]);
    }

    if ($action === 'save-settings' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $keys = [
            'realtime_protection' => 'realtime_protection',
            'deep_scan' => 'deep_scan',
            'auto_quarantine' => 'auto_quarantine',
            'email_alerts' => 'email_alerts',
            'weekly_summary' => 'weekly_summary',
        ];
        $values = [];
        foreach ($keys as $key => $column) {
            $values[$column] = !empty($input[$key]) ? 1 : 0;
        }
        $statement = $pdo->prepare(
            'INSERT INTO user_settings (user_id, realtime_protection, deep_scan, auto_quarantine, email_alerts, weekly_summary)
             VALUES (:user_id, :realtime_protection, :deep_scan, :auto_quarantine, :email_alerts, :weekly_summary)
             ON DUPLICATE KEY UPDATE realtime_protection = VALUES(realtime_protection), deep_scan = VALUES(deep_scan),
             auto_quarantine = VALUES(auto_quarantine), email_alerts = VALUES(email_alerts), weekly_summary = VALUES(weekly_summary)'
        );
        $statement->execute(['user_id' => $userId] + $values);
        respond(['ok' => true]);
    }

    respond(['ok' => false, 'message' => 'Unknown action.'], 404);
} catch (Throwable $error) {
    error_log($error->getMessage());
    respond(['ok' => false, 'message' => 'The server could not complete the request. Check the database setup.'], 500);
}