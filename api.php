<?php
declare(strict_types=1);

/**
 * Cyber-Shield dashboard API (browser sessions).
 * Lab computer agents use agent_api.php instead.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function respond(array $data, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function require_permission(array $user, string $permission): void
{
    if (!cs_can($user['role'], $permission)) {
        respond(['ok' => false, 'message' => 'Your role does not have access to this feature.'], 403);
    }
}

function computer_online_sql(): string
{
    $window = max(30, (int) cs_config('agent_heartbeat_seconds') * 3);
    return "(lc.last_heartbeat IS NOT NULL AND lc.last_heartbeat >= NOW() - INTERVAL {$window} SECOND)";
}

try {
    require __DIR__ . '/includes/bootstrap.php';
    require __DIR__ . '/includes/virustotal.php';
    require __DIR__ . '/includes/scans.php';
    cs_start_session();

    $action = $_GET['action'] ?? '';
    $method = $_SERVER['REQUEST_METHOD'];
    $input = json_decode((string) file_get_contents('php://input'), true) ?? [];

    // Every state-changing request must carry the session's CSRF token.
    if ($method === 'POST' && !cs_csrf_valid()) {
        respond(['ok' => false, 'message' => 'Your session token is missing or expired. Reload the page and try again.'], 419);
    }

    if ($action === 'login' && $method === 'POST') {
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        $attempts = $pdo->prepare(
            "SELECT COUNT(*) FROM audit_logs WHERE ip_address = :ip AND action = 'auth.login_failed' AND created_at >= NOW() - INTERVAL 15 MINUTE"
        );
        $attempts->execute(['ip' => cs_client_ip()]);
        if ((int) $attempts->fetchColumn() >= 10) {
            respond(['ok' => false, 'message' => 'Too many failed sign-in attempts. Wait 15 minutes and try again.'], 429);
        }

        $statement = $pdo->prepare('SELECT id, email, name, role, is_active, password_hash FROM users WHERE email = :email LIMIT 1');
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();

        if (!$user || !password_verify($password, $user['password_hash']) || !(int) $user['is_active']) {
            cs_audit($pdo, 'auth.login_failed', 'Failed sign-in for ' . substr($email, 0, 190), ['user_id' => $user['id'] ?? null]);
            respond(['ok' => false, 'message' => 'Email or password is incorrect.'], 401);
        }

        session_regenerate_id(true);
        $updateLogin = $pdo->prepare('UPDATE users SET last_login = NOW() WHERE id = :user_id');
        $updateLogin->execute(['user_id' => $user['id']]);
        $_SESSION['user'] = [
            'id' => (int) $user['id'],
            'email' => $user['email'],
            'name' => $user['name'],
            'role' => cs_normalize_role($user['role']),
        ];
        $_SESSION['last_activity'] = time();
        unset($_SESSION['csrf_token']);
        cs_audit($pdo, 'auth.login', $user['email'] . ' signed in as ' . cs_role_label($user['role']), ['user_id' => (int) $user['id']]);
        respond(['ok' => true, 'user' => $_SESSION['user'], 'csrfToken' => cs_csrf_token()]);
    }

    if ($action === 'register' && $method === 'POST') {
        if (!cs_config('allow_registration')) {
            respond(['ok' => false, 'message' => 'Self-registration is disabled. Ask your Cyber-Shield Super Admin for an account.'], 403);
        }
        $name = trim((string) ($input['name'] ?? ''));
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = (string) ($input['password'] ?? '');

        if ($name === '' || strlen($name) > 100 || !filter_var($email, FILTER_VALIDATE_EMAIL)
            || strlen($email) > 190 || strlen($password) < 8 || strlen($password) > 4096) {
            respond(['ok' => false, 'message' => 'Enter a valid name and email, and a password of at least 8 characters.'], 422);
        }

        try {
            $statement = $pdo->prepare(
                "INSERT INTO users (name, email, password_hash, role) VALUES (:name, :email, :password_hash, 'admin')"
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
            'role' => 'admin',
        ];
        $_SESSION['last_activity'] = time();
        unset($_SESSION['csrf_token']);
        cs_audit($pdo, 'auth.register', $email . ' created an Admin account', ['user_id' => $_SESSION['user']['id']]);
        respond(['ok' => true, 'user' => $_SESSION['user'], 'csrfToken' => cs_csrf_token()]);
    }

    if ($action === 'logout' && $method === 'POST') {
        if (!empty($_SESSION['user']['id'])) {
            cs_audit($pdo, 'auth.logout', $_SESSION['user']['email'] . ' signed out', ['user_id' => (int) $_SESSION['user']['id']]);
        }
        cs_clear_session();
        respond(['ok' => true]);
    }

    if ($action === 'session' && $method === 'GET') {
        $user = cs_current_user($pdo);
        respond(['ok' => true, 'user' => $user]);
    }

    $user = cs_current_user($pdo);
    if ($user === null) {
        cs_clear_session();
        respond(['ok' => false, 'message' => 'Please sign in again.'], 401);
    }
    $userId = $user['id'];
    $role = $user['role'];

    if ($action === 'profile' && $method === 'GET') {
        $statement = $pdo->prepare(
            "SELECT name, email, role, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS createdAt,
                    DATE_FORMAT(last_login, '%Y-%m-%d %H:%i') AS lastLogin
             FROM users WHERE id = :id"
        );
        $statement->execute(['id' => $userId]);
        $profile = $statement->fetch();
        $profile['role'] = cs_role_label($profile['role']);
        respond(['ok' => true, 'user' => $profile]);
    }

    if ($action === 'incidents' && $method === 'GET') {
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

    if ($action === 'computers' && $method === 'GET') {
        require_permission($user, 'monitor_computers');
        respond(['ok' => true, 'computers' => load_computers($pdo)]);
    }

    if ($action === 'computer-authorize' && $method === 'POST') {
        require_permission($user, 'manage_computers');
        $computerId = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT);
        $authorize = !empty($input['authorized']);
        if (!$computerId) {
            respond(['ok' => false, 'message' => 'Invalid computer.'], 422);
        }
        $statement = $pdo->prepare(
            'UPDATE lab_computers SET is_authorized = :authorized, authorized_by = :user_id,
             authorized_at = IF(:authorized_again = 1, NOW(), NULL) WHERE id = :id'
        );
        $statement->execute([
            'authorized' => $authorize ? 1 : 0,
            'authorized_again' => $authorize ? 1 : 0,
            'user_id' => $authorize ? $userId : null,
            'id' => $computerId,
        ]);
        if ($statement->rowCount() === 0) {
            respond(['ok' => false, 'message' => 'Computer not found or already in that state.'], 404);
        }
        $hostname = $pdo->prepare('SELECT hostname FROM lab_computers WHERE id = :id');
        $hostname->execute(['id' => $computerId]);
        cs_audit(
            $pdo,
            $authorize ? 'computer.authorized' : 'computer.revoked',
            sprintf('%s %s lab computer %s', $user['email'], $authorize ? 'authorized' : 'revoked', $hostname->fetchColumn()),
            ['user_id' => $userId, 'computer_id' => $computerId]
        );
        respond(['ok' => true]);
    }

    if ($action === 'file-events' && $method === 'GET') {
        require_permission($user, 'view_file_activity');
        $limit = min(500, max(1, (int) ($_GET['limit'] ?? 200)));
        $conditions = [];
        $params = [];
        $computerId = filter_var($_GET['computer_id'] ?? null, FILTER_VALIDATE_INT);
        if ($computerId) {
            $conditions[] = 'fe.computer_id = :computer_id';
            $params['computer_id'] = $computerId;
        }
        $eventType = (string) ($_GET['type'] ?? '');
        if (in_array($eventType, ['created', 'modified', 'deleted', 'moved'], true)) {
            $conditions[] = 'fe.event_type = :event_type';
            $params['event_type'] = $eventType;
        }
        $search = trim((string) ($_GET['q'] ?? ''));
        if ($search !== '') {
            $conditions[] = '(fe.file_path LIKE :search_path OR fe.sha256 = :search_hash OR lc.hostname LIKE :search_host)';
            $like = '%' . addcslashes($search, '%_\\') . '%';
            $params += ['search_path' => $like, 'search_hash' => strtolower($search), 'search_host' => $like];
        }
        $where = $conditions ? 'WHERE ' . implode(' AND ', $conditions) : '';
        $statement = $pdo->prepare(
            "SELECT fe.id, fe.computer_id AS computerId, lc.hostname AS computer, fe.event_type AS eventType, fe.file_path AS filePath,
                    fe.file_name AS fileName, fe.file_size AS fileSize, fe.sha256, fe.detected_at AS detectedAt, fe.received_at AS receivedAt,
                    (SELECT sq.id FROM scan_requests sq
                     WHERE sq.file_event_id = fe.id OR (fe.sha256 IS NOT NULL AND sq.sha256 = fe.sha256 AND sq.source <> 'url')
                     ORDER BY sq.id DESC LIMIT 1) AS scanRequestId
             FROM file_events fe
             JOIN lab_computers lc ON lc.id = fe.computer_id
             {$where}
             ORDER BY fe.detected_at DESC, fe.id DESC
             LIMIT {$limit}"
        );
        $statement->execute($params);
        $events = $statement->fetchAll();

        $scanIds = array_values(array_unique(array_filter(array_map(fn ($event) => (int) $event['scanRequestId'], $events))));
        $scans = [];
        if ($scanIds) {
            $placeholders = implode(',', array_fill(0, count($scanIds), '?'));
            $scanStatement = $pdo->prepare(
                "SELECT sq.id, sq.status, sr.risk_level AS riskLevel, sr.detection_ratio AS detectionRatio
                 FROM scan_requests sq LEFT JOIN scan_results sr ON sr.scan_request_id = sq.id WHERE sq.id IN ({$placeholders})"
            );
            $scanStatement->execute($scanIds);
            foreach ($scanStatement->fetchAll() as $row) {
                $scans[(int) $row['id']] = $row;
            }
        }
        foreach ($events as &$event) {
            $event['scan'] = $scans[(int) $event['scanRequestId']] ?? null;
            unset($event['scanRequestId']);
        }
        unset($event);

        $summary = $pdo->query(
            "SELECT COUNT(*) AS total24h,
                    SUM(event_type = 'created') AS created24h,
                    SUM(event_type = 'modified') AS modified24h,
                    SUM(event_type = 'deleted') AS deleted24h
             FROM file_events WHERE detected_at >= NOW() - INTERVAL 1 DAY"
        )->fetch();
        respond(['ok' => true, 'events' => $events, 'summary' => $summary, 'canScan' => cs_can($role, 'scan_files')]);
    }

    if ($action === 'audit-logs' && $method === 'GET') {
        require_permission($user, 'view_audit_logs');
        $limit = min(500, max(1, (int) ($_GET['limit'] ?? 200)));
        $statement = $pdo->query(
            "SELECT al.id, al.actor_type AS actorType, al.action, al.details, al.ip_address AS ipAddress, al.created_at AS createdAt,
                    u.name AS userName, lc.hostname AS computer
             FROM audit_logs al
             LEFT JOIN users u ON u.id = al.user_id
             LEFT JOIN lab_computers lc ON lc.id = al.computer_id
             ORDER BY al.id DESC LIMIT {$limit}"
        );
        respond(['ok' => true, 'logs' => $statement->fetchAll()]);
    }

    if ($action === 'users' && $method === 'GET') {
        require_permission($user, 'view_audit_logs');
        $users = $pdo->query(
            'SELECT id, name, email, role, is_active AS isActive, created_at AS createdAt, last_login AS lastLogin FROM users ORDER BY name'
        )->fetchAll();
        foreach ($users as &$row) {
            $row['role'] = cs_role_label($row['role']);
        }
        unset($row);
        respond(['ok' => true, 'users' => $users]);
    }

    if ($action === 'history' && $method === 'GET') {
        require_permission($user, 'view_scan_results');
        $statement = $pdo->prepare(
            "SELECT id, scan_request_id AS scanRequestId, name, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') AS date, scan_type AS type, result, status, sha256
             FROM scans WHERE user_id = :user_id ORDER BY created_at DESC, id DESC"
        );
        $statement->execute(['user_id' => $userId]);
        respond(['ok' => true, 'history' => $statement->fetchAll()]);
    }

    if ($action === 'delete-scan' && $method === 'POST') {
        require_permission($user, 'scan_files');
        $scanId = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT);
        if (!$scanId) {
            respond(['ok' => false, 'message' => 'Invalid scan record.'], 422);
        }

        $statement = $pdo->prepare('DELETE FROM scans WHERE id = :id AND user_id = :user_id');
        $statement->execute([
            'id' => $scanId,
            'user_id' => $userId,
        ]);
        if ($statement->rowCount() > 0) {
            cs_audit($pdo, 'scan.history_deleted', $user['email'] . ' deleted scan history record #' . $scanId, ['user_id' => $userId]);
        }

        respond(['ok' => true]);
    }

    if ($action === 'dashboard' && $method === 'GET') {
        $computers = load_computers($pdo);
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
        $settings = $pdo->prepare('SELECT realtime_protection, deep_scan, auto_quarantine, email_alerts, weekly_summary FROM user_settings WHERE user_id = :user_id LIMIT 1');
        $settings->execute(['user_id' => $userId]);
        $fileActivity = $pdo->query(
            "SELECT COUNT(*) AS events24h, COUNT(DISTINCT computer_id) AS activeComputers24h
             FROM file_events WHERE detected_at >= NOW() - INTERVAL 1 DAY"
        )->fetch();
        $recentEvents = $pdo->query(
            "SELECT fe.event_type AS eventType, fe.file_name AS fileName, fe.detected_at AS detectedAt, lc.hostname AS computer
             FROM file_events fe JOIN lab_computers lc ON lc.id = fe.computer_id
             ORDER BY fe.detected_at DESC, fe.id DESC LIMIT 5"
        )->fetchAll();

        $data = [
            'ok' => true,
            'role' => $role,
            'computers' => $computers,
            'incidents' => $incidents,
            'incidentCounts' => $incidentCounts,
            'network' => $network,
            'regions' => $regions,
            'fileActivity' => $fileActivity,
            'recentFileEvents' => $recentEvents,
            'settings' => $settings->fetch() ?: [],
            'virusTotalConfigured' => trim((string) cs_config('virustotal_api_key')) !== '',
        ];
        if (cs_can($role, 'view_scan_results')) {
            $activity = $pdo->prepare(
                'SELECT DATE_FORMAT(created_at, \'%Y-%m-%d\') AS scan_date, COUNT(*) AS scan_count
                 FROM scans WHERE user_id = :user_id AND created_at >= CURDATE() - INTERVAL 6 DAY
                 GROUP BY DATE_FORMAT(created_at, \'%Y-%m-%d\') ORDER BY scan_date'
            );
            $activity->execute(['user_id' => $userId]);
            $lastFileScan = $pdo->prepare("SELECT MAX(created_at) FROM scans WHERE user_id = :user_id AND scan_type = 'File'");
            $lastFileScan->execute(['user_id' => $userId]);
            $data['scanActivity'] = $activity->fetchAll();
            $data['lastFileScan'] = $lastFileScan->fetchColumn() ?: null;
        }
        respond($data);
    }

    if ($action === 'threat-map' && $method === 'GET') {
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

    if ($action === 'scan-file' && $method === 'POST') {
        require_permission($user, 'scan_files');
        $upload = $_FILES['file'] ?? null;
        $maxBytes = (int) cs_config('virustotal_max_upload_bytes');
        if (!$upload || !is_array($upload) || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file($upload['tmp_name'])) {
            $tooBig = in_array($upload['error'] ?? null, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true);
            respond(['ok' => false, 'message' => $tooBig
                ? 'The file is larger than the server upload limit (upload_max_filesize in php.ini).'
                : 'No file was received. Choose a file and try again.'], 422);
        }
        if ((int) $upload['size'] === 0 || (int) $upload['size'] > $maxBytes) {
            respond(['ok' => false, 'message' => sprintf('Files must be between 1 byte and %d MB.', intdiv($maxBytes, 1048576))], 422);
        }
        $vt = CyberShieldVirusTotal::fromConfig();
        $fileName = substr(basename(str_replace('\\', '/', (string) $upload['name'])), 0, 255) ?: 'upload.bin';
        $sha256 = hash_file('sha256', $upload['tmp_name']);
        $request = cs_create_scan_request($pdo, ['source' => 'upload', 'target_name' => $fileName, 'sha256' => $sha256], $userId);
        cs_audit($pdo, 'scan.requested', sprintf('%s requested a VirusTotal scan of uploaded file %s (SHA-256 %s)', $user['email'], $fileName, $sha256), ['user_id' => $userId]);
        try {
            cs_lookup_hash($pdo, $vt, $request);
            $request = cs_get_scan_request($pdo, (int) $request['id']);
            if ($request['status'] === 'not_found') {
                cs_submit_file($pdo, $vt, $request, $upload['tmp_name']);
            }
        } catch (CyberShieldVirusTotalException $error) {
            cs_update_scan_request($pdo, (int) $request['id'], 'failed', ['error' => $error->getMessage()]);
        } finally {
            @unlink($upload['tmp_name']);
        }
        respond(['ok' => true, 'scan' => cs_scan_payload($pdo, (int) $request['id'])]);
    }

    if ($action === 'scan-url' && $method === 'POST') {
        require_permission($user, 'scan_files');
        $url = trim((string) ($input['url'] ?? ''));
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'http://' . $url;
        }
        if (strlen($url) > 500 || !filter_var($url, FILTER_VALIDATE_URL) || !preg_match('#^https?://#i', $url)) {
            respond(['ok' => false, 'message' => 'Enter a valid http or https URL (500 characters or fewer).'], 422);
        }
        $vt = CyberShieldVirusTotal::fromConfig();
        $request = cs_create_scan_request($pdo, ['source' => 'url', 'target_name' => $url], $userId);
        cs_audit($pdo, 'scan.requested', $user['email'] . ' requested a VirusTotal URL scan of ' . $url, ['user_id' => $userId]);
        try {
            $report = $vt->getUrlReport($url);
            if ($report !== null) {
                cs_store_scan_result($pdo, $request, cs_summarize_vt($report['data']['attributes'] ?? [], 'url', $url));
            } else {
                cs_update_scan_request($pdo, (int) $request['id'], 'submitted', ['analysis_id' => $vt->submitUrl($url)]);
            }
        } catch (CyberShieldVirusTotalException $error) {
            cs_update_scan_request($pdo, (int) $request['id'], 'failed', ['error' => $error->getMessage()]);
        }
        respond(['ok' => true, 'scan' => cs_scan_payload($pdo, (int) $request['id'])]);
    }

    if ($action === 'scan-event' && $method === 'POST') {
        require_permission($user, 'scan_files');
        $eventId = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT);
        $statement = $pdo->prepare(
            'SELECT fe.id, fe.computer_id, fe.file_path, fe.file_name, fe.sha256, lc.hostname
             FROM file_events fe JOIN lab_computers lc ON lc.id = fe.computer_id WHERE fe.id = :id'
        );
        $statement->execute(['id' => $eventId ?: 0]);
        $event = $statement->fetch();
        if (!$event) {
            respond(['ok' => false, 'message' => 'File event not found.'], 404);
        }
        if (!$event['sha256']) {
            respond(['ok' => false, 'message' => 'The agent did not report a SHA-256 hash for this event (the file was deleted, locked, or larger than the agent hashing limit), so it cannot be scanned.'], 422);
        }
        $vt = CyberShieldVirusTotal::fromConfig();
        $request = cs_create_scan_request($pdo, [
            'source' => 'file_event',
            'computer_id' => (int) $event['computer_id'],
            'file_event_id' => (int) $event['id'],
            'target_name' => $event['file_name'],
            'file_path' => $event['file_path'],
            'sha256' => $event['sha256'],
        ], $userId);
        cs_audit(
            $pdo,
            'scan.requested',
            sprintf('%s requested a VirusTotal hash lookup of %s on %s', $user['email'], $event['file_path'], $event['hostname']),
            ['user_id' => $userId, 'computer_id' => (int) $event['computer_id']]
        );
        try {
            cs_lookup_hash($pdo, $vt, $request);
        } catch (CyberShieldVirusTotalException $error) {
            cs_update_scan_request($pdo, (int) $request['id'], 'failed', ['error' => $error->getMessage()]);
        }
        respond(['ok' => true, 'scan' => cs_scan_payload($pdo, (int) $request['id'])]);
    }

    if ($action === 'request-upload' && $method === 'POST') {
        require_permission($user, 'scan_files');
        $requestId = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT);
        $request = $requestId ? cs_get_scan_request($pdo, $requestId) : null;
        if (!$request || $request['source'] !== 'file_event' || !$request['computer_id']
            || !in_array($request['status'], ['not_found', 'failed'], true)) {
            respond(['ok' => false, 'message' => 'Only lab-computer files that VirusTotal has not seen can be requested for upload.'], 422);
        }
        cs_update_scan_request($pdo, (int) $request['id'], 'awaiting_upload');
        cs_audit(
            $pdo,
            'scan.upload_requested',
            sprintf('%s asked %s to upload %s for VirusTotal analysis', $user['email'], $request['hostname'], $request['file_path']),
            ['user_id' => $userId, 'computer_id' => (int) $request['computer_id']]
        );
        respond(['ok' => true, 'scan' => cs_scan_payload($pdo, (int) $request['id'])]);
    }

    if ($action === 'scan-status' && $method === 'GET') {
        require_permission($user, 'view_scan_results');
        $requestId = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT);
        $request = $requestId ? cs_get_scan_request($pdo, $requestId) : null;
        if (!$request) {
            respond(['ok' => false, 'message' => 'Scan not found.'], 404);
        }
        if ($request['status'] === 'submitted') {
            try {
                if (cs_refresh_scan($pdo, CyberShieldVirusTotal::fromConfig(), $request)) {
                    cs_audit($pdo, 'scan.completed', sprintf('VirusTotal analysis finished for %s', $request['target_name']), ['computer_id' => $request['computer_id']]);
                }
            } catch (CyberShieldVirusTotalException $error) {
                if ($error->httpStatus !== 429) {
                    cs_update_scan_request($pdo, (int) $request['id'], 'failed', ['error' => $error->getMessage()]);
                }
            }
        }
        respond(['ok' => true, 'scan' => cs_scan_payload($pdo, (int) $request['id'])]);
    }

    if ($action === 'scan-requests' && $method === 'GET') {
        require_permission($user, 'view_scan_results');
        $ids = $pdo->query('SELECT id FROM scan_requests ORDER BY id DESC LIMIT 100')->fetchAll(PDO::FETCH_COLUMN);
        respond(['ok' => true, 'scans' => array_map(fn ($id) => cs_scan_payload($pdo, (int) $id), $ids)]);
    }

    if ($action === 'resolve-incident' && $method === 'POST') {
        require_permission($user, 'manage_incidents');
        $incidentId = filter_var($input['id'] ?? null, FILTER_VALIDATE_INT);
        if (!$incidentId) {
            respond(['ok' => false, 'message' => 'Invalid incident.'], 422);
        }
        $statement = $pdo->prepare("UPDATE incidents SET status = 'resolved', resolved_at = NOW() WHERE id = :id AND status <> 'resolved'");
        $statement->execute(['id' => $incidentId]);
        if ($statement->rowCount() > 0) {
            cs_audit($pdo, 'incident.resolved', $user['email'] . ' resolved incident #' . $incidentId, ['user_id' => $userId]);
        }
        respond(['ok' => true]);
    }

    if ($action === 'save-settings' && $method === 'POST') {
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
} catch (CyberShieldVirusTotalException $error) {
    respond(['ok' => false, 'message' => $error->getMessage()], 503);
} catch (Throwable $error) {
    if (function_exists('cs_log')) {
        cs_log('ERROR', $error->getMessage() . ' @ ' . $error->getFile() . ':' . $error->getLine());
    } else {
        error_log('[Cyber-Shield] ' . $error->getMessage());
    }
    respond(['ok' => false, 'message' => 'The server could not complete the request. Check the database setup.'], 500);
}

function load_computers(PDO $pdo): array
{
    $online = computer_online_sql();
    $rows = $pdo->query(
        "SELECT lc.id, lc.hostname, lc.lab_location AS labLocation, lc.ip_address AS ipAddress, lc.mac_address AS macAddress,
                lc.os_version AS os, lc.agent_version AS agentVersion, lc.connection_type AS connectionType,
                lc.is_authorized AS authorized, lc.registered_at AS registeredAt, lc.last_heartbeat AS lastHeartbeat,
                {$online} AS online,
                (SELECT COUNT(*) FROM file_events fe WHERE fe.computer_id = lc.id AND fe.detected_at >= NOW() - INTERVAL 1 DAY) AS events24h,
                (SELECT COUNT(*) FROM scan_requests sq JOIN scan_results sr ON sr.scan_request_id = sq.id
                 WHERE sq.computer_id = lc.id AND sr.risk_level IN ('high', 'critical')) AS threats
         FROM lab_computers lc
         ORDER BY lc.hostname"
    )->fetchAll();
    foreach ($rows as &$row) {
        $row['id'] = (int) $row['id'];
        $row['authorized'] = (bool) $row['authorized'];
        $row['online'] = (bool) $row['online'];
        $row['events24h'] = (int) $row['events24h'];
        $row['threats'] = (int) $row['threats'];
    }
    return $rows;
}
