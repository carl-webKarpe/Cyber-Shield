<?php
declare(strict_types=1);

/**
 * Cyber-Shield agent API - used only by the Python monitoring agent on lab computers.
 *
 * Registration is protected by the shared enrollment key. After registering, each
 * agent signs every request with its own secret (HMAC-SHA256), so the secret is
 * never sent over the network again and captured requests cannot be altered.
 *
 * Signature = hex(HMAC_SHA256(agent_secret, agent_uuid + "\n" + timestamp + "\n" + query_string + "\n" + sha256(body)))
 * where body is the raw request body, or the uploaded file's bytes for upload-file.
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

const CS_AGENT_SIGNATURE_WINDOW = 300;
const CS_AGENT_MAX_EVENTS = 200;

function agent_respond(array $data, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function agent_text($value, int $max): ?string
{
    if ($value === null) {
        return null;
    }
    $text = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', (string) $value) ?? '');
    return $text === '' ? null : mb_substr($text, 0, $max);
}

function agent_connection_type($value): string
{
    return in_array($value, ['ethernet', 'wifi', 'hotspot'], true) ? $value : 'unknown';
}

function agent_ip($reported): string
{
    $reported = (string) $reported;
    return filter_var($reported, FILTER_VALIDATE_IP) ? $reported : cs_client_ip();
}

/** Verifies the HMAC signature and returns the calling computer. */
function agent_authenticate(PDO $pdo, string $bodyHash): array
{
    $uuid = strtolower((string) ($_SERVER['HTTP_X_CYBERSHIELD_AGENT'] ?? ''));
    $timestamp = (string) ($_SERVER['HTTP_X_CYBERSHIELD_TIMESTAMP'] ?? '');
    $signature = strtolower((string) ($_SERVER['HTTP_X_CYBERSHIELD_SIGNATURE'] ?? ''));
    if (!preg_match('/^[0-9a-f-]{36}$/', $uuid) || !ctype_digit($timestamp) || !preg_match('/^[0-9a-f]{64}$/', $signature)) {
        agent_respond(['ok' => false, 'message' => 'Missing Cyber-Shield agent credentials.'], 401);
    }
    if (abs(time() - (int) $timestamp) > CS_AGENT_SIGNATURE_WINDOW) {
        agent_respond(['ok' => false, 'message' => 'Request timestamp is outside the allowed window. Check the lab computer clock.'], 401);
    }
    $statement = $pdo->prepare('SELECT * FROM lab_computers WHERE agent_uuid = :uuid LIMIT 1');
    $statement->execute(['uuid' => $uuid]);
    $computer = $statement->fetch();
    if (!$computer) {
        agent_respond(['ok' => false, 'message' => 'Unknown agent. Register again.', 'reregister' => true], 401);
    }
    $payload = $uuid . "\n" . $timestamp . "\n" . (string) ($_SERVER['QUERY_STRING'] ?? '') . "\n" . $bodyHash;
    if (!hash_equals(hash_hmac('sha256', $payload, $computer['agent_secret']), $signature)) {
        agent_respond(['ok' => false, 'message' => 'Invalid request signature. Register again.', 'reregister' => true], 401);
    }
    return $computer;
}

function agent_require_authorized(array $computer): void
{
    if (!(int) $computer['is_authorized']) {
        agent_respond(['ok' => false, 'message' => 'This computer is waiting for Super Admin approval.', 'authorized' => false], 403);
    }
}

try {
    require __DIR__ . '/includes/bootstrap.php';
    require __DIR__ . '/includes/virustotal.php';
    require __DIR__ . '/includes/scans.php';

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        agent_respond(['ok' => false, 'message' => 'Cyber-Shield agent API expects POST requests.'], 405);
    }
    $action = (string) ($_GET['action'] ?? '');
    $rawBody = (string) file_get_contents('php://input');
    $input = json_decode($rawBody, true) ?? [];
    $heartbeatSeconds = max(10, (int) cs_config('agent_heartbeat_seconds'));

    if ($action === 'ping') {
        agent_respond(['ok' => true, 'server' => CS_APP_NAME, 'version' => CS_VERSION]);
    }

    if ($action === 'register') {
        $configuredKey = (string) cs_config('agent_enrollment_key');
        $sentKey = (string) ($_SERVER['HTTP_X_CYBERSHIELD_ENROLLMENT_KEY'] ?? '');
        if (strlen($configuredKey) < 16) {
            agent_respond(['ok' => false, 'message' => 'The server has no agent_enrollment_key configured (minimum 16 characters).'], 503);
        }
        if (!hash_equals($configuredKey, $sentKey)) {
            cs_audit($pdo, 'agent.register_rejected', 'Agent registration with an invalid enrollment key', ['actor_type' => 'agent']);
            agent_respond(['ok' => false, 'message' => 'Invalid enrollment key.'], 403);
        }
        $uuid = strtolower((string) ($input['agent_uuid'] ?? ''));
        $hostname = agent_text($input['hostname'] ?? null, 255);
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $uuid) || $hostname === null) {
            agent_respond(['ok' => false, 'message' => 'agent_uuid and hostname are required.'], 422);
        }
        $mac = strtoupper((string) ($input['mac_address'] ?? ''));
        $secret = bin2hex(random_bytes(32));
        $autoAuthorize = (bool) cs_config('agent_auto_authorize');
        $fields = [
            'hostname' => $hostname,
            'lab_location' => agent_text($input['lab_location'] ?? null, 120),
            'ip_address' => agent_ip($input['ip_address'] ?? ''),
            'mac_address' => preg_match('/^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$/', $mac) ? str_replace('-', ':', $mac) : null,
            'os_version' => agent_text($input['os_version'] ?? null, 160),
            'agent_version' => agent_text($input['agent_version'] ?? null, 20),
            'connection_type' => agent_connection_type($input['connection_type'] ?? ''),
            'agent_secret' => $secret,
            'is_authorized' => $autoAuthorize ? 1 : 0,
            'watched_paths' => json_encode(array_slice(array_map('strval', (array) ($input['watched_paths'] ?? [])), 0, 50)),
        ];

        $existing = $pdo->prepare('SELECT id FROM lab_computers WHERE agent_uuid = :uuid');
        $existing->execute(['uuid' => $uuid]);
        $computerId = $existing->fetchColumn();
        if ($computerId) {
            // Re-registering issues a new secret and, unless auto-authorize is on, requires approval again.
            $statement = $pdo->prepare(
                'UPDATE lab_computers SET hostname = :hostname, lab_location = :lab_location, ip_address = :ip_address,
                 mac_address = :mac_address, os_version = :os_version, agent_version = :agent_version,
                 connection_type = :connection_type, agent_secret = :agent_secret, is_authorized = :is_authorized,
                 watched_paths = :watched_paths, last_heartbeat = NOW() WHERE id = :id'
            );
            $statement->execute($fields + ['id' => $computerId]);
            $event = 'agent.reregistered';
        } else {
            $statement = $pdo->prepare(
                'INSERT INTO lab_computers (agent_uuid, hostname, lab_location, ip_address, mac_address, os_version, agent_version,
                 connection_type, agent_secret, is_authorized, watched_paths, last_heartbeat)
                 VALUES (:agent_uuid, :hostname, :lab_location, :ip_address, :mac_address, :os_version, :agent_version,
                 :connection_type, :agent_secret, :is_authorized, :watched_paths, NOW())'
            );
            $statement->execute($fields + ['agent_uuid' => $uuid]);
            $computerId = $pdo->lastInsertId();
            $event = 'agent.registered';
        }
        cs_audit(
            $pdo,
            $event,
            sprintf('Lab computer %s (%s, %s) registered%s', $hostname, $fields['ip_address'], $fields['connection_type'], $autoAuthorize ? ' and was auto-authorized' : ' - awaiting approval'),
            ['actor_type' => 'agent', 'computer_id' => (int) $computerId]
        );
        agent_respond([
            'ok' => true,
            'computer_id' => (int) $computerId,
            'agent_secret' => $secret,
            'authorized' => $autoAuthorize,
            'heartbeat_seconds' => $heartbeatSeconds,
        ]);
    }

    if ($action === 'upload-file') {
        $upload = $_FILES['file'] ?? null;
        if (!$upload || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file($upload['tmp_name'])) {
            agent_respond(['ok' => false, 'message' => 'No file received (check upload_max_filesize on the server).'], 422);
        }
        $fileHash = hash_file('sha256', $upload['tmp_name']);
        $computer = agent_authenticate($pdo, $fileHash);
        agent_require_authorized($computer);
        $requestId = filter_var($_GET['request_id'] ?? null, FILTER_VALIDATE_INT);
        $request = $requestId ? cs_get_scan_request($pdo, $requestId) : null;
        try {
            if (!$request || (int) $request['computer_id'] !== (int) $computer['id'] || $request['status'] !== 'awaiting_upload') {
                agent_respond(['ok' => false, 'message' => 'No pending upload request matches this file.'], 404);
            }
            if (!hash_equals((string) $request['sha256'], $fileHash)) {
                cs_update_scan_request($pdo, (int) $request['id'], 'failed', ['error' => 'The file changed on the lab computer after the event was recorded.']);
                agent_respond(['ok' => false, 'message' => 'File hash does not match the scan request.'], 409);
            }
            if ((int) $upload['size'] > (int) cs_config('virustotal_max_upload_bytes')) {
                cs_update_scan_request($pdo, (int) $request['id'], 'failed', ['error' => 'The file is larger than the configured VirusTotal upload limit.']);
                agent_respond(['ok' => false, 'message' => 'File too large.'], 413);
            }
            try {
                cs_submit_file($pdo, CyberShieldVirusTotal::fromConfig(), $request, $upload['tmp_name']);
            } catch (CyberShieldVirusTotalException $error) {
                cs_update_scan_request($pdo, (int) $request['id'], 'failed', ['error' => $error->getMessage()]);
                agent_respond(['ok' => false, 'message' => $error->getMessage()], 502);
            }
            cs_audit(
                $pdo,
                'scan.file_uploaded',
                sprintf('%s uploaded %s for VirusTotal analysis', $computer['hostname'], $request['file_path']),
                ['actor_type' => 'agent', 'computer_id' => (int) $computer['id']]
            );
            agent_respond(['ok' => true]);
        } finally {
            @unlink($upload['tmp_name']);
        }
    }

    $computer = agent_authenticate($pdo, hash('sha256', $rawBody));
    $computerId = (int) $computer['id'];

    if ($action === 'heartbeat') {
        $wasOffline = !$computer['last_heartbeat'] || strtotime($computer['last_heartbeat']) < time() - $heartbeatSeconds * 3;
        $statement = $pdo->prepare(
            'UPDATE lab_computers SET last_heartbeat = NOW(), ip_address = :ip_address, connection_type = :connection_type,
             agent_version = COALESCE(:agent_version, agent_version), os_version = COALESCE(:os_version, os_version),
             watched_paths = COALESCE(:watched_paths, watched_paths) WHERE id = :id'
        );
        $statement->execute([
            'ip_address' => agent_ip($input['ip_address'] ?? ''),
            'connection_type' => agent_connection_type($input['connection_type'] ?? ''),
            'agent_version' => agent_text($input['agent_version'] ?? null, 20),
            'os_version' => agent_text($input['os_version'] ?? null, 160),
            'watched_paths' => isset($input['watched_paths'])
                ? json_encode(array_slice(array_map('strval', (array) $input['watched_paths']), 0, 50)) : null,
            'id' => $computerId,
        ]);
        if ($wasOffline) {
            cs_audit($pdo, 'computer.online', $computer['hostname'] . ' is online', ['actor_type' => 'agent', 'computer_id' => $computerId]);
        }
        $uploads = [];
        if ((int) $computer['is_authorized']) {
            $pending = $pdo->prepare(
                "SELECT id AS request_id, file_path, sha256 FROM scan_requests
                 WHERE computer_id = :id AND status = 'awaiting_upload' ORDER BY id LIMIT 5"
            );
            $pending->execute(['id' => $computerId]);
            $uploads = $pending->fetchAll();
            foreach ($uploads as &$upload) {
                $upload['request_id'] = (int) $upload['request_id'];
            }
            unset($upload);
        }
        agent_respond([
            'ok' => true,
            'authorized' => (bool) (int) $computer['is_authorized'],
            'heartbeat_seconds' => $heartbeatSeconds,
            'upload_requests' => $uploads,
            'max_upload_bytes' => (int) cs_config('virustotal_max_upload_bytes'),
        ]);
    }

    if ($action === 'file-events') {
        agent_require_authorized($computer);
        $events = $input['events'] ?? null;
        if (!is_array($events) || count($events) > CS_AGENT_MAX_EVENTS) {
            agent_respond(['ok' => false, 'message' => 'Send between 1 and ' . CS_AGENT_MAX_EVENTS . ' events per request.'], 422);
        }
        $statement = $pdo->prepare(
            'INSERT IGNORE INTO file_events (computer_id, event_uid, event_type, file_path, file_name, file_extension, file_size, sha256, detected_at)
             VALUES (:computer_id, :event_uid, :event_type, :file_path, :file_name, :file_extension, :file_size, :sha256, :detected_at)'
        );
        $accepted = 0;
        $rejected = 0;
        foreach ($events as $event) {
            if (!is_array($event)) {
                $rejected++;
                continue;
            }
            $uid = strtolower((string) ($event['event_uid'] ?? ''));
            $type = (string) ($event['event_type'] ?? '');
            $path = agent_text($event['file_path'] ?? null, 1024);
            if (!preg_match('/^[0-9a-f-]{36}$/', $uid) || $path === null
                || !in_array($type, ['created', 'modified', 'deleted', 'moved'], true)) {
                $rejected++;
                continue;
            }
            $name = mb_substr(basename(str_replace('\\', '/', $path)), 0, 255);
            $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            $sha256 = strtolower((string) ($event['sha256'] ?? ''));
            $detected = (int) ($event['detected_at'] ?? 0);
            if ($detected <= 0 || $detected > time() + CS_AGENT_SIGNATURE_WINDOW) {
                $detected = time();
            }
            $size = $event['file_size'] ?? null;
            $statement->execute([
                'computer_id' => $computerId,
                'event_uid' => $uid,
                'event_type' => $type,
                'file_path' => $path,
                'file_name' => $name,
                'file_extension' => $extension !== '' ? substr($extension, 0, 32) : null,
                'file_size' => is_numeric($size) && $size >= 0 ? (int) $size : null,
                'sha256' => preg_match('/^[0-9a-f]{64}$/', $sha256) ? $sha256 : null,
                'detected_at' => date('Y-m-d H:i:s', $detected),
            ]);
            $accepted++;
        }
        agent_respond(['ok' => true, 'accepted' => $accepted, 'rejected' => $rejected]);
    }

    if ($action === 'upload-failed') {
        $requestId = filter_var($input['request_id'] ?? null, FILTER_VALIDATE_INT);
        $reason = agent_text($input['reason'] ?? 'The agent could not upload the file.', 300);
        $statement = $pdo->prepare(
            "SELECT id FROM scan_requests WHERE id = :id AND computer_id = :computer_id AND status = 'awaiting_upload'"
        );
        $statement->execute(['id' => $requestId ?: 0, 'computer_id' => $computerId]);
        if ($statement->fetchColumn()) {
            cs_update_scan_request($pdo, (int) $requestId, 'failed', ['error' => 'Lab computer: ' . $reason]);
            cs_audit($pdo, 'scan.upload_failed', $computer['hostname'] . ': ' . $reason, ['actor_type' => 'agent', 'computer_id' => $computerId]);
        }
        agent_respond(['ok' => true]);
    }

    agent_respond(['ok' => false, 'message' => 'Unknown action.'], 404);
} catch (Throwable $error) {
    if (function_exists('cs_log')) {
        cs_log('ERROR', 'Agent API: ' . $error->getMessage() . ' @ ' . $error->getFile() . ':' . $error->getLine());
    } else {
        error_log('[Cyber-Shield] Agent API: ' . $error->getMessage());
    }
    agent_respond(['ok' => false, 'message' => 'The Cyber-Shield server could not complete the request.'], 500);
}
