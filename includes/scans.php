<?php
declare(strict_types=1);

/**
 * Cyber-Shield scan service.
 * Creates scan requests, stores real VirusTotal results, and keeps the
 * original "Scan History" table in sync. A file is only ever labelled safe
 * when VirusTotal actually returned engine results for it.
 */

const CS_RECOMMENDED_ACTIONS = [
    'clean' => 'No engine flagged this item. Keep normal precautions; re-scan if the file changes.',
    'low' => 'Some engines rate this as suspicious. Do not open it until an Admin reviews the VirusTotal report.',
    'medium' => 'Flagged as malicious by a small number of engines. Isolate the file and review the detections before use.',
    'high' => 'Flagged as malicious by several engines. Quarantine or delete the file and check the lab computer for other infections.',
    'critical' => 'Widely detected as malicious. Disconnect the lab computer from the network, delete the file, and run a full antivirus scan.',
    'unknown' => 'VirusTotal has no engine results yet. Treat the file as untrusted until a scan completes.',
];

function cs_risk_level(int $malicious, int $suspicious, int $total): string
{
    if ($total === 0) {
        return 'unknown';
    }
    if ($malicious >= 10) {
        return 'critical';
    }
    if ($malicious >= 3) {
        return 'high';
    }
    if ($malicious >= 1) {
        return 'medium';
    }
    if ($suspicious >= 1) {
        return 'low';
    }
    return 'clean';
}

/** Maps a risk level onto the original Scan History statuses. */
function cs_history_status(string $riskLevel): string
{
    return [
        'clean' => 'safe',
        'low' => 'suspicious',
        'medium' => 'suspicious',
        'high' => 'threat',
        'critical' => 'threat',
    ][$riskLevel] ?? 'unknown';
}

function cs_vt_timestamp($value): ?string
{
    return is_numeric($value) && (int) $value > 0 ? date('Y-m-d H:i:s', (int) $value) : null;
}

/**
 * Builds a result row from a VirusTotal file or URL object (`data.attributes`)
 * or from an analysis object (`stats` + `meta`).
 */
function cs_summarize_vt(array $attributes, string $source, string $target, array $meta = []): array
{
    $stats = $attributes['last_analysis_stats'] ?? $attributes['stats'] ?? [];
    $malicious = (int) ($stats['malicious'] ?? 0);
    $suspicious = (int) ($stats['suspicious'] ?? 0);
    $harmless = (int) ($stats['harmless'] ?? 0);
    $undetected = (int) ($stats['undetected'] ?? 0);
    $total = $malicious + $suspicious + $harmless + $undetected;
    $risk = cs_risk_level($malicious, $suspicious, $total);
    $fileInfo = $meta['file_info'] ?? [];
    $sha256 = $attributes['sha256'] ?? $fileInfo['sha256'] ?? null;

    if ($source === 'url') {
        $link = 'https://www.virustotal.com/gui/url/' . hash('sha256', $target);
    } else {
        $link = $sha256 ? 'https://www.virustotal.com/gui/file/' . $sha256 : null;
    }

    return [
        'sha256' => $sha256,
        'sha1' => $attributes['sha1'] ?? $fileInfo['sha1'] ?? null,
        'md5' => $attributes['md5'] ?? $fileInfo['md5'] ?? null,
        'malicious' => $malicious,
        'suspicious' => $suspicious,
        'harmless' => $harmless,
        'undetected' => $undetected,
        'total_engines' => $total,
        'detection_ratio' => $malicious . '/' . $total,
        'risk_level' => $risk,
        'threat_label' => isset($attributes['popular_threat_classification']['suggested_threat_label'])
            ? substr((string) $attributes['popular_threat_classification']['suggested_threat_label'], 0, 255) : null,
        'file_type' => isset($attributes['type_description']) ? substr((string) $attributes['type_description'], 0, 120) : null,
        'recommended_action' => CS_RECOMMENDED_ACTIONS[$risk],
        'vt_link' => $link,
        'analysis_date' => cs_vt_timestamp($attributes['last_analysis_date'] ?? $attributes['date'] ?? null),
    ];
}

function cs_create_scan_request(PDO $pdo, array $fields, int $userId): array
{
    $statement = $pdo->prepare(
        'INSERT INTO scan_requests (requested_by, source, computer_id, file_event_id, target_name, file_path, sha256, status)
         VALUES (:requested_by, :source, :computer_id, :file_event_id, :target_name, :file_path, :sha256, :status)'
    );
    $statement->execute([
        'requested_by' => $userId,
        'source' => $fields['source'],
        'computer_id' => $fields['computer_id'] ?? null,
        'file_event_id' => $fields['file_event_id'] ?? null,
        'target_name' => substr($fields['target_name'], 0, 500),
        'file_path' => $fields['file_path'] ?? null,
        'sha256' => $fields['sha256'] ?? null,
        'status' => 'pending',
    ]);
    $requestId = (int) $pdo->lastInsertId();

    $history = $pdo->prepare(
        "INSERT INTO scans (user_id, scan_request_id, name, scan_type, result, status, sha256)
         VALUES (:user_id, :request_id, :name, :type, 'Scan requested', 'pending', :sha256)"
    );
    $history->execute([
        'user_id' => $userId,
        'request_id' => $requestId,
        'name' => substr($fields['target_name'], 0, 500),
        'type' => $fields['source'] === 'url' ? 'URL' : 'File',
        'sha256' => $fields['sha256'] ?? null,
    ]);

    return cs_get_scan_request($pdo, $requestId);
}

function cs_update_scan_request(PDO $pdo, int $requestId, string $status, array $extra = []): void
{
    $statement = $pdo->prepare(
        'UPDATE scan_requests SET status = :status, vt_analysis_id = COALESCE(:analysis_id, vt_analysis_id),
         error_message = :error_message, sha256 = COALESCE(:sha256, sha256) WHERE id = :id'
    );
    $statement->execute([
        'status' => $status,
        'analysis_id' => $extra['analysis_id'] ?? null,
        'error_message' => isset($extra['error']) ? substr($extra['error'], 0, 500) : null,
        'sha256' => $extra['sha256'] ?? null,
        'id' => $requestId,
    ]);

    $historyText = [
        'pending' => ['Scan requested', 'pending'],
        'awaiting_upload' => ['Waiting for the lab computer to upload the file', 'pending'],
        'submitted' => ['Submitted to VirusTotal - analysis in progress', 'pending'],
        'not_found' => ['Not in VirusTotal database - not scanned', 'unknown'],
        'failed' => ['Scan failed: ' . ($extra['error'] ?? 'unknown error'), 'unknown'],
    ][$status] ?? null;
    if ($historyText !== null) {
        $history = $pdo->prepare('UPDATE scans SET result = :result, status = :status WHERE scan_request_id = :id');
        $history->execute(['result' => substr($historyText[0], 0, 255), 'status' => $historyText[1], 'id' => $requestId]);
    }
}

function cs_store_scan_result(PDO $pdo, array $request, array $summary): void
{
    $pdo->beginTransaction();
    try {
        $statement = $pdo->prepare(
            'INSERT INTO scan_results (scan_request_id, sha256, sha1, md5, malicious, suspicious, harmless, undetected,
                total_engines, detection_ratio, risk_level, threat_label, file_type, recommended_action, vt_link, analysis_date)
             VALUES (:scan_request_id, :sha256, :sha1, :md5, :malicious, :suspicious, :harmless, :undetected,
                :total_engines, :detection_ratio, :risk_level, :threat_label, :file_type, :recommended_action, :vt_link, :analysis_date)
             ON DUPLICATE KEY UPDATE sha256 = VALUES(sha256), sha1 = VALUES(sha1), md5 = VALUES(md5), malicious = VALUES(malicious),
                suspicious = VALUES(suspicious), harmless = VALUES(harmless), undetected = VALUES(undetected),
                total_engines = VALUES(total_engines), detection_ratio = VALUES(detection_ratio), risk_level = VALUES(risk_level),
                threat_label = VALUES(threat_label), file_type = VALUES(file_type), recommended_action = VALUES(recommended_action),
                vt_link = VALUES(vt_link), analysis_date = VALUES(analysis_date)'
        );
        $statement->execute(['scan_request_id' => $request['id']] + $summary);

        $update = $pdo->prepare("UPDATE scan_requests SET status = 'completed', error_message = NULL, sha256 = COALESCE(:sha256, sha256) WHERE id = :id");
        $update->execute(['sha256' => $summary['sha256'], 'id' => $request['id']]);

        $label = [
            'clean' => 'No engines flagged this item',
            'low' => 'Suspicious - review recommended',
            'medium' => 'Malicious detections found',
            'high' => 'Malicious - quarantine recommended',
            'critical' => 'Malicious - widely detected',
            'unknown' => 'No engine results yet',
        ][$summary['risk_level']];
        $history = $pdo->prepare('UPDATE scans SET result = :result, status = :status, details = :details, sha256 = COALESCE(:sha256, sha256) WHERE scan_request_id = :id');
        $history->execute([
            'result' => sprintf('%s (VirusTotal %s)', $label, $summary['detection_ratio']),
            'status' => cs_history_status($summary['risk_level']),
            'details' => $summary['recommended_action'],
            'sha256' => $summary['sha256'],
            'id' => $request['id'],
        ]);

        if (in_array($summary['risk_level'], ['high', 'critical'], true)) {
            $where = $request['hostname'] ? ' on lab computer ' . $request['hostname'] : '';
            $incident = $pdo->prepare(
                "INSERT INTO incidents (incident_code, title, description, severity, category, status, detected_at)
                 VALUES (:code, :title, :description, :severity, 'File scanning', 'open', NOW())
                 ON DUPLICATE KEY UPDATE description = VALUES(description), severity = VALUES(severity)"
            );
            $incident->execute([
                'code' => 'VT-' . $request['id'],
                'title' => substr('Malicious file detected: ' . $request['target_name'], 0, 200),
                'description' => sprintf(
                    'VirusTotal flagged %s%s (%s engines, risk %s). %s',
                    $request['target_name'], $where, $summary['detection_ratio'], $summary['risk_level'], $summary['recommended_action']
                ),
                'severity' => $summary['risk_level'] === 'critical' ? 'critical' : 'high',
            ]);
        }
        $pdo->commit();
    } catch (Throwable $error) {
        $pdo->rollBack();
        throw $error;
    }
}

function cs_get_scan_request(PDO $pdo, int $requestId): ?array
{
    $statement = $pdo->prepare(
        'SELECT sq.id, sq.source, sq.computer_id, sq.file_event_id, sq.target_name, sq.file_path, sq.sha256, sq.status,
                sq.vt_analysis_id, sq.error_message, sq.created_at, sq.updated_at, lc.hostname, u.name AS requested_by_name
         FROM scan_requests sq
         LEFT JOIN lab_computers lc ON lc.id = sq.computer_id
         LEFT JOIN users u ON u.id = sq.requested_by
         WHERE sq.id = :id'
    );
    $statement->execute(['id' => $requestId]);
    $request = $statement->fetch();
    return $request ?: null;
}

/** Public shape of a scan request + result, as returned to the dashboard. */
function cs_scan_payload(PDO $pdo, int $requestId): ?array
{
    $request = cs_get_scan_request($pdo, $requestId);
    if (!$request) {
        return null;
    }
    $statement = $pdo->prepare(
        'SELECT sha256, sha1, md5, malicious, suspicious, harmless, undetected, total_engines, detection_ratio,
                risk_level, threat_label, file_type, recommended_action, vt_link, analysis_date, created_at
         FROM scan_results WHERE scan_request_id = :id'
    );
    $statement->execute(['id' => $requestId]);
    $result = $statement->fetch() ?: null;
    return [
        'id' => (int) $request['id'],
        'source' => $request['source'],
        'target' => $request['target_name'],
        'filePath' => $request['file_path'],
        'computer' => $request['hostname'],
        'computerId' => $request['computer_id'] !== null ? (int) $request['computer_id'] : null,
        'fileEventId' => $request['file_event_id'] !== null ? (int) $request['file_event_id'] : null,
        'sha256' => $request['sha256'],
        'status' => $request['status'],
        'error' => $request['error_message'],
        'requestedBy' => $request['requested_by_name'],
        'requestedAt' => $request['created_at'],
        'updatedAt' => $request['updated_at'],
        'result' => $result,
    ];
}

/** Looks a hash up on VirusTotal and records either the result or "not found". */
function cs_lookup_hash(PDO $pdo, CyberShieldVirusTotal $vt, array $request): void
{
    $report = $vt->getFileReport((string) $request['sha256']);
    if ($report === null) {
        cs_update_scan_request($pdo, (int) $request['id'], 'not_found');
        return;
    }
    cs_store_scan_result($pdo, $request, cs_summarize_vt($report['data']['attributes'] ?? [], $request['source'], $request['target_name']));
}

/** Uploads a local file to VirusTotal for a request that has no existing report. */
function cs_submit_file(PDO $pdo, CyberShieldVirusTotal $vt, array $request, string $path): void
{
    $analysisId = $vt->uploadFile($path, basename((string) $request['target_name']));
    cs_update_scan_request($pdo, (int) $request['id'], 'submitted', ['analysis_id' => $analysisId]);
}

/**
 * Polls VirusTotal for a submitted analysis. Returns true when the request changed.
 * Requests are polled at most every 15 seconds to respect the public API rate limit.
 */
function cs_refresh_scan(PDO $pdo, CyberShieldVirusTotal $vt, array $request): bool
{
    if ($request['status'] !== 'submitted' || !$request['vt_analysis_id']) {
        return false;
    }
    if (strtotime((string) $request['updated_at']) > time() - 15) {
        return false;
    }
    $pdo->prepare('UPDATE scan_requests SET updated_at = NOW() WHERE id = :id')->execute(['id' => $request['id']]);

    $analysis = $vt->getAnalysis((string) $request['vt_analysis_id']);
    $attributes = $analysis['data']['attributes'] ?? [];
    if (($attributes['status'] ?? '') !== 'completed') {
        return false;
    }
    $meta = $analysis['meta'] ?? [];
    $report = null;
    if ($request['source'] === 'url') {
        $report = $vt->getUrlReport((string) $request['target_name']);
    } elseif (!empty($meta['file_info']['sha256'])) {
        $report = $vt->getFileReport((string) $meta['file_info']['sha256']);
    }
    $summary = $report !== null
        ? cs_summarize_vt($report['data']['attributes'] ?? [], $request['source'], $request['target_name'])
        : cs_summarize_vt($attributes, $request['source'], $request['target_name'], $meta);
    cs_store_scan_result($pdo, $request, $summary);
    return true;
}
