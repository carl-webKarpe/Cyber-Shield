<?php
declare(strict_types=1);

/**
 * Cyber-Shield audit log. Every security-relevant action is written to the
 * audit_logs table (shown to Super Admins) and mirrored to logs/cyber_shield.log.
 */
function cs_audit(PDO $pdo, string $action, string $details = '', array $context = []): void
{
    $actorType = $context['actor_type'] ?? (isset($context['user_id']) ? 'user' : 'system');
    try {
        $statement = $pdo->prepare(
            'INSERT INTO audit_logs (actor_type, user_id, computer_id, action, details, ip_address)
             VALUES (:actor_type, :user_id, :computer_id, :action, :details, :ip_address)'
        );
        $statement->execute([
            'actor_type' => $actorType,
            'user_id' => $context['user_id'] ?? null,
            'computer_id' => $context['computer_id'] ?? null,
            'action' => substr($action, 0, 64),
            'details' => substr($details, 0, 2000),
            'ip_address' => $context['ip'] ?? cs_client_ip(),
        ]);
    } catch (Throwable $error) {
        cs_log('ERROR', 'Could not write audit log: ' . $error->getMessage());
    }
    cs_log('INFO', $action . ($details !== '' ? ' - ' . $details : ''));
}

function cs_log(string $level, string $message): void
{
    $line = sprintf("[%s] [Cyber-Shield] [%s] %s\n", date('Y-m-d H:i:s'), $level, str_replace(["\r", "\n"], ' ', $message));
    $file = dirname(__DIR__) . '/logs/cyber_shield.log';
    if (@file_put_contents($file, $line, FILE_APPEND | LOCK_EX) === false) {
        error_log(trim($line));
    }
}
