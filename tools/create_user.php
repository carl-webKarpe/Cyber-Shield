<?php
declare(strict_types=1);

/**
 * Cyber-Shield account tool. Creates a user or resets an existing user's password/role.
 *
 * Usage (from the Cyber-Shield folder):
 *   php tools\create_user.php --email=admin@lab.local --name="Lab Admin" --role=admin
 *   php tools\create_user.php --email=head@lab.local --name="IT Head" --role=superadmin
 *   php tools\create_user.php --email=old@lab.local --disable
 * The password is prompted for (not shown on screen) unless --password=... is given.
 */
if (PHP_SAPI !== 'cli') {
    exit(1);
}
require dirname(__DIR__) . '/includes/bootstrap.php';

$options = getopt('', ['email:', 'name::', 'role::', 'password::', 'disable']);
$email = strtolower(trim((string) ($options['email'] ?? '')));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage: php tools/create_user.php --email=you@lab.local --name=\"Full Name\" --role=admin|superadmin [--password=...] [--disable]\n");
    exit(1);
}

if (isset($options['disable'])) {
    $statement = $pdo->prepare('UPDATE users SET is_active = 0 WHERE email = :email');
    $statement->execute(['email' => $email]);
    echo $statement->rowCount() ? "[Cyber-Shield] Disabled {$email}\n" : "[Cyber-Shield] No change for {$email}\n";
    cs_audit($pdo, 'user.disabled', "{$email} disabled from the command line", ['ip' => 'cli']);
    exit(0);
}

$role = (string) ($options['role'] ?? 'admin');
if (!in_array($role, ['admin', 'superadmin'], true)) {
    fwrite(STDERR, "--role must be admin or superadmin\n");
    exit(1);
}
$password = (string) ($options['password'] ?? '');
if ($password === '') {
    echo 'Password (min 8 characters): ';
    if (PHP_OS_FAMILY === 'Windows') {
        $password = trim((string) shell_exec('powershell -NoProfile -Command "$p = Read-Host -AsSecureString; [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p))"'));
    } else {
        system('stty -echo');
        $password = trim((string) fgets(STDIN));
        system('stty echo');
        echo "\n";
    }
}
if (strlen($password) < 8) {
    fwrite(STDERR, "Password must be at least 8 characters.\n");
    exit(1);
}
$givenName = trim((string) ($options['name'] ?? ''));
$name = $givenName !== '' ? $givenName : strstr($email, '@', true);

// Without --name, an existing account keeps its current name (e.g. when only resetting a password).
$statement = $pdo->prepare(
    'INSERT INTO users (name, email, password_hash, role, is_active) VALUES (:name, :email, :hash, :role, 1)
     ON DUPLICATE KEY UPDATE name = IF(:keep_name = 1, name, VALUES(name)), password_hash = VALUES(password_hash), role = VALUES(role), is_active = 1'
);
$statement->execute([
    'name' => substr($name, 0, 100),
    'email' => $email,
    'hash' => password_hash($password, PASSWORD_DEFAULT),
    'role' => $role,
    'keep_name' => $givenName === '' ? 1 : 0,
]);
$pdo->prepare('INSERT IGNORE INTO user_settings (user_id) SELECT id FROM users WHERE email = :email')->execute(['email' => $email]);
cs_audit($pdo, 'user.saved', sprintf('%s saved as %s from the command line', $email, cs_role_label($role)), ['ip' => 'cli']);
echo "[Cyber-Shield] Saved {$email} as " . cs_role_label($role) . "\n";
