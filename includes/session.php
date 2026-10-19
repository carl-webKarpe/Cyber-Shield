<?php
declare(strict_types=1);

/**
 * Cyber-Shield session, role and CSRF helpers shared by every page and the API.
 */

const CS_SESSION_LIFETIME = 28800;

const CS_ROLE_LABELS = [
    'superadmin' => 'Super Admin',
    'admin' => 'Admin',
];

function cs_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    ini_set('session.use_strict_mode', '1');
    session_name('CYBERSHIELDSESSID');
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    ]);
    session_start();
}

/** Legacy 'analyst' accounts keep working and get Admin permissions. */
function cs_normalize_role(?string $role): string
{
    return $role === 'superadmin' ? 'superadmin' : 'admin';
}

function cs_role_label(string $role): string
{
    return CS_ROLE_LABELS[cs_normalize_role($role)];
}

/** Permissions are decided here only, so the pages and the API always agree. */
function cs_can(string $role, string $permission): bool
{
    $permissions = [
        'superadmin' => ['monitor_computers', 'view_file_activity', 'view_audit_logs', 'manage_computers', 'manage_incidents'],
        'admin' => ['monitor_computers', 'view_file_activity', 'scan_files', 'view_scan_results', 'manage_incidents'],
    ];
    return in_array($permission, $permissions[cs_normalize_role($role)], true);
}

function cs_session_expired(): bool
{
    return empty($_SESSION['user']['id']) || time() - (int) ($_SESSION['last_activity'] ?? 0) > CS_SESSION_LIFETIME;
}

function cs_clear_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $cookie = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $cookie['path'], $cookie['domain'], $cookie['secure'], $cookie['httponly']);
    }
    session_destroy();
}

/**
 * Re-reads the signed-in user from the database so a disabled account or a
 * role change takes effect on the next request. Returns null when signed out.
 */
function cs_current_user(PDO $pdo): ?array
{
    if (cs_session_expired()) {
        return null;
    }
    $statement = $pdo->prepare('SELECT id, name, email, role, is_active FROM users WHERE id = :id LIMIT 1');
    $statement->execute(['id' => (int) $_SESSION['user']['id']]);
    $user = $statement->fetch();
    if (!$user || !(int) $user['is_active']) {
        return null;
    }
    $_SESSION['last_activity'] = time();
    $_SESSION['user'] = [
        'id' => (int) $user['id'],
        'email' => $user['email'],
        'name' => $user['name'],
        'role' => cs_normalize_role($user['role']),
    ];
    return $_SESSION['user'];
}

/** For server-rendered pages: sends signed-out visitors to the sign-in page. */
function cs_require_page_user(PDO $pdo, ?string $permission = null): array
{
    $user = cs_current_user($pdo);
    if ($user === null) {
        cs_clear_session();
        header('Location: login.php');
        exit;
    }
    if ($permission !== null && !cs_can($user['role'], $permission)) {
        http_response_code(403);
        header('Location: index.php');
        exit;
    }
    return $user;
}

function cs_csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function cs_csrf_valid(): bool
{
    $sent = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    return $sent !== '' && !empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $sent);
}

function cs_e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function cs_client_ip(): string
{
    return substr((string) ($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
}
