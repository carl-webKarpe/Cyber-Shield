<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';
cs_start_session();
$user = cs_require_page_user($pdo, 'view_audit_logs');

$window = max(30, (int) cs_config('agent_heartbeat_seconds') * 3);
$computerStats = $pdo->query(
    "SELECT COUNT(*) AS total,
            COALESCE(SUM(is_authorized = 1 AND last_heartbeat >= NOW() - INTERVAL {$window} SECOND), 0) AS online,
            COALESCE(SUM(is_authorized = 0), 0) AS pending
     FROM lab_computers"
)->fetch();
$userCount = (int) $pdo->query('SELECT COUNT(*) FROM users WHERE is_active = 1')->fetchColumn();
$events24h = (int) $pdo->query('SELECT COUNT(*) FROM audit_logs WHERE created_at >= NOW() - INTERVAL 1 DAY')->fetchColumn();
$failedLogins = (int) $pdo->query("SELECT COUNT(*) FROM audit_logs WHERE action = 'auth.login_failed' AND created_at >= NOW() - INTERVAL 1 DAY")->fetchColumn();
$users = $pdo->query('SELECT name, email, role, is_active, last_login FROM users ORDER BY role = \'superadmin\' DESC, name')->fetchAll();
$pendingComputers = $pdo->query(
    'SELECT id, hostname, lab_location, ip_address, connection_type, registered_at FROM lab_computers WHERE is_authorized = 0 ORDER BY registered_at DESC'
)->fetchAll();

$stats = [
    ['label' => 'Active Accounts', 'value' => $userCount, 'note' => 'Super Admins and Admins', 'tone' => 'text-[#39c6ff]'],
    ['label' => 'Lab Computers Online', 'value' => $computerStats['online'] . ' / ' . $computerStats['total'], 'note' => 'Heartbeat in the last ' . $window . 's', 'tone' => 'text-[#2fe0a8]'],
    ['label' => 'Pending Approval', 'value' => (int) $computerStats['pending'], 'note' => 'Agents waiting to be authorized', 'tone' => 'text-[#ffb648]'],
    ['label' => 'Log Events (24h)', 'value' => $events24h, 'note' => $failedLogins . ' failed sign-ins', 'tone' => $failedLogins ? 'text-[#ff5470]' : 'text-[#9db3d1]'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#07111e">
    <meta name="csrf-token" content="<?php echo cs_e(cs_csrf_token()); ?>">
    <title>System Logs — Cyber-Shield Super Admin</title>
    <script src="js/auth.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/tailwind.css">
    <style>
        :root { --cs-bg: #060d18; --cs-panel: #0a1526; --cs-panel-2: #0f1e35; --cs-line: rgba(125,217,255,.12); --cs-text: #eaf3ff; --cs-muted: #9db3d1; --cs-faint: #6d84a6; }
        html[data-theme="light"] { --cs-bg: #edf3f6; --cs-panel: #ffffff; --cs-panel-2: #f3f7f9; --cs-line: rgba(27,77,98,.14); --cs-text: #172c39; --cs-muted: #4a6473; --cs-faint: #6c8290; }
        body { background: radial-gradient(1100px 600px at 85% -10%, rgba(46,111,232,.16), transparent 60%), var(--cs-bg); color: var(--cs-text); }
    </style>
</head>
<body class="min-h-screen font-body antialiased">
<div class="mx-auto max-w-7xl px-4 py-6 sm:px-6">

    <header class="mb-6 flex flex-col gap-4 rounded-2xl border border-[var(--cs-line)] bg-[var(--cs-panel)] px-5 py-4 shadow-xl sm:flex-row sm:items-center sm:justify-between">
        <div class="flex items-center gap-3">
            <svg class="h-10 w-10" viewBox="0 0 40 40" fill="none" aria-hidden="true"><path d="M20 3 5 9v10c0 9.94 6.4 18.9 15 21 8.6-2.1 15-11.06 15-21V9L20 3z" fill="url(#saShield)"/><path d="m14 20.5 4 4 8-8.5" stroke="#04141f" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="saShield" x1="5" y1="3" x2="35" y2="40"><stop stop-color="#39c6ff"/><stop offset="1" stop-color="#2e6fe8"/></linearGradient></defs></svg>
            <div>
                <p class="font-display text-lg font-bold leading-tight">Cyber-Shield</p>
                <p class="text-xs uppercase tracking-widest text-[var(--cs-faint)]">Super Admin Console</p>
            </div>
        </div>
        <nav class="flex flex-wrap items-center gap-2 text-sm">
            <a class="rounded-lg border border-[var(--cs-line)] px-3 py-2 text-[var(--cs-muted)] hover:text-[var(--cs-text)]" href="index.php">Dashboard</a>
            <a class="rounded-lg border border-[var(--cs-line)] px-3 py-2 text-[var(--cs-muted)] hover:text-[var(--cs-text)]" href="index.php?view=endpoints">Lab Computers</a>
            <a class="rounded-lg border border-[var(--cs-line)] px-3 py-2 text-[var(--cs-muted)] hover:text-[var(--cs-text)]" href="index.php?view=file-activity">File Activity</a>
            <button class="rounded-lg border border-[var(--cs-line)] px-3 py-2 text-[var(--cs-muted)] hover:text-[var(--cs-text)]" type="button" data-theme-toggle><span data-theme-label>Light mode</span></button>
            <span class="rounded-full border border-[#2fe0a8]/30 bg-[#2fe0a8]/10 px-3 py-2 text-xs font-semibold text-[#2fe0a8]"><?php echo cs_e($user['name']); ?> · Super Admin</span>
            <button class="rounded-lg bg-gradient-to-r from-[#39c6ff] to-[#2e6fe8] px-3 py-2 font-semibold text-[#04141f]" id="logoutBtn" type="button">Sign out</button>
        </nav>
    </header>

    <section class="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <?php foreach ($stats as $stat): ?>
        <article class="rounded-2xl border border-[var(--cs-line)] bg-[var(--cs-panel)] p-5 shadow-lg">
            <p class="text-xs uppercase tracking-wider text-[var(--cs-faint)]"><?php echo cs_e($stat['label']); ?></p>
            <p class="mt-2 font-display text-3xl font-bold <?php echo cs_e($stat['tone']); ?>"><?php echo cs_e($stat['value']); ?></p>
            <p class="mt-1 text-xs text-[var(--cs-muted)]"><?php echo cs_e($stat['note']); ?></p>
        </article>
        <?php endforeach; ?>
    </section>

    <section class="mb-6 rounded-2xl border border-[var(--cs-line)] bg-[var(--cs-panel)] p-5 shadow-lg">
        <div class="mb-4 flex items-center justify-between">
            <h2 class="font-display text-base font-semibold">Computers awaiting approval</h2>
            <span class="text-xs text-[var(--cs-faint)]">Only authorized computers may report file events</span>
        </div>
        <?php if (!$pendingComputers): ?>
            <p class="py-6 text-center text-sm text-[var(--cs-faint)]">No lab computers are waiting for approval.</p>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="w-full min-w-[640px] text-left text-sm">
                    <thead class="text-xs uppercase tracking-wider text-[var(--cs-faint)]">
                        <tr><th class="py-2 pr-4">Computer</th><th class="py-2 pr-4">Location</th><th class="py-2 pr-4">IP / connection</th><th class="py-2 pr-4">Registered</th><th class="py-2"></th></tr>
                    </thead>
                    <tbody>
                    <?php foreach ($pendingComputers as $computer): ?>
                        <tr class="border-t border-[var(--cs-line)]">
                            <td class="py-3 pr-4 font-medium"><?php echo cs_e($computer['hostname']); ?></td>
                            <td class="py-3 pr-4 text-[var(--cs-muted)]"><?php echo cs_e($computer['lab_location'] ?: '—'); ?></td>
                            <td class="py-3 pr-4 text-[var(--cs-muted)]"><?php echo cs_e($computer['ip_address'] . ' · ' . $computer['connection_type']); ?></td>
                            <td class="py-3 pr-4 text-[var(--cs-muted)]"><?php echo cs_e($computer['registered_at']); ?></td>
                            <td class="py-3 text-right"><button class="rounded-lg border border-[#2fe0a8]/40 px-3 py-1.5 text-xs font-semibold text-[#2fe0a8] hover:bg-[#2fe0a8]/10" type="button" data-authorize="<?php echo (int) $computer['id']; ?>" data-hostname="<?php echo cs_e($computer['hostname']); ?>">Authorize</button></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </section>

    <section class="mb-6 rounded-2xl border border-[var(--cs-line)] bg-[var(--cs-panel)] p-5 shadow-lg">
        <div class="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
                <h2 class="font-display text-base font-semibold">System logs</h2>
                <p class="text-xs text-[var(--cs-faint)]">Sign-ins, scan requests, agent registrations and approvals (latest 300). Also written to logs/cyber_shield.log on the server.</p>
            </div>
            <div class="flex flex-wrap gap-2">
                <input class="h-10 w-56 rounded-lg border border-[var(--cs-line)] bg-[var(--cs-panel-2)] px-3 text-sm text-[var(--cs-text)] placeholder:text-[var(--cs-faint)] focus:border-[#39c6ff] focus:outline-none" id="logSearch" type="search" placeholder="Filter logs" aria-label="Filter logs">
                <select class="h-10 rounded-lg border border-[var(--cs-line)] bg-[var(--cs-panel-2)] px-3 text-sm text-[var(--cs-text)]" id="logActor" aria-label="Actor">
                    <option value="">All actors</option><option value="user">Users</option><option value="agent">Agents</option><option value="system">System</option>
                </select>
                <button class="h-10 rounded-lg border border-[var(--cs-line)] px-3 text-sm text-[var(--cs-muted)] hover:text-[var(--cs-text)]" id="refreshLogs" type="button">Refresh</button>
                <button class="h-10 rounded-lg border border-[var(--cs-line)] px-3 text-sm text-[var(--cs-muted)] hover:text-[var(--cs-text)]" id="exportLogs" type="button">Export CSV</button>
            </div>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full min-w-[760px] text-left text-sm">
                <thead class="text-xs uppercase tracking-wider text-[var(--cs-faint)]">
                    <tr><th class="py-2 pr-4">Time</th><th class="py-2 pr-4">Actor</th><th class="py-2 pr-4">Action</th><th class="py-2 pr-4">Details</th><th class="py-2">IP address</th></tr>
                </thead>
                <tbody id="logTableBody"><tr><td class="py-6 text-center text-[var(--cs-faint)]" colspan="5">Loading system logs…</td></tr></tbody>
            </table>
        </div>
    </section>

    <section class="rounded-2xl border border-[var(--cs-line)] bg-[var(--cs-panel)] p-5 shadow-lg">
        <div class="mb-4 flex items-center justify-between">
            <h2 class="font-display text-base font-semibold">Accounts &amp; roles</h2>
            <span class="text-xs text-[var(--cs-faint)]">Manage accounts with tools\create_user.php on the server</span>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full min-w-[640px] text-left text-sm">
                <thead class="text-xs uppercase tracking-wider text-[var(--cs-faint)]">
                    <tr><th class="py-2 pr-4">Name</th><th class="py-2 pr-4">Email</th><th class="py-2 pr-4">Role</th><th class="py-2 pr-4">Status</th><th class="py-2">Last sign-in</th></tr>
                </thead>
                <tbody>
                <?php foreach ($users as $account): ?>
                    <tr class="border-t border-[var(--cs-line)]">
                        <td class="py-3 pr-4 font-medium"><?php echo cs_e($account['name']); ?></td>
                        <td class="py-3 pr-4 text-[var(--cs-muted)]"><?php echo cs_e($account['email']); ?></td>
                        <td class="py-3 pr-4"><?php echo cs_e(cs_role_label($account['role'])); ?></td>
                        <td class="py-3 pr-4"><span class="rounded-full px-2 py-1 text-xs font-semibold <?php echo $account['is_active'] ? 'bg-[#2fe0a8]/10 text-[#2fe0a8]' : 'bg-[#9db3d1]/10 text-[var(--cs-muted)]'; ?>"><?php echo $account['is_active'] ? 'Active' : 'Disabled'; ?></span></td>
                        <td class="py-3 text-[var(--cs-muted)]"><?php echo cs_e($account['last_login'] ?: 'Never'); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
</div>
<script src="js/superadmin.js"></script>
</body>
</html>
