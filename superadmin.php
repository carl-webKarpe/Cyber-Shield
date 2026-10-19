<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

if (empty($_SESSION['user']['id'])) {
    header('Location: login.php');
    exit;
}

$role = $_SESSION['user']['role'] ?? 'superadmin';

$_SESSION['last_activity'] = time();

$stats = [
    ['label' => 'Total Users', 'value' => '2,486', 'change' => '+12.4%', 'icon' => '👥', 'tone' => 'blue'],
    ['label' => 'Active Incidents', 'value' => '28', 'change' => '-8.1%', 'icon' => '🚨', 'tone' => 'red'],
    ['label' => 'Protected Endpoints', 'value' => '1,942', 'change' => '+3.2%', 'icon' => '🛡️', 'tone' => 'green'],
    ['label' => 'Threat Score', 'value' => '34/100', 'change' => 'Stable', 'icon' => '📊', 'tone' => 'amber'],
];

$alerts = [
    ['title' => 'Suspicious login pattern', 'detail' => '3 failed attempts from 192.168.2.14', 'severity' => 'high', 'time' => '3 min ago'],
    ['title' => 'Malware signature detected', 'detail' => 'Host 12-ATL-03 matched IOC set A-9', 'severity' => 'critical', 'time' => '7 min ago'],
    ['title' => 'Patch required', 'detail' => 'Windows endpoint needs security update KB503', 'severity' => 'medium', 'time' => '22 min ago'],
];

$activity = [
    ['label' => 'Mon', 'value' => 40],
    ['label' => 'Tue', 'value' => 58],
    ['label' => 'Wed', 'value' => 46],
    ['label' => 'Thu', 'value' => 74],
    ['label' => 'Fri', 'value' => 68],
    ['label' => 'Sat', 'value' => 82],
    ['label' => 'Sun', 'value' => 64],
];

$users = [
    ['name' => 'Aiko Reyes', 'email' => 'aiko@cybershield.local', 'role' => 'Super Admin', 'status' => 'Active', 'lastSeen' => '2 mins ago'],
    ['name' => 'Ben Castillo', 'email' => 'ben@cybershield.local', 'role' => 'SOC Analyst', 'status' => 'On duty', 'lastSeen' => '9 mins ago'],
    ['name' => 'Celine Dela Cruz', 'email' => 'celine@cybershield.local', 'role' => 'Threat Hunter', 'status' => 'Reviewing', 'lastSeen' => '16 mins ago'],
    ['name' => 'Daniel Ortega', 'email' => 'daniel@cybershield.local', 'role' => 'Engineer', 'status' => 'Offline', 'lastSeen' => '1 hr ago'],
];

$incidents = [
    ['code' => 'INC-5821', 'title' => 'Phishing domain verified', 'severity' => 'Critical', 'status' => 'Investigating'],
    ['code' => 'INC-5823', 'title' => 'Unauthorized VPN access', 'severity' => 'High', 'status' => 'Blocked'],
    ['code' => 'INC-5827', 'title' => 'Suspicious port scanning', 'severity' => 'Medium', 'status' => 'Monitoring'],
];

$systemHealth = [
    ['label' => 'Firewall', 'value' => 97, 'color' => '#39c6ff'],
    ['label' => 'Endpoint Scan', 'value' => 94, 'color' => '#7afb92'],
    ['label' => 'Cloud Guard', 'value' => 91, 'color' => '#9f7bff'],
    ['label' => 'Identity Lock', 'value' => 99, 'color' => '#ffc857'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Super Admin — Cyber Shield</title>
    <style>
        :root {
            --bg: #05131d;
            --bg-soft: #0d1d2b;
            --panel: rgba(14, 26, 38, 0.9);
            --panel-strong: #102638;
            --panel-alt: #0b1b2a;
            --line: rgba(124, 167, 202, 0.18);
            --text: #eaf6ff;
            --muted: #9ec0d9;
            --blue: #39c6ff;
            --blue-strong: #2e6fe8;
            --green: #7afb92;
            --amber: #ffc857;
            --red: #ff5d7a;
            --purple: #9f7bff;
            --shadow: 0 20px 60px rgba(0,0,0,0.28);
        }

        * { box-sizing: border-box; }
        html, body { margin: 0; min-height: 100%; font-family: Arial, Helvetica, sans-serif; background: radial-gradient(circle at top, rgba(57,198,255,0.12), transparent 35%), var(--bg); color: var(--text); }
        body { padding: 28px; }
        a { color: inherit; text-decoration: none; }
        .container { max-width: 1380px; margin: 0 auto; }

        .topbar {
            display: flex; justify-content: space-between; align-items: center; gap: 18px;
            padding: 18px 24px; margin-bottom: 22px; border: 1px solid var(--line); border-radius: 20px;
            background: rgba(9, 20, 31, 0.84); box-shadow: var(--shadow);
        }

        .brand { display: flex; align-items: center; gap: 14px; }
        .logo {
            width: 42px; height: 42px; border-radius: 14px; display: grid; place-items: center;
            background: linear-gradient(135deg, var(--blue), var(--blue-strong));
            box-shadow: 0 12px 30px rgba(57,198,255,0.35);
            font-size: 20px;
        }
        .brand-text strong { display: block; font-size: 1.05rem; }
        .brand-text small { color: var(--muted); letter-spacing: .12em; text-transform: uppercase; font-size: .68rem; }

        .top-actions { display: flex; align-items: center; gap: 14px; }
        .status-pill {
            padding: 9px 14px; border-radius: 999px; border: 1px solid rgba(122,251,146,0.25);
            background: rgba(122,251,146,0.08); color: var(--green); font-weight: 700; font-size: .82rem;
        }
        .user-pill {
            display: inline-flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 999px;
            background: rgba(255,255,255,0.04); border: 1px solid var(--line);
        }
        .avatar {
            width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center;
            background: linear-gradient(135deg, var(--purple), var(--blue)); font-weight: bold; font-size: .9rem;
        }

        .stats-grid {
            display: grid; grid-template-columns: repeat(4, minmax(180px, 1fr)); gap: 18px; margin-bottom: 20px;
        }
        .card {
            background: linear-gradient(180deg, rgba(17,31,46,0.95), rgba(12,22,32,0.9));
            border: 1px solid var(--line); border-radius: 18px; padding: 20px; box-shadow: var(--shadow);
        }
        .stat {
            display: flex; align-items: center; justify-content: space-between; gap: 12px;
        }
        .stat-icon {
            width: 50px; height: 50px; border-radius: 14px; display: grid; place-items: center; font-size: 1.4rem;
            background: rgba(255,255,255,0.04);
        }
        .stat .tone-blue { background: rgba(57,198,255,0.12); }
        .stat .tone-red { background: rgba(255,93,122,0.12); }
        .stat .tone-green { background: rgba(122,251,146,0.12); }
        .stat .tone-amber { background: rgba(255,200,87,0.12); }
        .stat-label { color: var(--muted); font-size: .8rem; margin-bottom: 8px; }
        .stat-value { font-size: clamp(1.4rem, 2vw, 2rem); font-weight: 700; }
        .stat-change { font-size: .76rem; margin-top: 8px; color: var(--green); }

        .layout {
            display: grid; grid-template-columns: 1.5fr 1fr; gap: 20px; margin-bottom: 20px;
        }

        .panel-header {
            display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 18px;
            padding-bottom: 12px; border-bottom: 1px solid var(--line);
        }
        .panel-header h2 { margin: 0; font-size: 1.1rem; }
        .link-btn {
            padding: 8px 12px; border-radius: 10px; border: 1px solid var(--line); color: var(--muted); background: rgba(255,255,255,0.02);
            font-size: .75rem;
        }

        .chart-box { height: 240px; display: flex; align-items: end; gap: 18px; padding-top: 18px; }
        .bar-col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: end; gap: 12px; }
        .bar {
            width: 100%; max-width: 44px; border-radius: 12px 12px 0 0; background: linear-gradient(180deg, var(--blue), var(--blue-strong));
            min-height: 16px; box-shadow: 0 12px 20px rgba(57,198,255,0.2);
        }
        .bar-label { color: var(--muted); font-size: .74rem; }

        .alert-list, .incident-list, .system-list { display: flex; flex-direction: column; gap: 14px; }
        .alert-item { padding: 14px 16px; border-radius: 14px; background: rgba(255,255,255,0.02); border: 1px solid var(--line); }
        .alert-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
        .severity {
            display: inline-block; padding: 5px 8px; border-radius: 999px; font-size: .68rem; font-weight: 700; text-transform: uppercase; letter-spacing: .08em;
        }
        .severity.high { background: rgba(255,93,122,0.12); color: #ff96a8; }
        .severity.critical { background: rgba(255,93,122,0.18); color: #ff7f95; }
        .severity.medium { background: rgba(255,200,87,0.12); color: #ffd678; }
        .alert-item h3 { margin: 8px 0 6px; font-size: .97rem; }
        .alert-item p { margin: 0; color: var(--muted); font-size: .8rem; }
        .stamp { color: var(--muted); font-size: .75rem; }

        table {
            width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 18px; background: rgba(255,255,255,0.02);
        }
        th, td {
            padding: 14px 16px; text-align: left; border-bottom: 1px solid var(--line);
            font-size: .91rem;
        }
        th { color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: .08em; font-size: .7rem; }
        tbody tr:hover { background: rgba(255,255,255,0.02); }
        .badge {
            display: inline-flex; align-items: center; padding: 6px 9px; border-radius: 999px; font-size: .72rem; font-weight: 700;
            background: rgba(122,251,146,0.1); color: var(--green);
        }
        .badge.warning { background: rgba(255,200,87,0.12); color: var(--amber); }
        .badge.offline { background: rgba(158,192,217,0.12); color: var(--muted); }
        .badge.blocked { background: rgba(255,93,122,0.12); color: #ff8ea3; }

        .health-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .progress {
            position: relative; height: 12px; border-radius: 999px; overflow: hidden; background: rgba(255,255,255,0.04); border: 1px solid var(--line);
        }
        .progress-bar {
            position: absolute; inset: 0 auto 0 0; border-radius: inherit; background: linear-gradient(90deg, #39c6ff, #7afb92);
        }
        .metric { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; color: var(--muted); font-size: .8rem; }

        .bottom-grid {
            display: grid; grid-template-columns: 1.2fr .8fr; gap: 20px; margin-top: 20px;
        }

        @media (max-width: 980px) {
            .stats-grid { grid-template-columns: repeat(2, minmax(180px, 1fr)); }
            .layout, .bottom-grid { grid-template-columns: 1fr; }
        }

        @media (max-width: 640px) {
            body { padding: 16px; }
            .topbar { flex-direction: column; align-items: flex-start; }
            .stats-grid { grid-template-columns: 1fr; }
            th, td { padding: 10px 8px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="topbar">
            <div class="brand">
                <div class="logo">🛡️</div>
                <div class="brand-text">
                    <strong>Cyber Shield</strong>
                    <small>Super Admin Console</small>
                </div>
            </div>

            <div class="top-actions">
                <span class="status-pill">System Healthy</span>
                <div class="user-pill">
                    <span class="avatar"><?php echo htmlspecialchars(substr((string)($_SESSION['user']['name'] ?? 'SA'), 0, 2), ENT_QUOTES, 'UTF-8'); ?></span>
                    <div>
                        <div style="font-size:.82rem; font-weight:700;"><?php echo htmlspecialchars((string)($_SESSION['user']['name'] ?? 'Super Admin'), ENT_QUOTES, 'UTF-8'); ?></div>
                        <small style="color: var(--muted);"><?php echo htmlspecialchars((string)($role === 'superadmin' ? 'Super Admin' : 'Admin'), ENT_QUOTES, 'UTF-8'); ?></small>
                    </div>
                </div>
            </div>
        </header>

        <section class="stats-grid">
            <?php foreach ($stats as $stat): ?>
                <article class="card stat">
                    <div>
                        <div class="stat-label"><?php echo htmlspecialchars($stat['label'], ENT_QUOTES, 'UTF-8'); ?></div>
                        <div class="stat-value"><?php echo htmlspecialchars((string)$stat['value'], ENT_QUOTES, 'UTF-8'); ?></div>
                        <div class="stat-change"><?php echo htmlspecialchars((string)$stat['change'], ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                    <div class="stat-icon tone-<?php echo htmlspecialchars((string)$stat['tone'], ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars((string)$stat['icon'], ENT_QUOTES, 'UTF-8'); ?></div>
                </article>
            <?php endforeach; ?>
        </section>

        <section class="layout">
            <article class="card">
                <div class="panel-header">
                    <h2>Threat Activity</h2>
                    <button class="link-btn" type="button">Export Report</button>
                </div>

                <div class="chart-box">
                    <?php foreach ($activity as $point): ?>
                        <div class="bar-col">
                            <div class="bar" style="height: <?php echo (int)$point['value']; ?>%;"></div>
                            <span class="bar-label"><?php echo htmlspecialchars((string)$point['label'], ENT_QUOTES, 'UTF-8'); ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </article>

            <aside class="card">
                <div class="panel-header">
                    <h2>Security Alerts</h2>
                    <button class="link-btn" type="button">View All</button>
                </div>

                <div class="alert-list">
                    <?php foreach ($alerts as $alert): ?>
                        <div class="alert-item">
                            <div class="alert-head">
                                <span class="severity <?php echo htmlspecialchars((string)$alert['severity'], ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars((string)$alert['severity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                <span class="stamp"><?php echo htmlspecialchars((string)$alert['time'], ENT_QUOTES, 'UTF-8'); ?></span>
                            </div>
                            <h3><?php echo htmlspecialchars((string)$alert['title'], ENT_QUOTES, 'UTF-8'); ?></h3>
                            <p><?php echo htmlspecialchars((string)$alert['detail'], ENT_QUOTES, 'UTF-8'); ?></p>
                        </div>
                    <?php endforeach; ?>
                </div>
            </aside>
        </section>

        <section class="bottom-grid">
            <article class="card">
                <div class="panel-header">
                    <h2>Users & Access</h2>
                    <button class="link-btn" type="button">Add User</button>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $person): ?>
                            <tr>
                                <td><?php echo htmlspecialchars((string)$person['name'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars((string)$person['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td><?php echo htmlspecialchars((string)$person['role'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td>
                                    <?php
                                        $statusClass = 'badge';
                                        if (stripos((string)$person['status'], 'offline') !== false) {
                                            $statusClass .= ' offline';
                                        } elseif (stripos((string)$person['status'], 'reviewing') !== false || stripos((string)$person['status'], 'on duty') !== false) {
                                            $statusClass .= ' warning';
                                        }
                                    ?>
                                    <span class="<?php echo htmlspecialchars($statusClass, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars((string)$person['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </td>
                                <td><?php echo htmlspecialchars((string)$person['lastSeen'], ENT_QUOTES, 'UTF-8'); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </article>

            <aside class="card">
                <div class="panel-header">
                    <h2>System Health</h2>
                    <button class="link-btn" type="button">More</button>
                </div>

                <div class="system-list">
                    <?php foreach ($systemHealth as $item): ?>
                        <div>
                            <div class="metric">
                                <span><?php echo htmlspecialchars((string)$item['label'], ENT_QUOTES, 'UTF-8'); ?></span>
                                <strong><?php echo (int)$item['value']; ?>%</strong>
                            </div>
                            <div class="progress">
                                <div class="progress-bar" style="width: <?php echo (int)$item['value']; ?>%; background: linear-gradient(90deg, <?php echo htmlspecialchars((string)$item['color'], ENT_QUOTES, 'UTF-8'); ?>, #7afb92);"></div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </aside>
        </section>

        <section class="layout" style="margin-top: 20px;">
            <article class="card">
                <div class="panel-header">
                    <h2>Incident Queue</h2>
                    <button class="link-btn" type="button">Open Console</button>
                </div>

                <div class="incident-list">
                    <?php foreach ($incidents as $incident): ?>
                        <div class="alert-item" style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
                            <div>
                                <div style="color: var(--muted); font-size: .75rem; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 6px;">
                                    <?php echo htmlspecialchars((string)$incident['code'], ENT_QUOTES, 'UTF-8'); ?>
                                </div>
                                <h3 style="margin: 0 0 4px; font-size: .97rem;"><?php echo htmlspecialchars((string)$incident['title'], ENT_QUOTES, 'UTF-8'); ?></h3>
                            </div>
                            <div style="display:flex; gap:10px; align-items:center;">
                                <span class="severity <?php echo strtolower(htmlspecialchars((string)$incident['severity'], ENT_QUOTES, 'UTF-8')); ?>"><?php echo htmlspecialchars((string)$incident['severity'], ENT_QUOTES, 'UTF-8'); ?></span>
                                <span class="badge blocked"><?php echo htmlspecialchars((string)$incident['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </article>

            <aside class="card">
                <div class="panel-header">
                    <h2>Quick Controls</h2>
                </div>

                <div class="alert-list">
                    <button class="link-btn" type="button" style="padding: 12px 14px; text-align: left; width:100%;">Lock Down Admin Access</button>
                    <button class="link-btn" type="button" style="padding: 12px 14px; text-align: left; width:100%;">Run Full Network Scan</button>
                    <button class="link-btn" type="button" style="padding: 12px 14px; text-align: left; width:100%;">Review Audit Log</button>
                    <button class="link-btn" type="button" style="padding: 12px 14px; text-align: left; width:100%;">Generate Compliance Snapshot</button>
                </div>
            </aside>
        </section>
    </div>
</body>
</html>
