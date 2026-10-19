<?php
ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
  'httponly' => true,
  'samesite' => 'Lax',
  'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();
if (empty($_SESSION['user']['id']) || time() - (int) ($_SESSION['last_activity'] ?? 0) > 28800) {
  $_SESSION = [];
  session_destroy();
  header('Location: login.php');
  exit;
}
$_SESSION['last_activity'] = time();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#26c650">
<title>Cyber Shield — Threat Detection</title>
<script src="js/auth.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="css/style.css">
</head>
<body>

<div class="app">

  
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <svg class="brand-icon" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M20 3L5 9v10c0 9.94 6.4 18.9 15 21 8.6-2.1 15-11.06 15-21V9L20 3z" fill="url(#shieldGrad)"/>
        <path d="M20 3L5 9v10c0 9.94 6.4 18.9 15 21 8.6-2.1 15-11.06 15-21V9L20 3z" stroke="#7DD9FF" stroke-width="1.2" stroke-opacity="0.5"/>
        <path d="M14 20.5l4 4 8-8.5" stroke="#04141F" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
        <defs>
          <linearGradient id="shieldGrad" x1="5" y1="3" x2="35" y2="40" gradientUnits="userSpaceOnUse">
            <stop stop-color="#39C6FF"/>
            <stop offset="1" stop-color="#2E6FE8"/>
          </linearGradient>
        </defs>
      </svg>
      <div class="brand-text">
        <span class="brand-name">Cyber Shield</span>
        <span class="brand-tag">Threat Detection</span>
      </div>
    </div>

    <nav class="nav">
      <button class="nav-item active" data-view="dashboard">
        <span class="nav-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="M4 13h6V4H4v9zm0 7h6v-5H4v5zm10 0h6V11h-6v9zm0-16v5h6V4h-6z"/></svg>
        </span>
        <span>Dashboard</span>
      </button>
      <button class="nav-item" data-view="scanner">
        <span class="nav-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="M10 18a8 8 0 1 0-5.29-14.01A8 8 0 0 0 10 18zm11 3-5.4-5.4" stroke-width="2" fill="none" stroke-linecap="round"/></svg>
        </span>
        <span>Cyber Scanner</span>
      </button>
      <button class="nav-item" data-view="url">
        <span class="nav-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 0c2.5 2.6 4 6 4 10s-1.5 7.4-4 10m0-20c-2.5 2.6-4 6-4 10s1.5 7.4 4 10M2.5 9h19M2.5 15h19" fill="none" stroke-width="1.6"/></svg>
        </span>
        <span>URL Scanner</span>
      </button>
      <button class="nav-item" data-view="endpoints">
        <span class="nav-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2" fill="none" stroke-width="1.7"/><path d="M8 20h8m-4-4v4" fill="none" stroke-width="1.7" stroke-linecap="round"/></svg></span>
        <span>Endpoints</span>
      </button>
      <button class="nav-item" data-view="threat-map">
        <span class="nav-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 21s7-6.1 7-12a7 7 0 1 0-14 0c0 5.9 7 12 7 12z" fill="none" stroke-width="1.6"/><circle cx="12" cy="9" r="2.2" fill="none" stroke-width="1.6"/></svg></span>
        <span>Threat Map</span>
      </button>
      <button class="nav-item" data-view="network">
        <span class="nav-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="2.5" fill="none" stroke-width="1.6"/><circle cx="18.5" cy="5" r="2.5" fill="none" stroke-width="1.6"/><circle cx="18.5" cy="19" r="2.5" fill="none" stroke-width="1.6"/><path d="m7.2 10.8 9-4.6m-9 7 9 4.6" fill="none" stroke-width="1.6"/></svg></span>
        <span>Network</span>
      </button>
      <button class="nav-item" data-view="incidents">
        <span class="nav-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M12 3 3.5 19h17L12 3z" fill="none" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" fill="none" stroke-width="1.8" stroke-linecap="round"/></svg></span>
        <span>Incidents</span>
      </button>
      <button class="nav-item" data-view="reports">
        <span class="nav-ico" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z" fill="none" stroke-width="1.6"/><path d="M14 3v5h5M9 13h6m-6 4h6" fill="none" stroke-width="1.6" stroke-linecap="round"/></svg></span>
        <span>Reports</span>
      </button>
      <button class="nav-item" data-view="history">
        <span class="nav-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="M4 5h16v2H4zM4 11h16v2H4zM4 17h10v2H4z"/></svg>
        </span>
        <span>Scan History</span>
      </button>
      <button class="nav-item" data-view="settings">
        <span class="nav-ico" aria-hidden="true">
          <svg viewBox="0 0 24 24"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z" fill="none" stroke-width="1.6"/><path d="M19.4 13a7.5 7.5 0 0 0 0-2l2-1.5-2-3.4-2.4 1a7.6 7.6 0 0 0-1.7-1L15 3h-4l-.3 2.6a7.6 7.6 0 0 0-1.7 1l-2.4-1-2 3.4L6.6 11a7.5 7.5 0 0 0 0 2l-2 1.5 2 3.4 2.4-1a7.6 7.6 0 0 0 1.7 1L11 21h4l.3-2.6a7.6 7.6 0 0 0 1.7-1l2.4 1 2-3.4-2-1.5z" fill="none" stroke-width="1.3"/></svg>
        </span>
        <span>Settings</span>
      </button>
    </nav>

    <div class="sidebar-footer">
      <button class="theme-toggle" type="button" data-theme-toggle aria-label="Switch to light mode" title="Switch to light mode">
        <svg class="theme-icon theme-icon--sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/></svg>
        <svg class="theme-icon theme-icon--moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20.8 14.2A8.8 8.8 0 0 1 9.8 3.2 8.8 8.8 0 1 0 20.8 14.2z"/></svg>
        <span data-theme-label>Light mode</span>
      </button>
      <div class="status-chip"> 
        <span class="dot"></span> Jhon Faith
      </div>
      <div class="account-row">
        <span class="account-avatar" aria-hidden="true">CS</span>
        <a class="account-copy" href="user.php" aria-label="Open your profile"><strong id="sessionUserName"><?php echo htmlspecialchars($_SESSION['user']['name'], ENT_QUOTES, 'UTF-8'); ?></strong><small>My profile</small></a>
        <button class="logout-btn" id="logoutBtn" type="button" aria-label="Sign out" title="Sign out">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 17l5-5-5-5m5 5H3m9-9h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
      </div>
    </div>
  </aside>

  
  <header class="topbar">
    <button class="menu-btn" id="menuBtn" aria-label="Open menu">
      <svg viewBox="0 0 24 24"><path d="M3 6h18M3 12h18M3 18h18" stroke-width="2" stroke-linecap="round"/></svg>
    </button>
    <span class="topbar-title">Cyber Shield</span>
  </header>
  <div class="sidebar-overlay" id="overlay"></div>

  
  <main class="main">

    
    <section class="view active" id="view-dashboard">
      <div class="view-head">
        <div>
          <h1>Dashboard</h1>
          <p class="subhead">All your scan data at a glance.</p>
        </div>
        <div class="head-actions">
          <button class="btn btn-primary" data-goto="scanner">
            <svg viewBox="0 0 24 24" class="btn-ico"><path d="M12 5v14M5 12h14" stroke-width="2" stroke-linecap="round"/></svg>
            New Scan
          </button>
        </div>
      </div>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-ico stat-ico--total">
            <svg viewBox="0 0 24 24"><path d="M9 3h6l2 4h3v13H4V7h3l2-4z" fill="none" stroke-width="1.6"/><path d="M9 12l2 2 4-4" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div class="stat-meta">
            <span class="stat-label">Total Scans</span>
            <span class="stat-value" id="stat-total">1,248</span>
            <span class="stat-delta">Account scan records</span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-ico stat-ico--safe">
            <svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 5-3 8.5-7 9-4-.5-7-4-7-9V6l7-3z" fill="none" stroke-width="1.6"/><path d="M9 12l2 2 4-4" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
          </div>
          <div class="stat-meta">
            <span class="stat-label">Safe Scans</span>
            <span class="stat-value" id="stat-safe">1,100</span>
            <span class="stat-delta">No threat indicators</span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-ico stat-ico--suspicious">
            <svg viewBox="0 0 24 24"><path d="M12 3l9 16H3L12 3z" fill="none" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v5" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="17" r="0.9"/></svg>
          </div>
          <div class="stat-meta">
            <span class="stat-label">Suspicious Scans</span>
            <span class="stat-value" id="stat-suspicious">104</span>
            <span class="stat-delta stat-delta--flat">Flagged for review</span>
          </div>
        </div>

        <div class="stat-card">
          <div class="stat-ico stat-ico--threat">
            <svg viewBox="0 0 24 24"><path d="M12 2l1.8 4.6L18 8l-4.2 1.4L12 14l-1.8-4.6L6 8l4.2-1.4L12 2z" fill="none" stroke-width="1.4" stroke-linejoin="round"/><path d="M5 17l1.2 3L9 21" stroke-width="1.4" stroke-linecap="round"/><path d="M19 17l-1.2 3L15 21" stroke-width="1.4" stroke-linecap="round"/></svg>
          </div>
          <div class="stat-meta">
            <span class="stat-label">Threats Detected</span>
            <span class="stat-value" id="stat-threats">42</span>
            <span class="stat-delta stat-delta--down">Reported by demo scanner</span>
          </div>
        </div>
      </div>

      <div class="panel-grid">
        <div class="panel">
          <div class="panel-head">
            <h2>Recent Activity</h2>
            <button class="link-btn" data-goto="history">View all</button>
          </div>
          <div class="mini-list" id="recent-activity"></div>
        </div>

        <div class="panel panel--tips">
          <div class="panel-head">
            <h2>System Status</h2>
          </div>
          <ul class="status-list">
            <li><span class="status-dot status-dot--warn"></span> Detection engine <strong>Demo mode</strong></li>
            <li><span class="status-dot status-dot--warn"></span> Signature database <strong>Simulated</strong></li>
            <li><span class="status-dot status-dot--safe" id="realtimeStatusDot"></span> Real-time protection <strong id="realtimeStatus">Active</strong></li>
            <li><span class="status-dot status-dot--warn"></span> Last file scan <strong id="lastFileScan">No scans yet</strong></li>
          </ul>
        </div>
      </div>
    </section>

    
    <section class="view" id="view-endpoints">
      <div class="view-head">
        <div><h1>Endpoints</h1><p class="subhead">Managed devices and their current protection posture.</p></div>
        <div class="head-actions"><label class="search-box"><svg viewBox="0 0 24 24"><path d="M10 18a8 8 0 1 0-5.29-14.01A8 8 0 0 0 10 18zm11 3-5.4-5.4" stroke-width="2" fill="none" stroke-linecap="round"/></svg><input id="endpointSearch" type="search" placeholder="Search endpoints" aria-label="Search endpoints"></label></div>
      </div>
      <div class="metric-strip">
        <div class="metric-item"><span>Managed devices</span><strong id="endpointCount">0</strong></div>
        <div class="metric-item"><span>Protected</span><strong class="text-safe" id="protectedEndpointCount">0</strong></div>
        <div class="metric-item"><span>Needs attention</span><strong class="text-warn" id="attentionEndpointCount">0</strong></div>
        <div class="metric-item"><span>Last check-in</span><strong id="endpointLastCheckin">—</strong></div>
      </div>
      <div class="table-card">
        <div class="section-toolbar"><h2>Device inventory</h2><span class="table-note">Managed endpoints</span></div>
        <div class="table-scroll"><table class="history-table endpoint-table"><thead><tr><th>Device</th><th>Owner</th><th>Platform</th><th>Last seen</th><th>Protection</th></tr></thead><tbody id="endpointTableBody"></tbody></table></div><p class="empty-state" id="endpointEmpty" hidden>No endpoints match your search.</p>
      </div>
    </section>

    <section class="view" id="view-threat-map">
      <div class="view-head"><div><h1>Threat Map</h1><p class="subhead">Global activity observed by your threat intelligence feed.</p></div><div class="head-actions"><div class="segmented" role="group" aria-label="Threat map time range"><button class="segment active" data-range="24h">24 hours</button><button class="segment" data-range="7d">7 days</button><button class="segment" data-range="30d">30 days</button></div></div></div>
      <div class="map-layout">
        <div class="panel map-panel"><div class="panel-head"><div><h2>Live threat activity</h2><p class="panel-kicker">Last updated moments ago</p></div><span class="live-label"><i></i> LIVE</span></div>
          <div class="map-canvas" role="img" aria-label="Illustrative world map showing threat activity across North America, Europe, and Asia">
            <svg class="world-map" viewBox="0 0 900 430" aria-hidden="true">
              <defs><pattern id="mapGrid" width="36" height="36" patternUnits="userSpaceOnUse"><path d="M36 0H0V36" fill="none" stroke="#29405b" stroke-width=".7"/></pattern></defs>
              <rect width="900" height="430" fill="url(#mapGrid)"/>
              <g class="land-shapes" fill="#18304a" stroke="#34516e" stroke-width="1.5"><path d="m91 102 31-23 40 4 17 17 40 7 18 22-12 22-31 7-12 28-28 13-7 27-28-5-16-27-24-8-15-31 5-24-16-16z"/><path d="m225 240 28 8 17 28-8 29 17 23-11 42-19 37-17-21-7-37-18-30 7-37z"/><path d="m394 102 30-21 45 4 17 16 39-3 25 14 31-8 27 11 39-1 36 19-9 18-39 6-21 17-32-8-17 20-28-3-25 19-32-5-22-19-34 1-17-14-36-3-21-24 14-18-13-17z"/><path d="m451 216 30 1 25 20 16 31-8 34-26 44-21 33-19-17-5-31-19-28 7-29-14-24 10-22z"/><path d="m666 270 41-16 53 8 29 22-16 28-42 9-26 21-42-9-25-26z"/></g>
              <g class="map-routes"><path d="M177 142Q399 70 560 153T741 194"/><path d="M177 142Q260 230 470 279T741 194"/><path d="M560 153Q606 206 741 194"/></g>
              <g class="map-points"><circle cx="177" cy="142" r="8" class="point point--danger"/><circle cx="399" cy="132" r="6" class="point point--warn"/><circle cx="560" cy="153" r="9" class="point point--danger"/><circle cx="741" cy="194" r="7" class="point point--warn"/><circle cx="470" cy="279" r="5" class="point point--safe"/><circle cx="650" cy="142" r="4" class="point point--safe"/></g>
            </svg>
            <span class="map-label map-label--na">NORTH AMERICA</span><span class="map-label map-label--eu">EUROPE</span><span class="map-label map-label--apac">ASIA PACIFIC</span>
            <div class="map-legend"><span><i class="legend-danger"></i>Malicious</span><span><i class="legend-warn"></i>Suspicious</span><span><i class="legend-safe"></i>Blocked</span></div>
          </div>
        </div>
        <aside class="panel attack-panel"><div class="panel-head"><h2>Top source regions</h2><span class="table-note" id="mapRangeLabel">24h</span></div>
          <div id="regionList"></div>
          <div class="feed-note"><span class="status-dot status-dot--safe"></span>Threat feed operational</div>
        </aside>
      </div>
    </section>

    <section class="view" id="view-network">
      <div class="view-head"><div><h1>Network</h1><p class="subhead">Connections and traffic monitored across your environment.</p></div>            <div class="head-actions"><a class="btn btn-outline" href="network.php">Detailed network view</a><button class="btn btn-outline" id="refreshNetworkBtn"><svg viewBox="0 0 24 24" class="btn-ico"><path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4m-4 5a8 8 0 0 0 14.9 3M20 20v-4h-4" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>Refresh</button></div></div>
      <div class="metric-strip"><div class="metric-item"><span>Connected devices</span><strong id="networkDevices">0</strong></div><div class="metric-item"><span>Active connections</span><strong id="activeConnections">0</strong></div><div class="metric-item"><span>Blocked requests</span><strong class="text-warn" id="blockedRequests">0</strong></div><div class="metric-item"><span>Network health</span><strong class="text-safe" id="networkHealth">—</strong></div></div>
      <div class="network-layout"><div class="panel topology-panel"><div class="panel-head"><div><h2>Network topology</h2><p class="panel-kicker">Enterprise office · Updated just now</p></div><span class="badge badge--safe">Secure</span></div>
        <div class="topology-canvas"><svg viewBox="0 0 860 410" role="img" aria-label="Network topology connecting gateway, core switch, and endpoint groups"><g class="topology-lines"><path d="M430 80V156M430 156 205 270M430 156 430 270M430 156 655 270M205 270V337M430 270V337M655 270V337"/></g><g class="topology-node topology-node--gateway" transform="translate(365 35)"><rect width="130" height="88" rx="14"/><path d="M65 18v23m-14-11h28M52 48h26"/><text x="65" y="75">GATEWAY</text></g><g class="topology-node" transform="translate(365 142)"><rect width="130" height="82" rx="14"/><circle cx="65" cy="28" r="10"/><path d="M55 28h20M65 18v20"/><text x="65" y="66">CORE SWITCH</text></g><g class="topology-node topology-node--leaf" transform="translate(140 252)"><rect width="130" height="82" rx="14"/><path d="M52 20h26v20H52zM60 47h10"/><text x="65" y="68">FINANCE · 64</text></g><g class="topology-node topology-node--leaf" transform="translate(365 252)"><rect width="130" height="82" rx="14"/><path d="M52 20h26v20H52zM60 47h10"/><text x="65" y="68">ENGINEERING · 92</text></g><g class="topology-node topology-node--alert" transform="translate(590 252)"><rect width="130" height="82" rx="14"/><path d="M65 17 78 41H52zM65 25v7m0 4v.1"/><text x="65" y="68">GUEST WIFI · 92</text></g><g class="topology-labels"><text x="430" y="20">INTERNET</text><text x="205" y="365">VLAN 10</text><text x="430" y="365">VLAN 20</text><text x="655" y="365">VLAN 30</text></g></svg></div>
      </div><div class="panel traffic-panel"><div class="panel-head"><h2>Traffic summary</h2><span class="table-note">Last 24 hours</span></div><div class="traffic-total"><strong id="trafficTotal">0</strong><span>TB transferred</span></div><div class="traffic-meter"><i id="trafficMeterFill"></i></div><div class="traffic-legend"><span><i class="traffic-in"></i>Inbound <strong id="inboundTraffic">0 TB</strong></span><span><i class="traffic-out"></i>Outbound <strong id="outboundTraffic">0 TB</strong></span></div><div class="divider"></div><div class="panel-head"><h2>Recent incidents</h2><button class="link-btn" data-goto="incidents">View incidents</button></div><div id="recentBlocks"></div></div></div>
    </section>

    <section class="view" id="view-incidents">
      <div class="view-head"><div><h1>Incidents</h1><p class="subhead">Investigate and track security events detected across your organization.</p></div><div class="head-actions"><label class="search-box"><svg viewBox="0 0 24 24"><path d="M10 18a8 8 0 1 0-5.29-14.01A8 8 0 0 0 10 18zm11 3-5.4-5.4" stroke-width="2" fill="none" stroke-linecap="round"/></svg><input id="incidentSearch" type="search" placeholder="Search incidents" aria-label="Search incidents"></label></div></div>
      <div class="metric-strip incident-metrics"><div class="metric-item"><span>Open incidents</span><strong id="openIncidentCount">0</strong></div><div class="metric-item"><span>Critical</span><strong class="text-danger" id="criticalIncidentCount">0</strong></div><div class="metric-item"><span>In progress</span><strong class="text-warn" id="inProgressIncidentCount">0</strong></div><div class="metric-item"><span>Resolved today</span><strong class="text-safe" id="resolvedTodayCount">0</strong></div></div>
      <div class="incident-list" id="incidentList"></div><p class="empty-state" id="incidentEmpty" hidden>No incidents match your search.</p>
    </section>

    <section class="view" id="view-reports">
      <div class="view-head"><div><h1>Reports</h1><p class="subhead">Review security activity and export scan data for your records.</p></div>            <div class="head-actions"><a class="btn btn-outline" href="report.php">Full report</a><button class="btn btn-primary" id="exportReportBtn"><svg viewBox="0 0 24 24" class="btn-ico"><path d="M12 3v12m0 0 5-5m-5 5-5-5M4 17v4h16v-4" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>Export report</button></div></div>
      <div class="report-summary"><div class="report-summary-head"><div><span class="eyebrow">SECURITY OVERVIEW</span><h2>Weekly activity</h2><p id="reportPeriod">Last 7 days</p></div><span class="report-badge"><span class="status-dot status-dot--safe"></span> All systems monitored</span></div>
        <div class="report-chart" role="img" aria-label="Weekly scan activity chart"><div class="chart-y-labels"><span>400</span><span>300</span><span>200</span><span>100</span><span>0</span></div><div class="chart-area"><div class="chart-gridlines"><i></i><i></i><i></i><i></i><i></i></div><svg viewBox="0 0 700 220" preserveAspectRatio="none"><defs><linearGradient id="scanFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#39c6ff" stop-opacity=".28"/><stop offset="1" stop-color="#39c6ff" stop-opacity="0"/></linearGradient></defs><path class="chart-fill" d="M0 166 116 132 233 146 350 83 466 104 583 54 700 72V220H0z"/><path class="chart-line" d="M0 166 116 132 233 146 350 83 466 104 583 54 700 72"/><g class="chart-dots"><circle cx="0" cy="166" r="4"/><circle cx="116" cy="132" r="4"/><circle cx="233" cy="146" r="4"/><circle cx="350" cy="83" r="4"/><circle cx="466" cy="104" r="4"/><circle cx="583" cy="54" r="4"/><circle cx="700" cy="72" r="4"/></g></svg><div class="chart-x-labels"><span>Fri</span><span>Sat</span><span>Sun</span><span>Mon</span><span>Tue</span><span>Wed</span><span>Thu</span></div></div></div>
        <div class="chart-legend"><span><i></i> Scans performed</span><strong id="reportTotalScans">0 scans in last 7 days</strong></div>
      </div>
      <div class="report-bottom"><div class="panel"><div class="panel-head"><h2>Detection breakdown</h2><span class="table-note">All scans</span></div><div class="breakdown-row"><span class="breakdown-color breakdown-safe"></span><span>Safe</span><strong id="reportSafeCount">0</strong><div><i id="reportSafeBar" style="width:0%"></i></div></div><div class="breakdown-row"><span class="breakdown-color breakdown-warn"></span><span>Suspicious</span><strong id="reportSuspiciousCount">0</strong><div><i id="reportSuspiciousBar" style="width:0%"></i></div></div><div class="breakdown-row"><span class="breakdown-color breakdown-danger"></span><span>Threats</span><strong id="reportThreatCount">0</strong><div><i id="reportThreatBar" style="width:0%"></i></div></div></div>
        <div class="panel report-insight"><div class="panel-head"><h2>Scan overview</h2><span class="insight-icon">↗</span></div><p id="reportInsight">Loading scan summary…</p><div class="insight-foot"><span class="status-dot status-dot--safe"></span> Results are simulated by this demo scanner</div></div></div>
      <p class="disclaimer report-disclaimer">Report data is sample dashboard data. Export creates a CSV snapshot of the scan history currently shown.</p>
    </section>

    <section class="view" id="view-scanner">
      <div class="view-head">
        <div>
          <h1>Cyber Shield Scanner</h1>
          <p class="subhead">Upload a file to check it for potential security threats.</p>
        </div>
      </div>

      <div class="scan-card">
        <div class="scan-card-icon">
          <svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 5-3 8.5-7 9-4-.5-7-4-7-9V6l7-3z" fill="none" stroke-width="1.5"/></svg>
        </div>
        <h2>Scan Your File</h2>
        <p class="scan-desc">Check your file for potential security threats. Supported: .exe, .zip, .pdf, .doc, .apk and more.</p>

        <div class="dropzone" id="dropzone">
          <svg class="dropzone-ico" viewBox="0 0 24 24"><path d="M12 16V4m0 0L7 9m5-5l5 5" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3" stroke-width="1.8" fill="none"/></svg>
          <p class="dropzone-text">Drag &amp; drop your file here</p>
          <p class="dropzone-sub">or</p>
          <label class="btn btn-outline" for="fileInput">Choose File</label>
          <input type="file" id="fileInput" hidden>
          <p class="file-chosen" id="fileChosen"></p>
        </div>

        <button class="btn btn-primary btn-wide" id="startScanBtn" disabled>
          <svg viewBox="0 0 24 24" class="btn-ico"><path d="M10 18a8 8 0 1 0-5.29-14.01A8 8 0 0 0 10 18zm11 3-5.4-5.4" stroke-width="2" fill="none" stroke-linecap="round"/></svg>
          Start Scan
        </button>

        <div class="scan-progress" id="fileScanProgress">
          <div class="radial" id="fileRadial">
            <svg viewBox="0 0 120 120">
              <circle class="radial-track" cx="60" cy="60" r="52"></circle>
              <circle class="radial-fill" id="fileRadialFill" cx="60" cy="60" r="52"></circle>
            </svg>
            <span class="radial-pct" id="fileRadialPct">0%</span>
          </div>
          <p class="scan-status-text">Scanning for potential threats…</p>
          <p class="scan-status-sub" id="fileScanSub">Checking file signatures…</p>
        </div>

        <div class="result-box" id="fileResultBox"></div>
      </div>
    </section>

    
    <section class="view" id="view-url">
      <div class="view-head">
        <div>
          <h1>URL Scanner</h1>
          <p class="subhead">Check a website or link for phishing and malicious activity.</p>
        </div>
      </div>

      <div class="scan-card">
        <div class="scan-card-icon">
          <svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 0c2.5 2.6 4 6 4 10s-1.5 7.4-4 10m0-20c-2.5 2.6-4 6-4 10s1.5 7.4 4 10M2.5 9h19M2.5 15h19" fill="none" stroke-width="1.3"/></svg>
        </div>
        <h2>Scan a URL</h2>
        <p class="scan-desc">Paste a website link below to check it for malicious content.</p>

        <div class="url-input-row">
          <svg class="url-ico" viewBox="0 0 24 24"><path d="M9.5 14.5l5-5M8 12l-1.5 1.5a3 3 0 0 0 4.24 4.24L12 16.5M16 12l1.5-1.5a3 3 0 0 0-4.24-4.24L12 7.5" fill="none" stroke-width="1.6" stroke-linecap="round"/></svg>
          <input type="text" id="urlInput" placeholder="https://example.com/link">
        </div>

        <button class="btn btn-primary btn-wide" id="startUrlScanBtn" disabled>
          <svg viewBox="0 0 24 24" class="btn-ico"><path d="M10 18a8 8 0 1 0-5.29-14.01A8 8 0 0 0 10 18zm11 3-5.4-5.4" stroke-width="2" fill="none" stroke-linecap="round"/></svg>
          Scan URL
        </button>

        <div class="scan-progress" id="urlScanProgress">
          <div class="radial" id="urlRadial">
            <svg viewBox="0 0 120 120">
              <circle class="radial-track" cx="60" cy="60" r="52"></circle>
              <circle class="radial-fill" id="urlRadialFill" cx="60" cy="60" r="52"></circle>
            </svg>
            <span class="radial-pct" id="urlRadialPct">0%</span>
          </div>
          <p class="scan-status-text">Scanning for potential threats…</p>
          <p class="scan-status-sub" id="urlScanSub">Resolving domain reputation…</p>
        </div>

        <div class="result-box" id="urlResultBox"></div>
      </div>
    </section>

    
    <section class="view" id="view-history">
      <div class="view-head">
        <div>
          <h1>Scan History</h1>
          <p class="subhead">A record of every file and URL scan performed.</p>
        </div>
        <div class="head-actions">
          <div class="search-box">
            <svg viewBox="0 0 24 24"><path d="M10 18a8 8 0 1 0-5.29-14.01A8 8 0 0 0 10 18zm11 3-5.4-5.4" stroke-width="2" fill="none" stroke-linecap="round"/></svg>
            <input type="text" id="historySearch" placeholder="Search history…">
          </div>
        </div>
      </div>

      <div class="table-card">
        <div class="table-scroll">
          <table class="history-table">
            <thead>
              <tr>
                <th>File / URL</th>
                <th>Scan Date</th>
                <th>Scan Type</th>
                <th>Result</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="historyTableBody"></tbody>
          </table>
        </div>
        <p class="empty-state" id="historyEmpty" hidden>No scans match your search.</p>
      </div>
    </section>

    
    <section class="view" id="view-settings">
      <div class="view-head">
        <div>
          <h1>Settings</h1>
          <p class="subhead">Manage how Cyber Shield scans and protects your system.</p>
        </div>
      </div>

      <div class="settings-grid">
        <div class="panel">
          <div class="panel-head"><h2>Scan Preferences</h2></div>
          <div class="setting-row">
            <div>
              <p class="setting-title">Real-time protection</p>
              <p class="setting-sub">Automatically scan files as they're downloaded.</p>
            </div>
            <label class="switch"><input type="checkbox" data-setting="realtime_protection" checked><span class="slider"></span></label>
          </div>
          <div class="setting-row">
            <div>
              <p class="setting-title">Deep scan mode</p>
              <p class="setting-sub">Perform a more thorough, slower scan on every file.</p>
            </div>
            <label class="switch"><input type="checkbox" data-setting="deep_scan"><span class="slider"></span></label>
          </div>
          <div class="setting-row">
            <div>
              <p class="setting-title">Auto-quarantine threats</p>
              <p class="setting-sub">Isolate detected threats automatically.</p>
            </div>
            <label class="switch"><input type="checkbox" data-setting="auto_quarantine" checked><span class="slider"></span></label>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><h2>Notifications</h2></div>
          <div class="setting-row">
            <div>
              <p class="setting-title">Email alerts</p>
              <p class="setting-sub">Get notified when a threat is detected.</p>
            </div>
            <label class="switch"><input type="checkbox" data-setting="email_alerts" checked><span class="slider"></span></label>
          </div>
          <div class="setting-row">
            <div>
              <p class="setting-title">Weekly summary report</p>
              <p class="setting-sub">Receive a scan summary every Monday.</p>
            </div>
            <label class="switch"><input type="checkbox" data-setting="weekly_summary"><span class="slider"></span></label>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><h2>About</h2></div>
          <div class="about-row"><span>Engine version</span><span>Cyber Shield 3.2.1</span></div>
          <div class="about-row"><span>Signature database</span><span>v24.9.1</span></div>
          <div class="about-row"><span>Last updated</span><span>Sept 9, 2026</span></div>
          <p class="disclaimer">This is a front-end demonstration only. Scan results shown are simulated and do not reflect real malware analysis.</p>
        </div>
      </div>
    </section>

  </main>
</div>

<script src="js/script.js"></script>
</body>
</html>
