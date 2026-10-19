(function () {
  "use strict";

  const auth = window.CyberShieldAuth;
  const canScan = document.body.dataset.canScan === "1";
  const canManageComputers = document.body.dataset.canManageComputers === "1";
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await auth.logout();
    window.location.replace("login.php");
  });

  let history = [];
  let dashboard = null;
  let computers = [];

  /* ---------- Navigation ---------- */
  const navItems = document.querySelectorAll(".nav-item[data-view]");
  const views = document.querySelectorAll(".view");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("overlay");
  const menuBtn = document.getElementById("menuBtn");

  function goToView(name) {
    if (!document.getElementById("view-" + name)) return;
    navItems.forEach((btn) => btn.classList.toggle("active", btn.dataset.view === name));
    views.forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
    closeSidebar();
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (name === "file-activity") loadFileEvents();
  }

  navItems.forEach((btn) => btn.addEventListener("click", () => goToView(btn.dataset.view)));
  document.querySelectorAll("[data-goto]").forEach((btn) =>
    btn.addEventListener("click", () => goToView(btn.dataset.goto))
  );
  const requestedView = new URLSearchParams(window.location.search).get("view");
  if (requestedView && [...navItems].some((button) => button.dataset.view === requestedView)) {
    goToView(requestedView);
  }

  function openSidebar() { sidebar.classList.add("open"); overlay.classList.add("open"); }
  function closeSidebar() { sidebar.classList.remove("open"); overlay.classList.remove("open"); }
  menuBtn.addEventListener("click", openSidebar);
  overlay.addEventListener("click", closeSidebar);

  /* ---------- Dashboard: recent activity ---------- */
  const STATUS_COLORS = {
    safe: ["var(--safe-bg)", "var(--safe)"],
    suspicious: ["var(--warn-bg)", "var(--warn)"],
    threat: ["var(--danger-bg)", "var(--danger)"],
    pending: ["var(--neutral-bg)", "var(--text-secondary)"],
    unknown: ["var(--neutral-bg)", "var(--text-secondary)"],
  };

  function renderRecentActivity() {
    const container = document.getElementById("recent-activity");
    container.innerHTML = "";
    const rows = canScan
      ? history.slice(0, 5).map((item) => ({ status: item.status, title: item.name, time: item.date.split(" ")[0] }))
      : (dashboard?.recentFileEvents || []).map((event) => ({
        status: event.eventType === "deleted" ? "suspicious" : "pending",
        title: `${event.computer}: ${event.eventType} ${event.fileName}`,
        time: relativeTime(event.detectedAt),
      }));
    rows.forEach((item) => {
      const row = document.createElement("div");
      row.className = "mini-row";
      const [bg, fg] = STATUS_COLORS[item.status] || STATUS_COLORS.unknown;
      row.innerHTML = `
        <span class="mini-icon" style="background:${bg}; color:${fg}">
          ${statusIconSVG(item.status)}
        </span>
        <span class="mini-title">${escapeHTML(item.title)}</span>
        <span class="mini-time">${escapeHTML(item.time)}</span>
      `;
      container.appendChild(row);
    });
    document.getElementById("recentActivityEmpty").hidden = rows.length !== 0;
  }

  function statusIconSVG(status) {
    if (status === "safe") return '<svg viewBox="0 0 24 24"><path d="M9 12l2 2 4-4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    if (status === "suspicious") return '<svg viewBox="0 0 24 24"><path d="M12 3l9 16H3L12 3z" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v5" stroke-width="1.8" stroke-linecap="round"/></svg>';
    if (status === "pending" || status === "unknown") return '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8" stroke-width="1.6"/><path d="M12 8v4l2.5 2.5" stroke-width="1.6" stroke-linecap="round"/></svg>';
    return '<svg viewBox="0 0 24 24"><path d="M12 2l1.8 4.6L18 8l-4.2 1.4L12 14l-1.8-4.6L6 8l4.2-1.4L12 2z" stroke-width="1.4" stroke-linejoin="round"/></svg>';
  }

  function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
  }

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function renderStats() {
    if (!canScan) return;
    const total = history.length;
    const safe = history.filter((h) => h.status === "safe").length;
    const suspicious = history.filter((h) => h.status === "suspicious").length;
    const threats = history.filter((h) => h.status === "threat").length;
    setText("stat-total", total.toLocaleString());
    setText("stat-safe", safe.toLocaleString());
    setText("stat-suspicious", suspicious.toLocaleString());
    setText("stat-threats", threats.toLocaleString());
  }

  /* ---------- Scan History table ---------- */
  function renderHistoryTable(filter = "") {
    const tbody = document.getElementById("historyTableBody");
    if (!tbody) return;
    const emptyState = document.getElementById("historyEmpty");
    const q = filter.trim().toLowerCase();
    const rows = history.filter((h) => h.name.toLowerCase().includes(q) || (h.sha256 || "").includes(q));

    tbody.innerHTML = "";
    emptyState.hidden = rows.length !== 0;

    rows.forEach((item) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="cell-name">${escapeHTML(item.name)}${item.sha256 ? `<span class="hash-line" title="SHA-256">${escapeHTML(item.sha256)}</span>` : ""}</td>
        <td>${escapeHTML(item.date)}</td>
        <td><span class="type-pill">${item.type === "File" ? fileTypeSVG() : linkTypeSVG()} ${escapeHTML(item.type)}</span></td>
        <td>${escapeHTML(item.result)}</td>
        <td><span class="badge badge--${escapeHTML(item.status)}">${statusLabel(item.status)}</span></td>
        <td class="scan-actions">${item.scanRequestId ? `<button class="link-btn" type="button" data-view-scan="${Number(item.scanRequestId)}">Details</button>` : ""}<button class="delete-scan-btn" type="button" data-scan-id="${escapeHTML(String(item.id))}" aria-label="Delete scan record" title="Delete scan record"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M10 11v6m4-6v6M5 7l1 14h12l1-14M9 7V4h6v3"/></svg></button></td>
      `;
      tbody.appendChild(tr);
    });
  }

  function statusLabel(status) {
    if (status === "safe") return "No detections";
    if (status === "suspicious") return "Suspicious";
    if (status === "pending") return "Pending";
    if (status === "unknown") return "Not scanned";
    return "Threat";
  }
  function fileTypeSVG() {
    return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 2h9l5 5v15H6z"/></svg>';
  }
  function linkTypeSVG() {
    return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9.5 14.5l5-5M8 12l-1.5 1.5a3 3 0 0 0 4.24 4.24L12 16.5M16 12l1.5-1.5a3 3 0 0 0-4.24-4.24L12 7.5"/></svg>';
  }

  async function reloadScanData() {
    if (!canScan) return;
    [history, dashboard] = await Promise.all([auth.getHistory(), auth.getDashboard()]);
    renderStats();
    renderRecentActivity();
    renderHistoryTable(document.getElementById("historySearch").value);
    renderDashboard(dashboard);
  }

  if (canScan) {
    document.getElementById("historySearch").addEventListener("input", (e) => {
      renderHistoryTable(e.target.value);
    });

    document.getElementById("historyTableBody").addEventListener("click", async (event) => {
      const detailsButton = event.target.closest("[data-view-scan]");
      if (detailsButton) {
        goToView("scanner");
        const scan = await auth.getScanStatus(detailsButton.dataset.viewScan).catch((error) => {
          window.alert("Could not load scan: " + error.message);
          return null;
        });
        if (scan) trackScan(scan, fileResultBox);
        return;
      }
      const button = event.target.closest("[data-scan-id]");
      if (!button || button.disabled) return;
      if (!window.confirm("Delete this scan record? This action cannot be undone.")) return;

      button.disabled = true;
      try {
        await auth.deleteScan(button.dataset.scanId);
        await reloadScanData();
      } catch (error) {
        button.disabled = false;
        window.alert("Could not delete scan record: " + error.message);
        console.error("Could not delete scan record:", error);
      }
    });
  }

  function relativeTime(value) {
    if (!value) return "Never";
    const timestamp = new Date(String(value).replace(" ", "T")).getTime();
    const minutes = Math.max(0, Math.floor((Date.now() - timestamp) / 60000));
    if (minutes < 1) return "Just now";
    if (minutes < 60) return minutes + " min ago";
    if (minutes < 1440) return Math.floor(minutes / 60) + " hours ago";
    if (minutes < 2880) return "Yesterday";
    return new Date(timestamp).toLocaleDateString();
  }

  function formatBytes(bytes) {
    if (bytes == null || bytes === "") return "—";
    const value = Number(bytes);
    if (value < 1024) return value + " B";
    const units = ["KB", "MB", "GB", "TB"];
    let size = value / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
    return size.toFixed(size < 10 ? 1 : 0) + " " + units[unit];
  }

  /* ---------- Lab computers ---------- */
  const CONNECTION_LABELS = { ethernet: "Ethernet / LAN", wifi: "Wi-Fi", hotspot: "Mobile hotspot", unknown: "Unknown link" };

  function computerStatus(computer) {
    if (!computer.authorized) return ["Pending approval", "suspicious"];
    if (computer.threats > 0) return ["Threat found", "threat"];
    if (computer.online) return ["Online", "safe"];
    return ["Offline", "unknown"];
  }

  function renderEndpoints(list) {
    computers = list;
    const tbody = document.getElementById("endpointTableBody");
    tbody.innerHTML = list.map((computer) => {
      const [label, tone] = computerStatus(computer);
      const action = canManageComputers
        ? `<td><button class="btn btn-outline incident-action" type="button" data-authorize-computer="${computer.id}" data-authorized="${computer.authorized ? "0" : "1"}">${computer.authorized ? "Revoke" : "Authorize"}</button></td>`
        : "";
      return `<tr><td class="cell-name">${escapeHTML(computer.hostname)}<span class="hash-line">${escapeHTML(computer.macAddress || "")}</span></td>`
        + `<td>${escapeHTML(computer.labLocation || "—")}</td>`
        + `<td>${escapeHTML(computer.ipAddress || "—")}<span class="hash-line">${escapeHTML(CONNECTION_LABELS[computer.connectionType] || CONNECTION_LABELS.unknown)}</span></td>`
        + `<td>${escapeHTML(computer.os || "—")}<span class="hash-line">Agent ${escapeHTML(computer.agentVersion || "?")} · ${Number(computer.events24h).toLocaleString()} events today</span></td>`
        + `<td>${escapeHTML(relativeTime(computer.lastHeartbeat))}</td>`
        + `<td><span class="badge badge--${tone}">${label}</span></td>${action}</tr>`;
    }).join("");
    const onlineCount = list.filter((item) => item.authorized && item.online).length;
    const attentionCount = list.filter((item) => !item.authorized || !item.online).length;
    setText("endpointCount", list.length.toLocaleString());
    setText("protectedEndpointCount", onlineCount.toLocaleString());
    setText("attentionEndpointCount", attentionCount.toLocaleString());
    const newest = list.map((item) => item.lastHeartbeat).filter(Boolean).sort().at(-1);
    setText("endpointLastCheckin", relativeTime(newest));
    filterEndpoints();

    const select = document.getElementById("fileEventComputer");
    const selected = select.value;
    select.innerHTML = '<option value="">All computers</option>' + list.map((computer) =>
      `<option value="${computer.id}">${escapeHTML(computer.hostname)}</option>`
    ).join("");
    select.value = selected;
  }

  function filterEndpoints() {
    const query = endpointSearch.value.trim().toLowerCase();
    const rows = [...document.querySelectorAll("#endpointTableBody tr")];
    let visible = 0;
    rows.forEach((row) => {
      const matches = row.textContent.toLowerCase().includes(query);
      row.hidden = !matches;
      if (matches) visible += 1;
    });
    document.getElementById("endpointEmpty").hidden = visible !== 0;
  }

  const endpointSearch = document.getElementById("endpointSearch");
  endpointSearch.addEventListener("input", filterEndpoints);

  document.getElementById("refreshComputersBtn").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      renderEndpoints(await auth.getComputers());
    } catch (error) {
      window.alert("Could not refresh lab computers: " + error.message);
    } finally {
      button.disabled = false;
    }
  });

  document.getElementById("endpointTableBody").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-authorize-computer]");
    if (!button || button.disabled) return;
    const authorize = button.dataset.authorized === "1";
    const computer = computers.find((item) => item.id === Number(button.dataset.authorizeComputer));
    const question = authorize
      ? `Authorize ${computer?.hostname}? Its agent will be allowed to report file events.`
      : `Revoke ${computer?.hostname}? Its agent will stop being accepted until authorized again.`;
    if (!window.confirm(question)) return;
    button.disabled = true;
    try {
      await auth.setComputerAuthorized(Number(button.dataset.authorizeComputer), authorize);
      renderEndpoints(await auth.getComputers());
    } catch (error) {
      button.disabled = false;
      window.alert("Could not update computer: " + error.message);
    }
  });

  /* ---------- File activity ---------- */
  const fileEventSearch = document.getElementById("fileEventSearch");
  const fileEventType = document.getElementById("fileEventType");
  const fileEventComputer = document.getElementById("fileEventComputer");
  let fileEventsRequestId = 0;
  let fileEventSearchTimer = null;

  function scanBadge(scan) {
    if (!scan) return '<span class="badge badge--unknown">Not scanned</span>';
    if (scan.status === "completed") {
      const tone = { clean: "safe", low: "suspicious", medium: "suspicious", high: "threat", critical: "threat" }[scan.riskLevel] || "unknown";
      const label = scan.riskLevel === "clean" ? "No detections" : scan.riskLevel.charAt(0).toUpperCase() + scan.riskLevel.slice(1) + " risk";
      return `<span class="badge badge--${tone}">${escapeHTML(label)} · ${escapeHTML(scan.detectionRatio)}</span>`;
    }
    const labels = {
      pending: "Pending", submitted: "Analysing", awaiting_upload: "Awaiting upload",
      not_found: "Not in VirusTotal", failed: "Scan failed",
    };
    return `<span class="badge badge--${scan.status === "failed" ? "suspicious" : "pending"}">${escapeHTML(labels[scan.status] || scan.status)}</span>`;
  }

  async function loadFileEvents() {
    const requestId = ++fileEventsRequestId;
    const params = {};
    if (fileEventSearch.value.trim()) params.q = fileEventSearch.value.trim();
    if (fileEventType.value) params.type = fileEventType.value;
    if (fileEventComputer.value) params.computer_id = fileEventComputer.value;
    try {
      const result = await auth.getFileEvents(params);
      if (requestId === fileEventsRequestId) renderFileEvents(result);
    } catch (error) {
      if (requestId === fileEventsRequestId) {
        document.getElementById("fileEventTableBody").innerHTML = "";
        const empty = document.getElementById("fileEventEmpty");
        empty.textContent = "File activity could not be loaded: " + error.message;
        empty.hidden = false;
      }
    }
  }

  function renderFileEvents(result) {
    const summary = result.summary || {};
    setText("fileEventsTotal", Number(summary.total24h || 0).toLocaleString());
    setText("fileEventsCreated", Number(summary.created24h || 0).toLocaleString());
    setText("fileEventsModified", Number(summary.modified24h || 0).toLocaleString());
    setText("fileEventsDeleted", Number(summary.deleted24h || 0).toLocaleString());
    const tbody = document.getElementById("fileEventTableBody");
    tbody.innerHTML = result.events.map((event) => {
      const action = canScan
        ? `<td>${event.sha256 ? `<button class="btn btn-outline incident-action" type="button" data-scan-event="${Number(event.id)}">Scan</button>` : '<span class="table-note">No hash</span>'}</td>`
        : "";
      return `<tr><td>${escapeHTML(event.detectedAt)}</td><td>${escapeHTML(event.computer)}</td>`
        + `<td><span class="type-pill">${escapeHTML(event.eventType)}</span></td>`
        + `<td class="cell-name">${escapeHTML(event.fileName)}<span class="hash-line" title="${escapeHTML(event.filePath)}">${escapeHTML(event.filePath)}</span></td>`
        + `<td>${escapeHTML(formatBytes(event.fileSize))}</td>`
        + `<td>${event.sha256 ? `<code class="hash-short" title="${escapeHTML(event.sha256)}">${escapeHTML(event.sha256.slice(0, 16))}…</code>` : "—"}</td>`
        + `<td>${scanBadge(event.scan)}</td>${action}</tr>`;
    }).join("");
    const empty = document.getElementById("fileEventEmpty");
    empty.textContent = "No file events match these filters.";
    empty.hidden = result.events.length !== 0;
  }

  fileEventSearch.addEventListener("input", () => {
    window.clearTimeout(fileEventSearchTimer);
    fileEventSearchTimer = window.setTimeout(loadFileEvents, 350);
  });
  fileEventType.addEventListener("change", loadFileEvents);
  fileEventComputer.addEventListener("change", loadFileEvents);
  document.getElementById("refreshFileEventsBtn").addEventListener("click", loadFileEvents);

  if (canScan) {
    document.getElementById("fileEventTableBody").addEventListener("click", async (event) => {
      const button = event.target.closest("[data-scan-event]");
      if (!button || button.disabled) return;
      button.disabled = true;
      button.textContent = "Scanning…";
      const box = document.getElementById("eventResultBox");
      try {
        const scan = await auth.scanFileEvent(Number(button.dataset.scanEvent));
        trackScan(scan, box, loadFileEvents);
        box.scrollIntoView({ behavior: "smooth", block: "nearest" });
        loadFileEvents();
        reloadScanData().catch(() => {});
      } catch (error) {
        button.disabled = false;
        button.textContent = "Scan";
        window.alert("Could not scan this file: " + error.message);
      }
    });
  }

  /* ---------- Incidents ---------- */
  function renderIncidents(incidents, counts) {
    const list = document.getElementById("incidentList");
    list.innerHTML = incidents.map((incident) => {
      const severity = incident.severity.toLowerCase();
      const badge = severity === "critical" || severity === "high" ? "threat" : "suspicious";
      const isResolved = incident.status === "resolved";
      const text = [incident.code, incident.title, incident.description, incident.category, severity].join(" ").toLowerCase();
      return `<article class="incident-row${isResolved ? " resolved" : ""}" data-search="${escapeHTML(text)}"><span class="incident-severity severity-${escapeHTML(severity)}"></span><div class="incident-main"><div class="incident-title-line"><h2>${escapeHTML(incident.title)}</h2><span class="badge badge--${badge}">${escapeHTML(severity.charAt(0).toUpperCase() + severity.slice(1))}</span></div><p>${escapeHTML(incident.description)}</p><div class="incident-meta"><span>${escapeHTML(incident.code)}</span><span>${escapeHTML(incident.category)}</span><time>${escapeHTML(relativeTime(incident.detectedAt))}</time></div></div><button class="btn btn-outline incident-action" data-incident-id="${Number(incident.id)}"${isResolved ? " disabled" : ""}>${isResolved ? "Resolved" : "Resolve"}</button></article>`;
    }).join("");
    setText("openIncidentCount", Number(counts.open_count || 0).toLocaleString());
    setText("criticalIncidentCount", Number(counts.critical_count || 0).toLocaleString());
    setText("inProgressIncidentCount", Number(counts.progress_count || 0).toLocaleString());
    setText("resolvedTodayCount", Number(counts.resolved_today || 0).toLocaleString());
    setText("stat-open-incidents", Number(counts.open_count || 0).toLocaleString());
    filterIncidents();
  }

  function filterIncidents() {
    const query = incidentSearch.value.trim().toLowerCase();
    const rows = [...document.querySelectorAll(".incident-row")];
    let visible = 0;
    rows.forEach((row) => {
      const matches = row.dataset.search.includes(query);
      row.hidden = !matches;
      if (matches) visible += 1;
    });
    document.getElementById("incidentEmpty").hidden = visible !== 0;
  }

  const incidentSearch = document.getElementById("incidentSearch");
  incidentSearch.addEventListener("input", filterIncidents);
  document.getElementById("incidentList").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-incident-id]");
    if (!button || button.disabled) return;
    button.disabled = true;
    try {
      await auth.resolveIncident(button.dataset.incidentId);
      dashboard = await auth.getDashboard();
      renderDashboard(dashboard);
    } catch (error) {
      button.disabled = false;
      console.error("Could not resolve incident:", error);
    }
  });

  function renderRegions(regions, range) {
    const maxCount = Math.max(1, ...regions.map((region) => Number(region.count)));
    document.getElementById("mapRangeLabel").textContent = range;
    document.getElementById("regionList").innerHTML = regions.map((region, index) => {
      const count = Number(region.count);
      const width = Math.max(2, count / maxCount * 100);
      return `<div class="region-row"><span class="region-rank">${String(index + 1).padStart(2, "0")}</span><span class="region-name">${escapeHTML(region.name)}</span><strong>${count.toLocaleString()}</strong><span class="region-bar"><i style="width:${width}%"></i></span></div>`;
    }).join("");
  }

  let threatMapRequestId = 0;
  async function loadThreatMap(range) {
    const requestId = ++threatMapRequestId;
    const regionList = document.getElementById("regionList");
    regionList.textContent = "Loading threat data…";
    try {
      const result = await auth.getThreatMap(range);
      if (requestId === threatMapRequestId) renderRegions(result.regions, result.range);
    } catch (error) {
      if (requestId === threatMapRequestId) regionList.textContent = "Threat data could not be loaded.";
      console.error("Could not load threat map data:", error);
    }
  }

  document.querySelectorAll(".segment[data-range]").forEach((button) => {
    button.addEventListener("click", () => {
      const range = button.dataset.range;
      document.querySelectorAll(".segment[data-range]").forEach((segment) => {
        segment.classList.toggle("active", segment === button);
        segment.setAttribute("aria-pressed", String(segment === button));
      });
      loadThreatMap(range);
    });
  });

  document.getElementById("refreshNetworkBtn").addEventListener("click", (event) => {
    const button = event.currentTarget;
    const kicker = document.querySelector(".topology-panel .panel-kicker");
    button.disabled = true;
    kicker.textContent = "Refreshing network status…";
    auth.getDashboard().then((data) => {
      dashboard = data;
      renderDashboard(data);
      kicker.textContent = "Enterprise office · Updated just now";
    }).catch((error) => {
      kicker.textContent = error.message;
    }).finally(() => { button.disabled = false; });
  });

  function renderReport() {
    if (!canScan) return;
    const totals = { safe: 0, suspicious: 0, threat: 0 };
    history.forEach((item) => { if (Object.hasOwn(totals, item.status)) totals[item.status] += 1; });
    const total = history.length;
    renderStats();
    document.getElementById("reportSafeCount").textContent = totals.safe.toLocaleString();
    document.getElementById("reportSuspiciousCount").textContent = totals.suspicious.toLocaleString();
    document.getElementById("reportThreatCount").textContent = totals.threat.toLocaleString();
    const safePercent = total ? totals.safe / total * 100 : 0;
    const suspiciousPercent = total ? totals.suspicious / total * 100 : 0;
    const threatPercent = total ? totals.threat / total * 100 : 0;
    document.getElementById("reportSafeBar").style.width = safePercent + "%";
    document.getElementById("reportSuspiciousBar").style.width = suspiciousPercent + "%";
    document.getElementById("reportThreatBar").style.width = threatPercent + "%";
    const activity = new Map((dashboard?.scanActivity || []).map((day) => [day.scan_date, Number(day.scan_count)]));
    const days = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (6 - index));
      const dateKey = [date.getFullYear(), String(date.getMonth() + 1).padStart(2, "0"), String(date.getDate()).padStart(2, "0")].join("-");
      return { date, count: activity.get(dateKey) || 0 };
    });
    const weeklyTotal = days.reduce((sum, day) => sum + day.count, 0);
    document.getElementById("reportTotalScans").textContent = weeklyTotal.toLocaleString() + " scans in last 7 days";
    const unresolved = history.filter((item) => item.status === "pending" || item.status === "unknown").length;
    document.getElementById("reportInsight").textContent = total
      ? `${total.toLocaleString()} scan records are saved to this account. ${totals.threat.toLocaleString()} are marked as threats, ${totals.suspicious.toLocaleString()} need review, and ${unresolved.toLocaleString()} are pending or not scanned by VirusTotal.`
      : "No scan records are saved to this account yet.";
    const max = Math.max(1, ...days.map((day) => day.count));
    document.querySelectorAll(".chart-y-labels span").forEach((label, index) => {
      label.textContent = Math.round(max * (4 - index) / 4).toLocaleString();
    });
    const points = days.map((day, index) => ({ x: index * (700 / 6), y: 198 - day.count / max * 170 }));
    const linePath = points.map((point, index) => `${index ? "L" : "M"}${point.x} ${point.y}`).join(" ");
    document.querySelector(".chart-line").setAttribute("d", linePath);
    document.querySelector(".chart-fill").setAttribute("d", `${linePath} L700 220 L0 220 Z`);
    document.querySelector(".chart-dots").innerHTML = points.map((point) => `<circle cx="${point.x}" cy="${point.y}" r="4"/>`).join("");
    document.querySelector(".chart-x-labels").innerHTML = days.map((day) => `<span>${day.date.toLocaleDateString(undefined, { weekday: "short" })}</span>`).join("");
  }

  function renderDashboard(data) {
    renderEndpoints(data.computers);
    renderIncidents(data.incidents, data.incidentCounts);
    const authorized = data.computers.filter((item) => item.authorized);
    const online = authorized.filter((item) => item.online).length;
    const pending = data.computers.length - authorized.length;
    setText("stat-computers", data.computers.length.toLocaleString());
    setText("stat-computers-pending", pending ? `${pending} awaiting approval` : "All registered agents authorized");
    setText("stat-online", online.toLocaleString());
    setText("stat-file-events", Number(data.fileActivity?.events24h || 0).toLocaleString());
    setText("stat-file-computers", `Across ${Number(data.fileActivity?.activeComputers24h || 0)} computers`);
    setText("agentStatus", `${online} of ${authorized.length}`);
    document.getElementById("agentStatusDot").className = "status-dot " + (authorized.length && online === authorized.length ? "status-dot--safe" : "status-dot--warn");
    setText("vtStatus", data.virusTotalConfigured ? "VirusTotal API v3" : "VirusTotal not configured");
    document.getElementById("vtStatusDot").className = "status-dot " + (data.virusTotalConfigured ? "status-dot--safe" : "status-dot--warn");

    const network = data.network || {};
    document.getElementById("networkDevices").textContent = Number(network.connected_devices || 0).toLocaleString();
    document.getElementById("activeConnections").textContent = Number(network.active_connections || 0).toLocaleString();
    document.getElementById("blockedRequests").textContent = Number(network.blocked_requests || 0).toLocaleString();
    document.getElementById("networkHealth").textContent = network.network_health || "Offline";
    const inbound = Number(network.inbound_tb || 0);
    const outbound = Number(network.outbound_tb || 0);
    const total = inbound + outbound;
    document.getElementById("trafficTotal").textContent = total.toFixed(2);
    document.getElementById("inboundTraffic").textContent = inbound.toFixed(2) + " TB";
    document.getElementById("outboundTraffic").textContent = outbound.toFixed(2) + " TB";
    document.getElementById("trafficMeterFill").style.width = (total ? inbound / total * 100 : 0) + "%";
    document.querySelectorAll("[data-setting]").forEach((input) => {
      input.checked = Boolean(Number(data.settings[input.dataset.setting]));
    });
    updateRealtimeStatus(Boolean(Number(data.settings.realtime_protection ?? 1)));
    setText("lastFileScan", relativeTime(data.lastFileScan));
    document.getElementById("recentBlocks").innerHTML = data.incidents.slice(0, 2).map((incident) =>
      `<div class="block-row"><span class="status-dot status-dot--warn"></span><span>${escapeHTML(incident.title)}</span><time>${escapeHTML(relativeTime(incident.detectedAt))}</time></div>`
    ).join("");
    if (!canScan) renderRecentActivity();
    renderReport();
  }

  function updateRealtimeStatus(isActive) {
    document.getElementById("realtimeStatus").textContent = isActive ? "Active" : "Paused";
    document.getElementById("realtimeStatusDot").className = "status-dot " + (isActive ? "status-dot--safe" : "status-dot--warn");
  }

  document.querySelectorAll("[data-setting]").forEach((input) => {
    input.addEventListener("change", async () => {
      const previousValue = !input.checked;
      const settings = Object.fromEntries([...document.querySelectorAll("[data-setting]")].map((item) => [item.dataset.setting, item.checked]));
      try {
        await auth.saveSettings(settings);
        updateRealtimeStatus(Boolean(settings.realtime_protection));
      } catch (error) {
        input.checked = previousValue;
        console.error("Could not save settings:", error);
      }
    });
  });

  if (canScan) {
    document.getElementById("exportReportBtn").addEventListener("click", (event) => {
      const escapeCsv = (value) => '"' + String(value ?? "").replace(/"/g, '""') + '"';
      const rows = [["File / URL", "Scan Date", "Scan Type", "Result", "Status", "SHA-256"]];
      history.forEach((item) => rows.push([item.name, item.date, item.type, item.result, statusLabel(item.status), item.sha256 || ""]));
      const csv = rows.map((row) => row.map(escapeCsv).join(",")).join("\r\n");
      const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "cyber-shield-scan-report.csv";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      const button = event.currentTarget;
      const originalText = button.innerHTML;
      button.textContent = "Report exported";
      window.setTimeout(() => { button.innerHTML = originalText; }, 1800);
    });
  }

  /* ---------- VirusTotal scan results ---------- */
  const CIRCUMFERENCE = 2 * Math.PI * 52;
  const POLL_INTERVAL_MS = 20000;
  const POLL_LIMIT_MS = 15 * 60 * 1000;

  function setRadial(fillEl, pctEl, progress, label) {
    fillEl.style.strokeDasharray = CIRCUMFERENCE;
    fillEl.style.strokeDashoffset = CIRCUMFERENCE * (1 - progress / 100);
    pctEl.textContent = label;
  }

  const RISK_COPY = {
    clean: { tone: "safe", title: "NO DETECTIONS", sub: "No VirusTotal engine flagged this item" },
    low: { tone: "suspicious", title: "SUSPICIOUS", sub: "Some engines rate this item as suspicious" },
    medium: { tone: "suspicious", title: "MALICIOUS DETECTIONS", sub: "A few engines flagged this item as malicious" },
    high: { tone: "threat", title: "THREAT DETECTED", sub: "Several engines flagged this item as malicious" },
    critical: { tone: "threat", title: "THREAT DETECTED", sub: "Widely detected as malicious" },
    unknown: { tone: "suspicious", title: "NO RESULTS YET", sub: "VirusTotal returned no engine results" },
  };

  const STATUS_COPY = {
    pending: { tone: "suspicious", title: "SCAN PENDING", sub: "Waiting to contact VirusTotal", detail: "The scan request was recorded. Results will appear here." },
    submitted: { tone: "suspicious", title: "ANALYSIS IN PROGRESS", sub: "VirusTotal is analysing this item", detail: "New submissions usually take one to five minutes. This page checks again every 20 seconds. Treat the item as untrusted until the analysis completes." },
    awaiting_upload: { tone: "suspicious", title: "WAITING FOR LAB COMPUTER", sub: "The agent will upload the file on its next heartbeat", detail: "The file stays untrusted until VirusTotal finishes analysing it." },
    not_found: { tone: "suspicious", title: "NOT SCANNED", sub: "VirusTotal has no record of this file", detail: "This file has not been analysed, so it is NOT confirmed safe. Treat it as untrusted." },
    failed: { tone: "threat", title: "SCAN FAILED", sub: "The scan could not be completed", detail: "" },
  };

  const ICONS = {
    safe: '<svg viewBox="0 0 24 24"><path d="M9 12l2 2 4-4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    suspicious: '<svg viewBox="0 0 24 24"><path d="M12 3l9 16H3L12 3z" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v5" stroke-width="1.8" stroke-linecap="round"/></svg>',
    threat: '<svg viewBox="0 0 24 24"><path d="M12 2l1.8 4.6L18 8l-4.2 1.4L12 14l-1.8-4.6L6 8l4.2-1.4L12 2z" stroke-width="1.5" stroke-linejoin="round"/></svg>',
  };

  function detailRow(label, value, extraClass = "") {
    if (value === null || value === undefined || value === "") return "";
    return `<div class="scan-detail${extraClass ? " " + extraClass : ""}"><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`;
  }

  function renderScanResult(box, scan) {
    const result = scan.result;
    const copy = scan.status === "completed" && result ? RISK_COPY[result.risk_level] || RISK_COPY.unknown : STATUS_COPY[scan.status] || STATUS_COPY.pending;
    box.className = "result-box active result-box--" + copy.tone;
    const detail = scan.status === "failed" ? (scan.error || "Unknown error.") : (copy.detail || (result && result.recommended_action) || "");
    const where = scan.computer ? `${scan.computer} · ${scan.filePath || scan.target}` : scan.target;
    let rows = detailRow(scan.source === "url" ? "URL" : "File", where, "scan-detail--wide");
    if (result) {
      rows += detailRow("Detection ratio", `${result.detection_ratio} engines flagged as malicious`)
        + detailRow("Risk level", result.risk_level.charAt(0).toUpperCase() + result.risk_level.slice(1))
        + detailRow("Engine verdicts", `${result.malicious} malicious · ${result.suspicious} suspicious · ${result.harmless} harmless · ${result.undetected} undetected`, "scan-detail--wide")
        + detailRow("Threat label", result.threat_label)
        + detailRow("File type", result.file_type)
        + detailRow("SHA-256", result.sha256 || scan.sha256, "scan-detail--wide scan-detail--hash")
        + detailRow("SHA-1", result.sha1, "scan-detail--wide scan-detail--hash")
        + detailRow("MD5", result.md5, "scan-detail--wide scan-detail--hash")
        + detailRow("VirusTotal analysis date", result.analysis_date)
        + detailRow("Result saved", result.created_at);
    } else {
      rows += detailRow("SHA-256", scan.sha256, "scan-detail--wide scan-detail--hash");
    }
    rows += detailRow("Requested", `${scan.requestedAt}${scan.requestedBy ? " by " + scan.requestedBy : ""}`);
    if (result) rows += detailRow("Recommended action", result.recommended_action, "scan-detail--wide scan-detail--action");

    const actions = [];
    if (result && result.vt_link) actions.push(`<a class="link-btn" href="${escapeHTML(result.vt_link)}" target="_blank" rel="noopener noreferrer">View full report on VirusTotal ↗</a>`);
    if (scan.source === "file_event" && (scan.status === "not_found" || scan.status === "failed")) {
      actions.push(`<button class="btn btn-outline" type="button" data-request-upload="${Number(scan.id)}">Upload file from lab computer to VirusTotal</button>`);
    }
    box.innerHTML = `
      <div class="result-head">
        <span class="result-icon">${ICONS[copy.tone]}</span>
        <div>
          <div class="result-title">${copy.title}</div>
          <div class="result-sub">${escapeHTML(copy.sub)}</div>
        </div>
      </div>
      <p class="result-detail">${escapeHTML(detail)}</p>
      <dl class="scan-details">${rows}</dl>
      ${actions.length ? `<div class="scan-result-actions">${actions.join("")}</div>` : ""}
    `;
  }

  const trackers = new WeakMap();

  /** Shows a scan in `box` and keeps polling VirusTotal until it reaches a final state. */
  function trackScan(scan, box, onFinish) {
    const previous = trackers.get(box);
    if (previous) window.clearTimeout(previous);
    renderScanResult(box, scan);
    box.onclick = async (event) => {
      const button = event.target.closest("[data-request-upload]");
      if (!button) return;
      if (!window.confirm("Upload this file from the lab computer to VirusTotal? Uploaded files are shared with the security community, so do not continue for personal or confidential documents.")) return;
      button.disabled = true;
      try {
        trackScan(await auth.requestAgentUpload(Number(button.dataset.requestUpload)), box, onFinish);
        if (onFinish) onFinish();
      } catch (error) {
        button.disabled = false;
        window.alert("Could not request the upload: " + error.message);
      }
    };
    const started = Date.now();
    const poll = async () => {
      if (Date.now() - started > POLL_LIMIT_MS) return;
      try {
        const updated = await auth.getScanStatus(scan.id);
        renderScanResult(box, updated);
        if (["submitted", "pending", "awaiting_upload"].includes(updated.status)) {
          trackers.set(box, window.setTimeout(poll, POLL_INTERVAL_MS));
        } else {
          trackers.delete(box);
          reloadScanData().catch(() => {});
          if (onFinish) onFinish();
        }
      } catch (error) {
        trackers.set(box, window.setTimeout(poll, POLL_INTERVAL_MS));
      }
    };
    if (["submitted", "pending", "awaiting_upload"].includes(scan.status)) {
      trackers.set(box, window.setTimeout(poll, POLL_INTERVAL_MS));
    }
  }

  function scanFailedResult(box, message) {
    box.className = "result-box active result-box--threat";
    box.innerHTML = `<div class="result-head"><span class="result-icon">${ICONS.threat}</span><div><div class="result-title">SCAN FAILED</div><div class="result-sub">Nothing was recorded as safe</div></div></div><p class="result-detail">${escapeHTML(message)}</p>`;
  }

  const fileResultBox = document.getElementById("fileResultBox");

  if (canScan) {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");
    const fileChosen = document.getElementById("fileChosen");
    const startScanBtn = document.getElementById("startScanBtn");
    const fileScanProgress = document.getElementById("fileScanProgress");
    let selectedFile = null;

    ["dragenter", "dragover"].forEach((evt) =>
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
      })
    );
    ["dragleave", "drop"].forEach((evt) =>
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
      })
    );
    dropzone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files[0];
      if (file) setSelectedFile(file);
    });
    fileInput.addEventListener("change", (e) => {
      if (e.target.files[0]) setSelectedFile(e.target.files[0]);
    });

    function setSelectedFile(file) {
      selectedFile = file;
      fileChosen.textContent = "Selected: " + file.name + " (" + formatBytes(file.size) + ")";
      startScanBtn.disabled = false;
      fileResultBox.classList.remove("active");
      fileScanProgress.classList.remove("active");
    }

    startScanBtn.addEventListener("click", async () => {
      if (!selectedFile) return;
      startScanBtn.disabled = true;
      fileResultBox.classList.remove("active");
      fileScanProgress.classList.add("active");
      setRadial(document.getElementById("fileRadialFill"), document.getElementById("fileRadialPct"), 35, "…");
      document.getElementById("fileScanSub").textContent = "Hashing and checking VirusTotal…";
      try {
        const scan = await auth.scanFile(selectedFile);
        trackScan(scan, fileResultBox);
        await reloadScanData();
      } catch (error) {
        scanFailedResult(fileResultBox, error.message);
      } finally {
        fileScanProgress.classList.remove("active");
        startScanBtn.disabled = false;
      }
    });

    const urlInput = document.getElementById("urlInput");
    const startUrlScanBtn = document.getElementById("startUrlScanBtn");
    const urlScanProgress = document.getElementById("urlScanProgress");
    const urlResultBox = document.getElementById("urlResultBox");

    urlInput.addEventListener("input", () => {
      startUrlScanBtn.disabled = urlInput.value.trim().length === 0;
      urlResultBox.classList.remove("active");
    });

    startUrlScanBtn.addEventListener("click", async () => {
      const url = urlInput.value.trim();
      if (!url) return;
      startUrlScanBtn.disabled = true;
      urlResultBox.classList.remove("active");
      urlScanProgress.classList.add("active");
      setRadial(document.getElementById("urlRadialFill"), document.getElementById("urlRadialPct"), 35, "…");
      try {
        const scan = await auth.scanUrl(url);
        trackScan(scan, urlResultBox);
        await reloadScanData();
      } catch (error) {
        scanFailedResult(urlResultBox, error.message);
      } finally {
        urlScanProgress.classList.remove("active");
        startUrlScanBtn.disabled = false;
      }
    });
  }

  /* ---------- Initial load ---------- */
  Promise.all([canScan ? auth.getHistory() : Promise.resolve([]), auth.getDashboard()]).then(([savedHistory, dashboardData]) => {
    history = savedHistory;
    dashboard = dashboardData;
    renderStats();
    renderRecentActivity();
    renderHistoryTable();
    renderDashboard(dashboardData);
    loadThreatMap(document.querySelector(".segment.active")?.dataset.range || "24h");
    if (document.getElementById("view-file-activity").classList.contains("active")) loadFileEvents();
  }).catch((error) => {
    console.error("Could not load dashboard data:", error);
    renderStats();
    renderRecentActivity();
    renderHistoryTable();
  });

})();
