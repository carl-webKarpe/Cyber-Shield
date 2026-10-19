

(function () {
  "use strict";

  const auth = window.CyberShieldAuth;
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await auth.logout();
    window.location.replace("login.php");
  });

  let history = [];
  let dashboard = null;

  /* ---------- Navigation ---------- */
  const navItems = document.querySelectorAll(".nav-item");
  const views = document.querySelectorAll(".view");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("overlay");
  const menuBtn = document.getElementById("menuBtn");

  function goToView(name) {
    navItems.forEach((btn) => btn.classList.toggle("active", btn.dataset.view === name));
    views.forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
    closeSidebar();
    window.scrollTo({ top: 0, behavior: "smooth" });
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
  function renderRecentActivity() {
    const container = document.getElementById("recent-activity");
    container.innerHTML = "";
    history.slice(0, 5).forEach((item) => {
      const row = document.createElement("div");
      row.className = "mini-row";
      const iconColors = {
        safe: ["var(--safe-bg)", "var(--safe)"],
        suspicious: ["var(--warn-bg)", "var(--warn)"],
        threat: ["var(--danger-bg)", "var(--danger)"],
      };
      const [bg, fg] = iconColors[item.status];
      row.innerHTML = `
        <span class="mini-icon" style="background:${bg}; color:${fg}">
          ${statusIconSVG(item.status)}
        </span>
        <span class="mini-title">${escapeHTML(item.name)}</span>
        <span class="mini-time">${item.date.split(" ")[0]}</span>
      `;
      container.appendChild(row);
    });
  }

  function statusIconSVG(status) {
    if (status === "safe") return '<svg viewBox="0 0 24 24"><path d="M9 12l2 2 4-4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    if (status === "suspicious") return '<svg viewBox="0 0 24 24"><path d="M12 3l9 16H3L12 3z" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v5" stroke-width="1.8" stroke-linecap="round"/></svg>';
    return '<svg viewBox="0 0 24 24"><path d="M12 2l1.8 4.6L18 8l-4.2 1.4L12 14l-1.8-4.6L6 8l4.2-1.4L12 2z" stroke-width="1.4" stroke-linejoin="round"/></svg>';
  }

  function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  
  function renderStats() {
    const total = history.length;
    const safe = history.filter((h) => h.status === "safe").length;
    const suspicious = history.filter((h) => h.status === "suspicious").length;
    const threats = history.filter((h) => h.status === "threat").length;
    document.getElementById("stat-total").textContent = total.toLocaleString();
    document.getElementById("stat-safe").textContent = safe.toLocaleString();
    document.getElementById("stat-suspicious").textContent = suspicious.toLocaleString();
    document.getElementById("stat-threats").textContent = threats.toLocaleString();
  }

  /* ---------- Scan History table ---------- */
  function renderHistoryTable(filter = "") {
    const tbody = document.getElementById("historyTableBody");
    const emptyState = document.getElementById("historyEmpty");
    const q = filter.trim().toLowerCase();
    const rows = history.filter((h) => h.name.toLowerCase().includes(q));

    tbody.innerHTML = "";
    emptyState.hidden = rows.length !== 0;

    rows.forEach((item) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="cell-name">${escapeHTML(item.name)}</td>
        <td>${item.date}</td>
        <td><span class="type-pill">${item.type === "File" ? fileTypeSVG() : linkTypeSVG()} ${item.type}</span></td>
        <td>${escapeHTML(item.result)}</td>
        <td><span class="badge badge--${item.status}">${statusLabel(item.status)}</span></td>
        <td class="scan-actions"><button class="delete-scan-btn" type="button" data-scan-id="${escapeHTML(String(item.id))}" aria-label="Delete scan record" title="Delete scan record"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M10 11v6m4-6v6M5 7l1 14h12l1-14M9 7V4h6v3"/></svg></button></td>
      `;
      tbody.appendChild(tr);
    });
  }

  function statusLabel(status) {
    if (status === "safe") return "Safe";
    if (status === "suspicious") return "Suspicious";
    return "Threat";
  }
  function fileTypeSVG() {
    return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 2h9l5 5v15H6z"/></svg>';
  }
  function linkTypeSVG() {
    return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9.5 14.5l5-5M8 12l-1.5 1.5a3 3 0 0 0 4.24 4.24L12 16.5M16 12l1.5-1.5a3 3 0 0 0-4.24-4.24L12 7.5"/></svg>';
  }

  document.getElementById("historySearch").addEventListener("input", (e) => {
    renderHistoryTable(e.target.value);
  });

  document.getElementById("historyTableBody").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-scan-id]");
    if (!button || button.disabled) return;
    if (!window.confirm("Delete this scan record? This action cannot be undone.")) return;

    button.disabled = true;
    try {
      await auth.deleteScan(button.dataset.scanId);
      [history, dashboard] = await Promise.all([auth.getHistory(), auth.getDashboard()]);
      renderStats();
      renderRecentActivity();
      renderHistoryTable(document.getElementById("historySearch").value);
      renderDashboard(dashboard);
    } catch (error) {
      button.disabled = false;
      window.alert("Could not delete scan record: " + error.message);
      console.error("Could not delete scan record:", error);
    }
  });

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

  function renderEndpoints(endpoints) {
    const tbody = document.getElementById("endpointTableBody");
    tbody.innerHTML = endpoints.map((endpoint) => {
      const protection = {
        protected: ["Protected", "safe"],
        update_needed: ["Update needed", "suspicious"],
        at_risk: ["At risk", "suspicious"],
        offline: ["Offline", "threat"],
      }[endpoint.protection] || ["Unknown", "suspicious"];
      return `<tr><td class="cell-name">${escapeHTML(endpoint.device)}</td><td>${escapeHTML(endpoint.owner)}</td><td>${escapeHTML(endpoint.platform)}</td><td>${escapeHTML(relativeTime(endpoint.lastSeen))}</td><td><span class="badge badge--${protection[1]}">${protection[0]}</span></td></tr>`;
    }).join("");
    const protectedCount = endpoints.filter((item) => item.protection === "protected").length;
    const attentionCount = endpoints.length - protectedCount;
    document.getElementById("endpointCount").textContent = endpoints.length.toLocaleString();
    document.getElementById("protectedEndpointCount").textContent = protectedCount.toLocaleString();
    document.getElementById("attentionEndpointCount").textContent = attentionCount.toLocaleString();
    const newest = endpoints.map((item) => item.lastSeen).filter(Boolean).sort().at(-1);
    document.getElementById("endpointLastCheckin").textContent = relativeTime(newest);
    filterEndpoints();
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

  function renderIncidents(incidents, counts) {
    const list = document.getElementById("incidentList");
    list.innerHTML = incidents.map((incident) => {
      const severity = incident.severity.toLowerCase();
      const badge = severity === "critical" || severity === "high" ? "threat" : "suspicious";
      const isResolved = incident.status === "resolved";
      const text = [incident.code, incident.title, incident.description, incident.category, severity].join(" ").toLowerCase();
      return `<article class="incident-row${isResolved ? " resolved" : ""}" data-search="${escapeHTML(text)}"><span class="incident-severity severity-${escapeHTML(severity)}"></span><div class="incident-main"><div class="incident-title-line"><h2>${escapeHTML(incident.title)}</h2><span class="badge badge--${badge}">${escapeHTML(severity.charAt(0).toUpperCase() + severity.slice(1))}</span></div><p>${escapeHTML(incident.description)}</p><div class="incident-meta"><span>${escapeHTML(incident.code)}</span><span>${escapeHTML(incident.category)}</span><time>${escapeHTML(relativeTime(incident.detectedAt))}</time></div></div><button class="btn btn-outline incident-action" data-incident-id="${Number(incident.id)}"${isResolved ? " disabled" : ""}>${isResolved ? "Resolved" : "Resolve"}</button></article>`;
    }).join("");
    document.getElementById("openIncidentCount").textContent = Number(counts.open_count || 0).toLocaleString();
    document.getElementById("criticalIncidentCount").textContent = Number(counts.critical_count || 0).toLocaleString();
    document.getElementById("inProgressIncidentCount").textContent = Number(counts.progress_count || 0).toLocaleString();
    document.getElementById("resolvedTodayCount").textContent = Number(counts.resolved_today || 0).toLocaleString();
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
    const totals = { safe: 0, suspicious: 0, threat: 0 };
    history.forEach((item) => { if (Object.hasOwn(totals, item.status)) totals[item.status] += 1; });
    const total = history.length;
    document.getElementById("stat-total").textContent = total.toLocaleString();
    document.getElementById("stat-safe").textContent = totals.safe.toLocaleString();
    document.getElementById("stat-suspicious").textContent = totals.suspicious.toLocaleString();
    document.getElementById("stat-threats").textContent = totals.threat.toLocaleString();
    document.getElementById("reportSafeCount").textContent = totals.safe.toLocaleString();
    document.getElementById("reportSuspiciousCount").textContent = totals.suspicious.toLocaleString();
    document.getElementById("reportThreatCount").textContent = totals.threat.toLocaleString();
    document.getElementById("reportTotalScans").textContent = total.toLocaleString() + " total scans";
    const safePercent = total ? totals.safe / total * 100 : 0;
    const suspiciousPercent = total ? totals.suspicious / total * 100 : 0;
    const threatPercent = total ? totals.threat / total * 100 : 0;
    document.getElementById("reportSafeBar").style.width = safePercent + "%";
    document.getElementById("reportSuspiciousBar").style.width = suspiciousPercent + "%";
    document.getElementById("reportThreatBar").style.width = threatPercent + "%";
    const weekAgo = new Date();
    weekAgo.setHours(0, 0, 0, 0);
    weekAgo.setDate(weekAgo.getDate() - 6);
    const activity = new Map((dashboard?.scanActivity || []).map((day) => [day.scan_date, Number(day.scan_count)]));
    const days = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (6 - index));
      const dateKey = [date.getFullYear(), String(date.getMonth() + 1).padStart(2, "0"), String(date.getDate()).padStart(2, "0")].join("-");
      return { date, count: activity.get(dateKey) || 0 };
    });
    const weeklyTotal = days.filter((day) => day.date >= weekAgo).reduce((sum, day) => sum + day.count, 0);
    document.getElementById("reportTotalScans").textContent = weeklyTotal.toLocaleString() + " scans in last 7 days";
    document.getElementById("reportInsight").textContent = total
      ? `${total.toLocaleString()} scan records are saved to this account. ${totals.threat.toLocaleString()} are marked as threats and ${totals.suspicious.toLocaleString()} need review.`
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
    renderEndpoints(data.endpoints);
    renderIncidents(data.incidents, data.incidentCounts);
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
    updateRealtimeStatus(Boolean(Number(data.settings.realtime_protection)));
    document.getElementById("lastFileScan").textContent = relativeTime(data.lastFileScan);
    document.getElementById("recentBlocks").innerHTML = data.incidents.slice(0, 2).map((incident) =>
      `<div class="block-row"><span class="status-dot status-dot--warn"></span><span>${escapeHTML(incident.title)}</span><time>${escapeHTML(relativeTime(incident.detectedAt))}</time></div>`
    ).join("");
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

  document.getElementById("exportReportBtn").addEventListener("click", (event) => {
    const escapeCsv = (value) => '"' + String(value).replace(/"/g, '""') + '"';
    const rows = [["File / URL", "Scan Date", "Scan Type", "Result", "Status"]];
    history.forEach((item) => rows.push([item.name, item.date, item.type, item.result, statusLabel(item.status)]));
    const csv = rows.map((row) => row.map(escapeCsv).join(",")).join("\r\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
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


  
  const CIRCUMFERENCE = 2 * Math.PI * 52;

  function runRadialScan({ fillEl, pctEl, subEl, statusMessages, onDone }) {
    fillEl.style.strokeDasharray = CIRCUMFERENCE;
    fillEl.style.strokeDashoffset = CIRCUMFERENCE;

    let progress = 0;
    const totalMs = 2600;
    const stepMs = 40;
    const steps = totalMs / stepMs;
    const increment = 100 / steps;

    const msgAt = statusMessages.map((m, i) => ({
      text: m,
      at: (i / statusMessages.length) * 100,
    }));

    const interval = setInterval(() => {
      progress = Math.min(100, progress + increment);
      const offset = CIRCUMFERENCE * (1 - progress / 100);
      fillEl.style.strokeDashoffset = offset;
      pctEl.textContent = Math.round(progress) + "%";

      const current = [...msgAt].reverse().find((m) => progress >= m.at);
      if (current) subEl.textContent = current.text;

      if (progress >= 100) {
        clearInterval(interval);
        setTimeout(onDone, 300);
      }
    }, stepMs);
  }

  
  function sampleResult(kind) {
  
    const roll = Math.random();
    if (roll < 0.65) return "safe";
    if (roll < 0.88) return "suspicious";
    return "threat";
  }

  const RESULT_COPY = {
    safe: {
      title: "SAFE",
      sub: "No threats detected",
      detailFile: "This file matched no known malware signatures and showed no suspicious behavior patterns during analysis.",
      detailUrl: "This URL showed no signs of phishing, malware hosting, or malicious redirects.",
      icon: '<svg viewBox="0 0 24 24"><path d="M9 12l2 2 4-4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    },
    suspicious: {
      title: "SUSPICIOUS",
      sub: "Potentially unwanted characteristics found",
      detailFile: "This file contains characteristics commonly seen in packed or obfuscated software. Manual review is recommended before running it.",
      detailUrl: "This URL shows some characteristics associated with low-reputation or newly registered domains. Proceed with caution.",
      icon: '<svg viewBox="0 0 24 24"><path d="M12 3l9 16H3L12 3z" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9v5" stroke-width="1.8" stroke-linecap="round"/></svg>',
    },
    threat: {
      title: "THREAT DETECTED",
      sub: "Malicious activity identified",
      detailFile: "This file matches known malware signatures. Do not open or execute it — quarantine or delete immediately.",
      detailUrl: "This URL is associated with phishing or malware distribution. Avoid visiting this link.",
      icon: '<svg viewBox="0 0 24 24"><path d="M12 2l1.8 4.6L18 8l-4.2 1.4L12 14l-1.8-4.6L6 8l4.2-1.4L12 2z" stroke-width="1.5" stroke-linejoin="round"/></svg>',
    },
  };

  async function showResult(boxEl, status, kind, name) {
    const copy = RESULT_COPY[status];
    boxEl.className = "result-box active result-box--" + status;
    boxEl.innerHTML = `
      <div class="result-head">
        <span class="result-icon">${copy.icon}</span>
        <div>
          <div class="result-title">${copy.title}</div>
          <div class="result-sub">${copy.sub}</div>
        </div>
      </div>
      <p class="result-detail">${kind === "file" ? copy.detailFile : copy.detailUrl}</p>
    `;

    
    try {
      await auth.saveScan({
        name,
        type: kind === "file" ? "File" : "URL",
        result: copy.sub,
        status,
      });
      history = await auth.getHistory();
      dashboard = await auth.getDashboard();
      renderRecentActivity();
      renderHistoryTable(document.getElementById("historySearch").value);
      renderDashboard(dashboard);
    } catch (error) {
      const detail = boxEl.querySelector(".result-detail");
      detail.textContent += " Scan history could not be saved: " + error.message;
    }
  }

  
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const fileChosen = document.getElementById("fileChosen");
  const startScanBtn = document.getElementById("startScanBtn");
  const fileScanProgress = document.getElementById("fileScanProgress");
  const fileResultBox = document.getElementById("fileResultBox");
  let selectedFileName = null;

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
    if (file) setSelectedFile(file.name);
  });
  fileInput.addEventListener("change", (e) => {
    if (e.target.files[0]) setSelectedFile(e.target.files[0].name);
  });

  function setSelectedFile(name) {
    selectedFileName = name;
    fileChosen.textContent = "Selected: " + name;
    startScanBtn.disabled = false;
    fileResultBox.classList.remove("active");
    fileScanProgress.classList.remove("active");
  }

  startScanBtn.addEventListener("click", () => {
    if (!selectedFileName) return;
    startScanBtn.disabled = true;
    fileResultBox.classList.remove("active");
    fileScanProgress.classList.add("active");

    runRadialScan({
      fillEl: document.getElementById("fileRadialFill"),
      pctEl: document.getElementById("fileRadialPct"),
      subEl: document.getElementById("fileScanSub"),
      statusMessages: [
        "Reading file signatures…",
        "Checking against threat database…",
        "Analyzing behavior patterns…",
        "Finalizing report…",
      ],
      onDone: () => {
        fileScanProgress.classList.remove("active");
        const status = sampleResult("file");
        showResult(fileResultBox, status, "file", selectedFileName);
        startScanBtn.disabled = false;
      },
    });
  });

  
  const urlInput = document.getElementById("urlInput");
  const startUrlScanBtn = document.getElementById("startUrlScanBtn");
  const urlScanProgress = document.getElementById("urlScanProgress");
  const urlResultBox = document.getElementById("urlResultBox");

  urlInput.addEventListener("input", () => {
    startUrlScanBtn.disabled = urlInput.value.trim().length === 0;
    urlResultBox.classList.remove("active");
  });

  startUrlScanBtn.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (!url) return;
    startUrlScanBtn.disabled = true;
    urlResultBox.classList.remove("active");
    urlScanProgress.classList.add("active");

    runRadialScan({
      fillEl: document.getElementById("urlRadialFill"),
      pctEl: document.getElementById("urlRadialPct"),
      subEl: document.getElementById("urlScanSub"),
      statusMessages: [
        "Resolving domain reputation…",
        "Checking phishing blocklists…",
        "Inspecting redirect chain…",
        "Finalizing report…",
      ],
      onDone: () => {
        urlScanProgress.classList.remove("active");
        const status = sampleResult("url");
        showResult(urlResultBox, status, "url", url);
        startUrlScanBtn.disabled = false;
      },
    });
  });

  
  Promise.all([auth.getHistory(), auth.getDashboard()]).then(([savedHistory, dashboardData]) => {
    history = savedHistory;
    dashboard = dashboardData;
    renderStats();
    renderRecentActivity();
    renderHistoryTable();
    renderDashboard(dashboardData);
    loadThreatMap(document.querySelector(".segment.active")?.dataset.range || "24h");
  }).catch((error) => {
    console.error("Could not load dashboard data:", error);
    renderStats();
    renderRecentActivity();
    renderHistoryTable();
  });

})();
