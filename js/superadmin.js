(function () {
  "use strict";

  const auth = window.CyberShieldAuth;
  const tbody = document.getElementById("logTableBody");
  const search = document.getElementById("logSearch");
  const actor = document.getElementById("logActor");
  let logs = [];

  const ACTOR_STYLES = {
    user: "bg-[#39c6ff]/10 text-[#39c6ff]",
    agent: "bg-[#2fe0a8]/10 text-[#2fe0a8]",
    system: "bg-[#9db3d1]/10 text-[var(--cs-muted)]",
  };

  function escapeHTML(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
  }

  function visibleLogs() {
    const query = search.value.trim().toLowerCase();
    return logs.filter((log) => (!actor.value || log.actorType === actor.value)
      && (!query || [log.action, log.details, log.userName, log.computer, log.ipAddress].join(" ").toLowerCase().includes(query)));
  }

  function render() {
    const rows = visibleLogs();
    if (!rows.length) {
      tbody.innerHTML = '<tr><td class="py-6 text-center text-[var(--cs-faint)]" colspan="5">No log entries match.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((log) => {
      const who = log.userName || log.computer || "Cyber-Shield";
      const danger = /failed|rejected|revoked/.test(log.action) ? " text-[#ff5470]" : "";
      return `<tr class="border-t border-[var(--cs-line)] align-top">`
        + `<td class="whitespace-nowrap py-3 pr-4 font-mono text-xs text-[var(--cs-muted)]">${escapeHTML(log.createdAt)}</td>`
        + `<td class="py-3 pr-4"><span class="rounded-full px-2 py-1 text-xs font-semibold ${ACTOR_STYLES[log.actorType] || ACTOR_STYLES.system}">${escapeHTML(log.actorType)}</span><div class="mt-1 text-xs text-[var(--cs-muted)]">${escapeHTML(who)}</div></td>`
        + `<td class="py-3 pr-4 font-mono text-xs${danger}">${escapeHTML(log.action)}</td>`
        + `<td class="py-3 pr-4 text-[var(--cs-muted)]">${escapeHTML(log.details)}</td>`
        + `<td class="py-3 font-mono text-xs text-[var(--cs-muted)]">${escapeHTML(log.ipAddress || "—")}</td></tr>`;
    }).join("");
  }

  async function load() {
    try {
      logs = await auth.getAuditLogs();
      render();
    } catch (error) {
      tbody.innerHTML = `<tr><td class="py-6 text-center text-[#ff5470]" colspan="5">Could not load system logs: ${escapeHTML(error.message)}</td></tr>`;
    }
  }

  search.addEventListener("input", render);
  actor.addEventListener("change", render);
  document.getElementById("refreshLogs").addEventListener("click", load);

  document.getElementById("exportLogs").addEventListener("click", () => {
    const escapeCsv = (value) => '"' + String(value ?? "").replace(/"/g, '""') + '"';
    const rows = [["Time", "Actor", "User", "Computer", "Action", "Details", "IP address"]];
    visibleLogs().forEach((log) => rows.push([log.createdAt, log.actorType, log.userName, log.computer, log.action, log.details, log.ipAddress]));
    const blob = new Blob(["﻿" + rows.map((row) => row.map(escapeCsv).join(",")).join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "cyber-shield-system-logs.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  document.querySelectorAll("[data-authorize]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!window.confirm(`Authorize ${button.dataset.hostname}? Its agent will be allowed to report file events.`)) return;
      button.disabled = true;
      try {
        await auth.setComputerAuthorized(Number(button.dataset.authorize), true);
        window.location.reload();
      } catch (error) {
        button.disabled = false;
        window.alert("Could not authorize computer: " + error.message);
      }
    });
  });

  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await auth.logout();
    window.location.replace("login.php");
  });

  load();
})();
