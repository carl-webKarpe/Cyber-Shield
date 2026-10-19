(function () {
  "use strict";

  const THEME_KEY = "cyberShieldTheme";

  async function request(action, options = {}, params = {}) {
    const query = new URLSearchParams({ action, ...params });
    const response = await fetch("api.php?" + query.toString(), {
      credentials: "same-origin",
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    });
    const result = await response.json();
    if (response.status === 401 && action !== "login" && action !== "session") {
      window.location.replace("login.php");
      throw new Error(result.message || "Please sign in again.");
    }
    if (!response.ok && response.status !== 401) {
      throw new Error(result.message || "The server could not complete the request.");
    }
    return result;
  }

  function applyTheme(theme) {
    const nextTheme = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = nextTheme;
    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor) themeColor.content = nextTheme === "light" ? "#edf3f6" : "#07111e";
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      const label = nextTheme === "dark" ? "Light mode" : "Dark mode";
      button.setAttribute("aria-label", "Switch to " + label.toLowerCase());
      button.setAttribute("title", "Switch to " + label.toLowerCase());
      const text = button.querySelector("[data-theme-label]");
      if (text) text.textContent = label;
      button.setAttribute("aria-pressed", String(nextTheme === "light"));
    });
    return nextTheme;
  }

  let savedTheme = "dark";
  try {
    savedTheme = localStorage.getItem(THEME_KEY) || "dark";
  } catch (error) {
    savedTheme = "dark";
  }
  applyTheme(savedTheme);

  document.addEventListener("DOMContentLoaded", () => {
    applyTheme(document.documentElement.dataset.theme);
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.addEventListener("click", () => {
        const nextTheme = applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
        try {
          localStorage.setItem(THEME_KEY, nextTheme);
        } catch (error) {
          return;
        }
      });
    });
  });

  const api = {
    getTheme() {
      return document.documentElement.dataset.theme || "dark";
    },

    setTheme(theme) {
      const nextTheme = applyTheme(theme);
      try {
        localStorage.setItem(THEME_KEY, nextTheme);
      } catch (error) {
        return nextTheme;
      }
      return nextTheme;
    },

    login(email, password) {
      return request("login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
    },

    register(name, email, password) {
      return request("register", {
        method: "POST",
        body: JSON.stringify({ name, email, password }),
      });
    },

    getSession() {
      return request("session").then((result) => result.user);
    },

    getProfile() {
      return request("profile").then((result) => result.user);
    },

    logout() {
      return request("logout", { method: "POST" });
    },

    getHistory() {
      return request("history").then((result) => result.history);
    },

    deleteScan(id) {
      return request("delete-scan", {
        method: "POST",
        body: JSON.stringify({ id }),
      });
    },

    getDashboard() {
      return request("dashboard");
    },

    getIncidents() {
      return request("incidents");
    },

    getThreatMap(range) {
      return request("threat-map", {}, { range });
    },

    resolveIncident(id) {
      return request("resolve-incident", {
        method: "POST",
        body: JSON.stringify({ id }),
      });
    },

    saveSettings(settings) {
      return request("save-settings", {
        method: "POST",
        body: JSON.stringify(settings),
      });
    },

    saveScan(scan) {
      return request("save-scan", {
        method: "POST",
        body: JSON.stringify(scan),
      });
    },
  };

  window.CyberShieldAuth = api;
})();
