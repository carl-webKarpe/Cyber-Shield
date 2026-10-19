(function () {
  "use strict";

  const profile = document.querySelector("[data-user-profile]");
  if (!profile) return;

  const errorMessage = document.getElementById("profileError");
  const fields = {
    name: document.getElementById("profileName"),
    email: document.getElementById("profileEmail"),
    role: document.getElementById("profileRole"),
    createdAt: document.getElementById("profileCreatedAt"),
    lastLogin: document.getElementById("profileLastLogin"),
  };

  window.CyberShieldAuth.getProfile().then((user) => {
    const name = String(user.name || "User");
    const initials = name.trim().split(/\s+/).slice(0, 2)
      .map((part) => Array.from(part)[0] || "")
      .join("")
      .toUpperCase();

    document.getElementById("profileAvatar").textContent = initials || "CS";
    document.getElementById("profileDisplayName").textContent = name;
    document.getElementById("profileDisplayEmail").textContent = user.email || "";
    fields.name.textContent = name;
    fields.email.textContent = user.email || "Not available";
    fields.role.textContent = user.role || "Not available";
    fields.createdAt.textContent = user.createdAt || "Not available";
    fields.lastLogin.textContent = user.lastLogin || "No sign-in recorded";
  }).catch((error) => {
    errorMessage.textContent = "Could not load your profile: " + error.message;
    errorMessage.hidden = false;
    document.getElementById("profileDisplayName").textContent = "Profile unavailable";
    document.getElementById("profileDisplayEmail").textContent = "";
    Object.values(fields).forEach((field) => { field.textContent = "Not available"; });
  });
})();