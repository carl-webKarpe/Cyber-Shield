(function () {
  "use strict";

  const auth = window.CyberShieldAuth;
  const form = document.getElementById("loginForm");
  const nameInput = document.getElementById("loginName");
  const emailInput = document.getElementById("loginEmail");
  const passwordInput = document.getElementById("loginPassword");
  const message = document.getElementById("loginMessage");
  const submitButton = form.querySelector("[type='submit']");
  const registerFields = document.querySelectorAll("[data-register-field]");
  let isRegistering = false;

  function setAuthMode(registering) {
    isRegistering = registering;
    document.querySelector(".login-form-wrap h2").textContent = registering ? "Create your account" : "Welcome back";
    document.querySelector(".login-intro").textContent = registering
      ? "Create an account to access your security workspace."
      : "Sign in to your security workspace.";
    submitButton.querySelector("span").textContent = registering ? "Create account" : "Sign in";
    document.getElementById("switchPrompt").textContent = registering ? "Already have an account?" : "New to Cyber-Shield?";
    document.getElementById("switchAuthMode").textContent = registering ? "Sign in" : "Create an account";
    document.getElementById("passwordHint").textContent = registering ? "At least 8 characters" : "";
    nameInput.required = registering;
    passwordInput.autocomplete = registering ? "new-password" : "current-password";
    registerFields.forEach((field) => { field.hidden = !registering; });
    message.hidden = true;
    message.classList.remove("is-error", "is-success");
  }

  auth.getSession().then((session) => {
    if (session) window.location.replace("index.php");
  }).catch(() => {});

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.hidden = true;
    message.classList.remove("is-error", "is-success");

    if ((isRegistering && !nameInput.value.trim()) || !emailInput.value.trim() || !passwordInput.value) {
      message.textContent = isRegistering
        ? "Enter your name, email, and password to create an account."
        : "Enter your email and password to continue.";
      message.classList.add("is-error");
      message.hidden = false;
      return;
    }
    if (isRegistering && passwordInput.value.length < 8) {
      message.textContent = "Your password must be at least 8 characters.";
      message.classList.add("is-error");
      message.hidden = false;
      passwordInput.focus();
      return;
    }

    submitButton.disabled = true;
    submitButton.querySelector("span").textContent = isRegistering ? "Creating account..." : "Signing in...";
    try {
      const result = isRegistering
        ? await auth.register(nameInput.value, emailInput.value, passwordInput.value)
        : await auth.login(emailInput.value, passwordInput.value);
      if (!result.ok) {
        submitButton.disabled = false;
        submitButton.querySelector("span").textContent = isRegistering ? "Create account" : "Sign in";
        message.textContent = result.message;
        message.classList.add("is-error");
        message.hidden = false;
        passwordInput.focus();
        return;
      }

      message.textContent = isRegistering ? "Account created. Opening your workspace..." : "Signed in. Opening your workspace...";
      message.classList.add("is-success");
      message.hidden = false;
      window.location.assign("index.php");
    } catch (error) {
      submitButton.disabled = false;
      submitButton.querySelector("span").textContent = isRegistering ? "Create account" : "Sign in";
      message.textContent = error.message;
      message.classList.add("is-error");
      message.hidden = false;
    }
  });

  const switchAuthMode = document.getElementById("switchAuthMode");
  if (switchAuthMode && form.dataset.allowRegistration === "1") {
    switchAuthMode.addEventListener("click", () => {
      setAuthMode(!isRegistering);
    });
  }

  document.getElementById("togglePassword").addEventListener("click", (event) => {
    const button = event.currentTarget;
    const showing = passwordInput.type === "text";
    passwordInput.type = showing ? "password" : "text";
    button.setAttribute("aria-pressed", String(!showing));
    button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  });
})();
