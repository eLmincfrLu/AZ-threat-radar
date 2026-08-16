function bindAuthForm(formId, btnId) {
  document.getElementById(formId)?.addEventListener("submit", () => {
    const btn = document.getElementById(btnId);
    btn?.querySelector(".btn-label")?.classList.add("d-none");
    btn?.querySelector(".spinner-border")?.classList.remove("d-none");
    btn?.setAttribute("disabled", "disabled");
  });
}

function generateStrongPassword(length = 12) {
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const special = "!@#$%^&*";
  const all = upper + lower + digits + special;
  const size = Math.max(length, 8);
  const chars = [
    upper[Math.floor(Math.random() * upper.length)],
    lower[Math.floor(Math.random() * lower.length)],
    digits[Math.floor(Math.random() * digits.length)],
    special[Math.floor(Math.random() * special.length)],
  ];

  for (let i = chars.length; i < size; i += 1) {
    chars.push(all[Math.floor(Math.random() * all.length)]);
  }

  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join("");
}

function setPasswordVisible(input, visible) {
  if (!input) return;
  input.type = visible ? "text" : "password";
  const icon = input.closest(".password-input-wrap")?.querySelector(".password-toggle-btn i");
  if (icon) {
    icon.classList.toggle("bi-eye", !visible);
    icon.classList.toggle("bi-eye-slash", visible);
  }
}

function fillPasswordFields(passwordInput, confirmInput) {
  const password = generateStrongPassword();
  passwordInput.value = password;
  setPasswordVisible(passwordInput, false);
  if (confirmInput) {
    confirmInput.value = password;
    setPasswordVisible(confirmInput, false);
  }
}

function bindPasswordToggles() {
  document.querySelectorAll(".password-toggle-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.target);
      if (!input) return;
      setPasswordVisible(input, input.type === "password");
    });
  });
}

function bindGeneratePasswordButtons() {
  document.querySelectorAll(".generate-password-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const passwordInput = document.getElementById(btn.dataset.passwordTarget);
      const confirmInput = btn.dataset.confirmTarget
        ? document.getElementById(btn.dataset.confirmTarget)
        : null;
      if (!passwordInput) return;
      fillPasswordFields(passwordInput, confirmInput);
    });
  });
}

bindAuthForm("loginForm", "loginBtn");
bindAuthForm("registerForm", "registerBtn");
bindPasswordToggles();
bindGeneratePasswordButtons();
