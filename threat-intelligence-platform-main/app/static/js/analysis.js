const placeholders = {
  ip: "8.8.8.8",
  domain: "google.com",
  url: "https://example.com",
};

const targetInput = document.getElementById("target");
const hint = document.getElementById("targetHint");

document.querySelectorAll('input[name="target_type"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    if (targetInput) targetInput.placeholder = placeholders[radio.value] || "";
  });
});

document.querySelectorAll(".example-chip").forEach((btn) => {
  btn.addEventListener("click", () => {
    const type = btn.dataset.type;
    const value = btn.dataset.value;
    const radio = document.querySelector(`input[name="target_type"][value="${type}"]`);
    radio?.click();
    if (targetInput) targetInput.value = value;
  });
});

document.getElementById("analysisForm")?.addEventListener("submit", () => {
  const btn = document.getElementById("analyzeBtn");
  btn?.querySelector(".btn-label")?.classList.add("d-none");
  btn?.querySelector(".spinner-border")?.classList.remove("d-none");
  btn?.setAttribute("disabled", "disabled");
});
