function initRiskChart() {
  const el = document.getElementById("riskChart");
  if (!el || typeof Chart === "undefined") return;
  const safe = Number(el.dataset.safe || 0);
  const suspicious = Number(el.dataset.suspicious || 0);
  const malicious = Number(el.dataset.malicious || 0);
  new Chart(el, {
    type: "doughnut",
    data: {
      labels: [
        el.dataset.labelSafe || "Safe",
        el.dataset.labelSuspicious || "Suspicious",
        el.dataset.labelMalicious || "Malicious",
      ],
      datasets: [{
        data: [safe, suspicious, malicious],
        backgroundColor: ["#22c55e", "#f59e0b", "#ef4444"],
        borderWidth: 0,
      }],
    },
    options: {
      plugins: { legend: { position: "bottom", labels: { color: "#94a3b8" } } },
      cutout: "65%",
    },
  });
}

async function initCategoryChart() {
  const el = document.getElementById("categoryChart");
  if (!el || typeof Chart === "undefined") return;
  const riskEl = document.getElementById("riskChart");
  const countLabel = riskEl?.dataset.labelCount || "Count";
  let labels = ["Phishing", "Malware", "Botnet"];
  let values = [0, 0, 0];
  try {
    const res = await fetch("/api/dashboard/summary");
    const data = await res.json();
    if (data.top_categories?.length) {
      labels = data.top_categories.map((c) => c.name);
      values = data.top_categories.map((c) => c.count);
    }
  } catch (_) { /* use defaults */ }
  new Chart(el, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: countLabel,
        data: values,
        backgroundColor: "#2563eb",
        borderRadius: 6,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
        y: { ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "#1e293b" } },
      },
    },
  });
}

initRiskChart();
initCategoryChart();
