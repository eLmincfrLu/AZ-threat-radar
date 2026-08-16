document.getElementById("historyFilterForm")?.addEventListener("submit", () => {
  const btn = document.querySelector("#historyFilterForm button[type=submit]");
  btn?.setAttribute("disabled", "disabled");
  btn?.classList.add("disabled");
});
