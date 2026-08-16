document.getElementById("sidebarToggle")?.addEventListener("click", () => {
  document.getElementById("sidebar")?.classList.toggle("open");
});

setTimeout(() => {
  document.querySelectorAll("#flashToasts .toast").forEach((el) => {
    bootstrap.Toast.getOrCreateInstance(el, { delay: 4000 }).hide();
  });
}, 100);

const theme = localStorage.getItem("tip-theme");
if (theme) document.documentElement.dataset.theme = theme;
