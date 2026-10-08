/* Local browser interactions; provider credentials never reach the browser. */
document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const status = document.getElementById("copy-status");
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    status.textContent = "Indicator copied.";
  } catch {
    status.textContent = "Copy unavailable. Select the indicator text and copy it manually.";
  }
  window.setTimeout(() => { status.textContent = ""; }, 4000);
});

document.addEventListener("htmx:responseError", (event) => {
  const target = document.getElementById("report");
  const message = document.createElement("p");
  message.className = "error";
  message.setAttribute("role", "alert");
  message.textContent = event.detail.xhr.status === 403
    ? "Your session expired. Reload the page to continue."
    : "Request failed. Reload the page or try again.";
  target.prepend(message);
});

// Keep expanded evidence open when polling refreshes a report.
let expandedEvidence = [];
document.addEventListener("htmx:beforeSwap", (event) => {
  if (event.detail.target.id !== "report") return;
  expandedEvidence = [...document.querySelectorAll("#report details[open][data-evidence]")]
    .map((details) => details.dataset.evidence);
});
document.addEventListener("htmx:afterSwap", () => {
  document.querySelectorAll("#report details[data-evidence]").forEach((details) => {
    if (expandedEvidence.includes(details.dataset.evidence)) details.open = true;
  });
});
