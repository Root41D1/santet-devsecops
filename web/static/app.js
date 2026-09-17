const state = {
  csrf: "",
  overview: null,
  artifacts: [],
  activeJob: null,
  pollTimer: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.method && options.method !== "GET") headers["X-Santet-Token"] = state.csrf;
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function relativeTime(dateValue) {
  if (!dateValue) return "No evidence yet";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(dateValue).getTime()) / 1000));
  if (seconds < 60) return "Updated just now";
  if (seconds < 3600) return `Updated ${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `Updated ${Math.floor(seconds / 3600)}h ago`;
  return `Updated ${Math.floor(seconds / 86400)}d ago`;
}

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => element.classList.remove("show"), 3200);
}

function switchView(name) {
  $$(".view").forEach((view) => view.classList.toggle("active", view.dataset.view === name));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.section === name));
  $("#sidebar").classList.remove("open");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderOverview(data) {
  state.overview = data;
  $("#targetPath").textContent = data.target;
  $("#versionPill").textContent = `v${data.version}`;
  const blocking = data.findings.critical + data.findings.high + data.dependencyVulnerabilities;
  $("#blockingCount").textContent = formatNumber(blocking);
  $("#artifactCount").textContent = formatNumber(data.artifactCount);
  $("#componentCount").textContent = formatNumber(data.components);
  $("#freshness").textContent = relativeTime(data.latestEvidenceAt);
  const severities = ["critical", "high", "medium", "low"];
  const total = severities.reduce((sum, severity) => sum + data.findings[severity], 0);
  $("#findingTotal").textContent = formatNumber(total);
  const max = Math.max(...severities.map((severity) => data.findings[severity]), 1);
  $("#severityBars").innerHTML = severities.map((severity) => {
    const value = data.findings[severity];
    const height = value ? Math.max(12, Math.round((value / max) * 100)) : 3;
    return `<div class="bar ${severity}" style="height:${height}%" data-value="${value}" title="${severity}: ${value}"></div>`;
  }).join("");
  const score = !data.artifactCount ? "—" : blocking ? "Risk" : "Clear";
  $("#postureScore").textContent = score;
  $("#postureOrbit").dataset.posture = data.posture;
  renderRecent(data.artifacts);
}

function evidenceRow(item) {
  return `<div class="evidence-row">
    <div class="file-name"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.path)}</small></div>
    <span class="file-kind">${escapeHtml(item.kind)}</span>
    <a class="download-link" href="/api/artifacts/${encodeURI(item.path)}" title="Download evidence">Download ↓</a>
  </div>`;
}

function renderRecent(items) {
  $("#recentEvidence").innerHTML = items.length ? items.slice(0, 5).map(evidenceRow).join("") : '<div class="empty-state">Run a scan to create local evidence.</div>';
}

function renderEvidence(filter = "") {
  const normalized = filter.trim().toLowerCase();
  const items = state.artifacts.filter((item) => item.path.toLowerCase().includes(normalized));
  $("#evidenceCount").textContent = `${items.length} file${items.length === 1 ? "" : "s"}`;
  $("#evidenceTable").innerHTML = items.length ? items.map((item) => `<tr>
    <td title="${escapeHtml(item.path)}">${escapeHtml(item.path)}</td>
    <td><span class="file-kind">${escapeHtml(item.kind)}</span></td>
    <td>${formatBytes(item.size)}</td>
    <td>${relativeTime(item.updatedAt).replace("Updated ", "")}</td>
    <td><a class="download-link" href="/api/artifacts/${encodeURI(item.path)}">Download ↓</a></td>
  </tr>`).join("") : '<tr><td colspan="5"><div class="empty-state">No matching evidence.</div></td></tr>';
}

async function refreshData() {
  try {
    const [overviewData, artifactData] = await Promise.all([api("/api/overview"), api("/api/artifacts")]);
    renderOverview(overviewData);
    state.artifacts = artifactData.artifacts;
    renderEvidence($("#evidenceSearch").value);
  } catch (error) {
    toast(error.message);
  }
}

function commandTitle(command) {
  return command.split("-").map((word) => word[0].toUpperCase() + word.slice(1)).join(" ");
}

function showJobDrawer() {
  const drawer = $("#jobDrawer");
  drawer.classList.add("open");
  drawer.removeAttribute("inert");
  drawer.setAttribute("aria-hidden", "false");
}

function hideJobDrawer() {
  const drawer = $("#jobDrawer");
  drawer.classList.remove("open");
  drawer.setAttribute("inert", "");
  drawer.setAttribute("aria-hidden", "true");
}

async function runJob(payload) {
  try {
    const job = await api("/api/jobs", { method: "POST", body: JSON.stringify(payload) });
    state.activeJob = job.id;
    $("#jobTitle").textContent = commandTitle(payload.command);
    $("#jobLog").textContent = "Queued for safe local execution…";
    showJobDrawer();
    $("#cancelJob").hidden = false;
    updateJobState(job.status);
    pollJob();
  } catch (error) {
    toast(error.message);
  }
}

function updateJobState(status) {
  const element = $("#jobState");
  element.className = `job-state ${status}`;
  element.innerHTML = `<i></i>${escapeHtml(status)}`;
}

async function pollJob() {
  if (!state.activeJob) return;
  window.clearTimeout(state.pollTimer);
  try {
    const job = await api(`/api/jobs/${state.activeJob}`);
    updateJobState(job.status);
    const log = $("#jobLog");
    const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
    log.textContent = job.log || "Waiting for output…";
    if (nearBottom) log.scrollTop = log.scrollHeight;
    if (["succeeded", "failed", "cancelled"].includes(job.status)) {
      $("#cancelJob").hidden = true;
      toast(job.status === "succeeded" ? `${commandTitle(job.command)} completed` : `${commandTitle(job.command)} ${job.status}`);
      await refreshData();
      return;
    }
    state.pollTimer = window.setTimeout(pollJob, 900);
  } catch (error) {
    toast(error.message);
  }
}

async function initialize() {
  try {
    const health = await api("/api/health");
    state.csrf = health.csrfToken;
    $("#targetPath").textContent = health.target;
    $("#versionPill").textContent = `v${health.version}`;
    await refreshData();
    const jobs = await api("/api/jobs");
    const active = jobs.jobs.find((job) => ["queued", "running", "cancelling"].includes(job.status));
    if (active) {
      state.activeJob = active.id;
      $("#jobTitle").textContent = commandTitle(active.command);
      showJobDrawer();
      pollJob();
    }
  } catch (error) {
    toast(`Unable to connect: ${error.message}`);
  }
}

$$('[data-section]').forEach((item) => item.addEventListener("click", () => switchView(item.dataset.section)));
$$('[data-section-jump]').forEach((item) => item.addEventListener("click", () => switchView(item.dataset.sectionJump)));
$$('[data-run]').forEach((item) => item.addEventListener("click", () => runJob({ command: item.dataset.run })));
$$('[data-cloud]').forEach((item) => item.addEventListener("click", () => runJob({
  command: item.dataset.mode,
  provider: item.dataset.cloud,
  target: $("#cloudTarget").value,
})));
$("#imageScanButton").addEventListener("click", () => runJob({ command: "image-scan", image: $("#imageInput").value }));
$("#cloudGateButton").addEventListener("click", () => runJob({ command: "cloud-scan", provider: "all", target: $("#cloudTarget").value }));
$("#refreshButton").addEventListener("click", refreshData);
$("#evidenceRefresh").addEventListener("click", refreshData);
$("#evidenceSearch").addEventListener("input", (event) => renderEvidence(event.target.value));
$("#menuButton").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
$("#closeJob").addEventListener("click", hideJobDrawer);
$("#cancelJob").addEventListener("click", async () => {
  if (!state.activeJob) return;
  try {
    await api(`/api/jobs/${state.activeJob}/cancel`, { method: "POST", body: "{}" });
    toast("Cancellation requested");
    pollJob();
  } catch (error) { toast(error.message); }
});

initialize();
