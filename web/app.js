"use strict";
const $ = (id) => document.getElementById(id);
const token = document.querySelector('meta[name="probe-token"]').content;
const reports = new Map();
const names = { internet: "Internet", hasura: "Hasura", datev: "DATEVconnect" };
const buttons = [...document.querySelectorAll("button")];
let running = false;
function log(message) {
  $("logs").textContent += `\n${new Date().toLocaleTimeString()}  ${message}`;
  $("logs").scrollTop = $("logs").scrollHeight;
}
function setRunning(value) {
  running = value;
  buttons.forEach((button) => { button.disabled = value || button.id === "copy" && reports.size === 0; });
}
function renderReport() {
  $("report").value = JSON.stringify({
    application: "Ventura DATEV Connectivity Test",
    note: "Connectivity only. DATEV identity and accounting data access are not verified. Review internal hostnames before sharing.",
    checks: [...reports.values()],
  }, null, 2);
}
function render(check, results) {
  const area = $(`${check}-results`);
  area.replaceChildren();
  for (const item of results) {
    const row = document.createElement("div");
    row.className = `result ${["pass", "warn", "fail"].includes(item.status) ? item.status : "warn"}`;
    const heading = document.createElement("div");
    heading.className = "result-heading";
    const title = document.createElement("span");
    title.textContent = `${item.status.toUpperCase()} · ${item.stage}`;
    const latency = document.createElement("span");
    latency.textContent = `${item.latency_ms} ms`;
    heading.append(title, latency);
    const message = document.createElement("p");
    message.textContent = item.message;
    const meta = document.createElement("p");
    meta.className = "meta";
    meta.textContent = [item.target, item.http_status && `HTTP ${item.http_status}`, item.tls_version, item.code, item.record_count && `${item.record_count} records`].filter(Boolean).join(" · ");
    row.append(heading, message, meta);
    if (item.trips?.length) {
      const table = document.createElement("table");
      const head = document.createElement("tr");
      for (const value of ["Trip ID", "Created (UTC)"]) { const th = document.createElement("th"); th.scope = "col"; th.textContent = value; head.append(th); }
      const thead = document.createElement("thead"); thead.append(head); table.append(thead);
      const tbody = document.createElement("tbody");
      for (const trip of item.trips) {
        const tr = document.createElement("tr");
        for (const value of [trip.id, trip.created_at]) { const td = document.createElement("td"); td.textContent = value; tr.append(td); }
        tbody.append(tr);
      }
      table.append(tbody); row.append(table);
    }
    area.append(row);
  }
}
async function test(check) {
  $("activity").textContent = `Testing ${names[check]}…`;
  log(`${names[check]} started.`);
  const input = { check };
  if (check === "hasura") { input.endpoint = $("endpoint").value.trim(); input.query = $("query").value; }
  if (check === "datev") {
    const port = Number($("datev-port").value);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || !$("datev-host").value.trim()) {
      const result = { check: names[check], stage: "Configuration", status: "fail", code: "invalid_configuration", message: "Enter a hostname and a port between 1 and 65535.", latency_ms: 0 };
      reports.set(check, { results: [result] }); render(check, [result]); renderReport(); log(result.message); return;
    }
    input.datev = { host: $("datev-host").value.trim(), port, scheme: $("datev-scheme").value };
  }
  try {
    const response = await fetch("/api/check", { method: "POST", headers: { "Content-Type": "application/json", "X-Probe-Token": token }, body: JSON.stringify(input), signal: AbortSignal.timeout(20000) });
    if (!response.ok) throw new Error((await response.text()).trim() || `Local agent returned HTTP ${response.status}.`);
    const report = await response.json();
    reports.set(check, report); render(check, report.results); renderReport();
    for (const item of report.results) log(`${names[check]} / ${item.stage}: ${item.status.toUpperCase()}${item.http_status ? ` (HTTP ${item.http_status})` : ""}. ${item.message}`);
  } catch (error) {
    const item = { check: names[check], stage: "Local agent", status: "fail", code: "agent_error", message: `${error.message} Keep the application window open, then reload this page.`, latency_ms: 0 };
    reports.set(check, { results: [item] }); render(check, [item]); renderReport(); log(item.message);
  }
}
async function run(checks) {
  if (running) return;
  setRunning(true);
  try { for (const check of checks) await test(check); }
  finally { setRunning(false); $("activity").textContent = "Checks finished. Review the results below."; }
}
$("run-all").addEventListener("click", () => run(["internet", "hasura", "datev"]));
document.querySelectorAll("[data-check]").forEach((button) => button.addEventListener("click", () => run([button.dataset.check])));
$("copy").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("report").value); log("Report copied. Review it before sharing."); $("activity").textContent = "Report copied."; }
  catch { $("report").focus(); $("report").select(); $("activity").textContent = "Press Ctrl+C to copy the selected report."; }
});
