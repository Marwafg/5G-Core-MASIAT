const form = document.getElementById("attack-form");
const resultCard = document.getElementById("result");
const payloadField = document.getElementById("payload");
const attackVectorField = document.getElementById("attack-vector");
const historyContainer = document.getElementById("history");
const attackRunCount = document.getElementById("total-threats");
const searchInput = document.getElementById("table-search");
const filterButton = document.getElementById("filter-button");
const timeRangeButton = document.getElementById("time-range-button");
const scoreCycleButton = document.getElementById("score-cycle-button");
const riskGauge = document.getElementById("risk-gauge");
const riskScoreValue = document.getElementById("risk-score-value");
const statusTitle = document.getElementById("status-title");
const statusMessage = document.getElementById("status-message");
const alertsPanel = document.getElementById("alerts-panel");
const settingsPanel = document.getElementById("settings-panel");
const refreshFuzzButton = document.getElementById("refresh-fuzz-button");
const fuzzList = document.getElementById("fuzz-list");
const showLabButton = document.getElementById("show-lab-button");
const labOutput = document.getElementById("lab-output");
const verifyJwtButton = document.getElementById("verify-jwt-button");
const jwtOutput = document.getElementById("jwt-output");
const refreshCatalogButton = document.getElementById("refresh-catalog-button");
const catalogList = document.getElementById("catalog-list");
const uploadForm = document.getElementById("upload-form");
const simulatorFileInput = document.getElementById("simulator-file");
const uploadOutput = document.getElementById("upload-output");
const showPlaybookButton = document.getElementById("show-playbook-button");
const playbookList = document.getElementById("playbook-list");
const playbookOutput = document.getElementById("playbook-output");
const showSourcesButton = document.getElementById("show-sources-button");
const sourcesList = document.getElementById("sources-list");
const sourcesOutput = document.getElementById("sources-output");
const scanProfileField = document.getElementById("scan-profile");
const scanModeField = document.getElementById("scan-mode");
const scanModulesField = document.getElementById("scan-modules");
const runScanButton = document.getElementById("run-scan-button");
const refreshRunsButton = document.getElementById("refresh-runs-button");
const runsList = document.getElementById("runs-list");

const samples = {
  sql: {
    attack_vector: "sql_injection",
    payload: "' OR '1'='1' --",
  },
  cmd: {
    attack_vector: "command_injection",
    payload: "8.8.8.8 && whoami",
  },
  nosql: {
    attack_vector: "nosql_injection",
    payload: '{"$regex": ".*"}',
  },
  jwt: {
    attack_vector: "jwt_manipulation",
    payload: '{"role":"admin"}',
  },
  nrf: {
    attack_vector: "nrf_spoofing",
    payload: '{"nfType":"AMF","nfInstanceId":"fake-amf-01","priority":1}',
  },
  bola: {
    attack_vector: "bola",
    payload: "imsi-001010000000002",
  },
  json: {
    attack_vector: "json_injection",
    payload: '{"filters":{"$ne":null},"nfType":"SMF"}',
  },
  supi: {
    attack_vector: "supi_manipulation",
    payload: "imsi-001010000000001' OR '1'='1",
  },
};

const timeRanges = ["Daily", "Weekly", "Monthly"];
const scoreCycle = [70, 82, 58, 91];
let scoreIndex = 0;
let highRiskFilterEnabled = false;

function setStatus(title, message) {
  statusTitle.textContent = title;
  statusMessage.textContent = message;
}

function renderResult(data) {
  resultCard.classList.remove("empty");
  resultCard.textContent = JSON.stringify(data, null, 2);
}

function renderHistory(logs) {
  if (!logs.length) {
    historyContainer.innerHTML = '<p class="empty-state">No attack runs yet. Start with a sample payload.</p>';
    return;
  }

  historyContainer.innerHTML = logs
    .map(
      (log) => `
        <article class="history-chip">
          <strong>${log.attack_vector}</strong>
          <span>${log.risk_score} risk</span>
        </article>
      `
    )
    .join("");
}

function updateGauge(score) {
  riskGauge.style.setProperty("--score", String(score));
  riskScoreValue.textContent = `${score}%`;
}

function renderFuzzPayloads(payloads) {
  fuzzList.innerHTML = payloads
    .map(
      (item) => `
        <article class="fuzz-item">
          <strong>${item.attack_type}</strong>
          <span>${item.method} ${item.path}</span>
        </article>
      `
    )
    .join("");
}

function renderCatalog(attacks) {
  catalogList.innerHTML = attacks
    .map(
      (item) => `
        <article class="stride-item">
          <strong>${item.title}</strong>
          <span>${item.goal}</span>
        </article>
      `
    )
    .join("");
}

function renderPlaybook(sections) {
  playbookList.innerHTML = sections
    .map(
      (section) => `
        <article class="playbook-item">
          <strong>${section.title}</strong>
          <span>${section.summary}</span>
        </article>
      `
    )
    .join("");
}

function renderSources(sources) {
  sourcesList.innerHTML = sources
    .map(
      (source) => `
        <article class="playbook-item">
          <strong>${source.title}</strong>
          <span>${source.summary}</span>
        </article>
      `
    )
    .join("");
}

function renderRuns(runs) {
  if (!runs.length) {
    runsList.innerHTML = '<p class="empty-state">No structured scans yet. Launch one from the controls above.</p>';
    return;
  }
  runsList.innerHTML = runs
    .map(
      (run) => `
        <article class="history-chip" data-run-id="${run.run_id}">
          <strong>${run.profile_name}</strong>
          <span>${run.mode} | ${run.findings_count} findings</span>
        </article>
      `
    )
    .join("");

  runsList.querySelectorAll("[data-run-id]").forEach((item) => {
    item.addEventListener("click", async () => {
      const response = await fetch(`/api/scanner/runs/${item.dataset.runId}`);
      const data = await response.json();
      renderResult(data);
      setStatus("Run Loaded", `Loaded ${data.findings.length} findings from structured scan ${item.dataset.runId}.`);
    });
  });
}

function applyTableFilters() {
  const query = (searchInput?.value || "").trim().toLowerCase();

  document.querySelectorAll("#surface-table-body tr").forEach((row) => {
    const haystack = (row.dataset.search || "").toLowerCase();
    const score = Number(row.dataset.score || "0");
    const matchesSearch = haystack.includes(query);
    const matchesRisk = !highRiskFilterEnabled || score >= 60;
    row.classList.toggle("hidden-row", !(matchesSearch && matchesRisk));
  });
}

async function refreshOverview() {
  const response = await fetch("/api/overview");
  const data = await response.json();
  attackRunCount.textContent = `${(data.metrics.attack_runs * 5) + 125}%`;
  renderHistory(data.logs);
}

async function refreshRuns() {
  const response = await fetch("/api/scanner/runs");
  const data = await response.json();
  renderRuns(data.runs);
}

document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    const sample = samples[button.dataset.sample];
    attackVectorField.value = sample.attack_vector;
    payloadField.value = sample.payload;
    setStatus("Injection Payload Loaded", `Loaded the ${button.dataset.sample.toUpperCase()} test case into the OpenAPI-driven API testing runner.`);
  });
});

document.querySelectorAll(".nav-pill").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav-pill").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    const target = button.dataset.navTarget;
    const sections = document.querySelectorAll(".page-section");
    if (target === "dashboard") {
      sections.forEach((section) => section.classList.remove("is-hidden"));
      document.querySelector("[data-section='dashboard']")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } else {
      sections.forEach((section) => {
        section.classList.toggle("is-hidden", section.dataset.section !== target);
      });
      document.querySelector(`[data-section='${target}']`)?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    setStatus(button.textContent.trim(), `Switched focus to the ${button.dataset.navTarget.replace("-", " ")} view of the 5G Core API testing platform.`);
  });
});

document.querySelectorAll("[data-toolbar-action]").forEach((button) => {
  button.addEventListener("click", () => {
    const action = button.dataset.toolbarAction;

    if (action === "focus-search") {
      searchInput.focus();
      button.classList.add("is-active");
      setTimeout(() => button.classList.remove("is-active"), 900);
      setStatus("API Search Ready", "Type in the search bar to filter the discovered microservice API assets instantly.");
      return;
    }

    if (action === "toggle-alerts") {
      const nextHidden = !alertsPanel.classList.contains("is-hidden");
      alertsPanel.classList.toggle("is-hidden", nextHidden);
      button.classList.toggle("is-active", !nextHidden);
      setStatus("Alerts Panel", nextHidden ? "Alerts panel hidden." : "Alerts panel opened with the latest API security control message.");
      return;
    }

    if (action === "toggle-settings") {
      const nextHidden = !settingsPanel.classList.contains("is-hidden");
      settingsPanel.classList.toggle("is-hidden", nextHidden);
      button.classList.toggle("is-active", !nextHidden);
      setStatus("Settings Panel", nextHidden ? "Settings panel hidden." : "Settings panel opened with the current OpenAPI-driven testing configuration.");
    }
  });
});

timeRangeButton?.addEventListener("click", () => {
  const nextIndex = (Number(timeRangeButton.dataset.rangeIndex) + 1) % timeRanges.length;
  timeRangeButton.dataset.rangeIndex = String(nextIndex);
  timeRangeButton.textContent = timeRanges[nextIndex];
  setStatus("Time Range Updated", `API security metric cards are now showing the ${timeRanges[nextIndex].toLowerCase()} view.`);
});

scoreCycleButton?.addEventListener("click", () => {
  scoreIndex = (scoreIndex + 1) % scoreCycle.length;
  updateGauge(scoreCycle[scoreIndex]);
  setStatus("Risk Score Updated", `API risk gauge cycled to ${scoreCycle[scoreIndex]} percent for presentation mode.`);
});

refreshFuzzButton?.addEventListener("click", async () => {
  const response = await fetch("/api/analysis/fuzz");
  const data = await response.json();
  renderFuzzPayloads(data.payloads);
  setStatus("Fuzzing Refreshed", "Generated malformed API inputs directly from the OpenAPI-driven discovery module.");
});

showLabButton?.addEventListener("click", async () => {
  const response = await fetch("/api/analysis/lab");
  const data = await response.json();
  labOutput.classList.remove("empty");
  labOutput.textContent = JSON.stringify(data, null, 2);
  setStatus("Lab Blueprint", "Displayed the contained testbed architecture for free5GC or Open5GS, UERANSIM, and interception tooling.");
});

verifyJwtButton?.addEventListener("click", async () => {
  const sampleResponse = await fetch("/api/analysis/oauth/sample");
  const sample = await sampleResponse.json();
  const verifyResponse = await fetch("/api/analysis/oauth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: sample.tampered_token }),
  });
  const result = await verifyResponse.json();
  jwtOutput.classList.remove("empty");
  jwtOutput.textContent = JSON.stringify({
    tampered_token: sample.tampered_token,
    verification: result,
  }, null, 2);
  setStatus("JWT Verification", "Secondary API authentication validation executed against a tampered NF JWT.");
});

refreshCatalogButton?.addEventListener("click", async () => {
  const response = await fetch("/api/analysis/catalog");
  const data = await response.json();
  renderCatalog(data.attacks);
  setStatus("Testing Modules", "Loaded the API-focused testing modules for injection, authentication, authorization, and registration abuse.");
});

showPlaybookButton?.addEventListener("click", async () => {
  const response = await fetch("/api/analysis/playbook");
  const data = await response.json();
  renderPlaybook(data.sections);
  playbookOutput.classList.remove("empty");
  playbookOutput.textContent = JSON.stringify(data, null, 2);
  setStatus("Implementation Playbook", "Displayed the full lab setup, OpenAPI discovery, injection engine, reporting, and standards playbook.");
});

showSourcesButton?.addEventListener("click", async () => {
  const response = await fetch("/api/analysis/sources");
  const data = await response.json();
  renderSources(data.sources);
  sourcesOutput.classList.remove("empty");
  sourcesOutput.textContent = JSON.stringify(data, null, 2);
  setStatus("Research Sources", "Displayed specifications, OWASP guidance, open-source documentation, and 5G API security research references.");
});

runScanButton?.addEventListener("click", async () => {
  const selectedModules = Array.from(scanModulesField.selectedOptions).map((option) => option.value);
  resultCard.classList.remove("empty");
  resultCard.textContent = "Launching structured scan...";
  const response = await fetch("/api/scanner/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      profile_name: scanProfileField.value,
      mode: scanModeField.value,
      selected_modules: selectedModules,
    }),
  });
  const data = await response.json();
  renderResult(data);
  await refreshRuns();
  setStatus("Structured Scan Completed", `Structured scan finished on ${scanProfileField.value} with ${data.run_summary.findings_count} findings.`);
});

refreshRunsButton?.addEventListener("click", async () => {
  await refreshRuns();
  setStatus("Runs Refreshed", "Loaded the latest structured scan summaries from the shared engine.");
});

uploadForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = simulatorFileInput.files?.[0];
  if (!file) {
    setStatus("Upload Required", "Select an API simulator or replay scenario file before uploading.");
    return;
  }

  uploadOutput.classList.remove("empty");
  uploadOutput.textContent = "Uploading simulator file...";

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/api/tester/upload", {
    method: "POST",
    body: formData,
  });
  const data = await response.json();
  uploadOutput.textContent = JSON.stringify(data, null, 2);
  setStatus("Simulator Uploaded", `${data.filename} uploaded successfully for the 5G Core microservice API tester.`);
});

filterButton?.addEventListener("click", () => {
  highRiskFilterEnabled = !highRiskFilterEnabled;
  filterButton.classList.toggle("is-active", highRiskFilterEnabled);
  applyTableFilters();
  setStatus(
    "Risk Filter",
    highRiskFilterEnabled
      ? "Showing only high-risk API assets with a security score of 60 percent or more."
      : "Showing all discovered API assets again."
  );
});

if (searchInput) {
  searchInput.addEventListener("input", () => {
    applyTableFilters();
    setStatus("Search Filter", searchInput.value ? `Filtering discovered API rows by "${searchInput.value}".` : "Search cleared and all matching API rows restored.");
  });
}

document.querySelectorAll(".checkbox").forEach((checkbox) => {
  checkbox.addEventListener("click", () => {
    checkbox.classList.toggle("is-checked");
    checkbox.closest("tr")?.classList.toggle("row-selected", checkbox.classList.contains("is-checked"));
    const selectedCount = document.querySelectorAll(".checkbox.is-checked").length;
    setStatus("Row Selection", `${selectedCount} API asset row${selectedCount === 1 ? "" : "s"} selected in the attack surface table.`);
  });
});

document.querySelectorAll("[data-row-action='open']").forEach((button) => {
  button.addEventListener("click", () => {
    const row = button.closest("tr");
    const assetName = row?.querySelector(".identity-cell strong")?.textContent || "Asset";
    const score = row?.dataset.score || "0";
    renderResult({
      action: "open_asset",
      asset: assetName,
      security_score: `${score}%`,
      summary: "Loaded API asset details from the attack surface table for operator review.",
    });
    setStatus("API Asset Opened", `${assetName} was opened in the result panel for quick API security review.`);
  });
});

document.querySelectorAll("[data-row-action='delete']").forEach((button) => {
  button.addEventListener("click", () => {
    const row = button.closest("tr");
    const assetName = row?.querySelector(".identity-cell strong")?.textContent || "Asset";
    row?.classList.add("row-dimmed", "hidden-row");
    setStatus("Row Hidden", `${assetName} was hidden from the API table. Use search or refresh to restore the full dataset.`);
  });
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resultCard.classList.remove("empty");
  resultCard.textContent = "Running attack simulation...";
  setStatus("Injection Testing on 5G Core APIs", "Executing the payload against vulnerable and secure API flows.");

  const response = await fetch("/api/tester/run", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      attack_vector: attackVectorField.value,
      payload: payloadField.value,
    }),
  });

  const data = await response.json();
  renderResult(data);
  await refreshOverview();
  if (data?.evaluation?.risk_score) {
    updateGauge(Math.min(99, data.evaluation.risk_score));
  }
  setStatus("Injection Test Completed", `Test finished with a ${data?.evaluation?.risk_score ?? 0} risk score and updated API security evidence.`);
});

refreshRuns();
