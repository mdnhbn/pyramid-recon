(() => {
  const PHASES = [
    ["Scope & Setup", "Permission and scope confirmation"],
    ["Passive Recon & OSINT", "Certificate transparency lookup"],
    ["Subdomain Discovery", "Public DNS resolution"],
    ["Live Host Verification", "One homepage request to the confirmed root domain"],
    ["Technology Fingerprinting", "Analyze observed page and response headers"],
    ["Content & Directory Discovery", "Read robots.txt and sitemap.xml only"],
    ["URL & Endpoint Discovery", "Extract same-origin links from collected pages"],
    ["JavaScript Analysis", "Inspect up to three same-scope JavaScript files"],
    ["Parameter Discovery", "Inventory parameter names without values"],
    ["Passive Security Review", "Review observed security configuration indicators"],
  ];
  const STORAGE_KEY = "pyramidReconRunsV1";
  const form = document.getElementById("scan-form");
  const domainInput = document.getElementById("domain");
  const authorization = document.getElementById("authorization");
  const providerConsent = document.getElementById("provider-consent");
  const runButton = document.getElementById("run-button");
  const stopButton = document.getElementById("stop-button");
  const clearHistoryButton = document.getElementById("clear-history");
  const phaseList = document.getElementById("phase-list");
  const emptyState = document.getElementById("empty-state");
  const finalCard = document.getElementById("final-card");
  const finalSummary = document.getElementById("final-summary");
  const finalJson = document.getElementById("final-json");
  const downloadButton = document.getElementById("download-report");
  const downloadPdfButton = document.getElementById("download-pdf");
  const downloadDocxButton = document.getElementById("download-docx");
  const progressLabel = document.getElementById("progress-label");
  const progressValue = document.getElementById("progress-value");
  const progressBar = document.getElementById("progress-bar");
  const statePill = document.getElementById("run-state");
  const stateLabel = document.getElementById("state-label");
  const reportHint = document.getElementById("report-hint");
  const toast = document.getElementById("toast");
  const backendStatus = document.getElementById("backend-status");
  const themeToggle = document.getElementById("theme-toggle");

  let backendAvailable = false;
  let activeController = null;
  let currentReports = [];
  let currentFinal = null;
  let toastTimer = null;

  function normalizeInputDomain(value) {
    const candidate = value.trim();
    if (!candidate || candidate.includes("@") || /[/?#\\]/.test(candidate)) return "";
    try {
      const parsed = new URL(`https://${candidate}`);
      if (parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.port) return "";
      return parsed.hostname.toLowerCase().replace(/\.$/, "");
    } catch {
      return "";
    }
  }

  function updateReadyState() {
    const domain = normalizeInputDomain(domainInput.value);
    const ready = Boolean(domain && authorization.checked && providerConsent.checked && backendAvailable && !activeController);
    runButton.disabled = !ready;
  }

  function toastMessage(message) {
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 2500);
  }

  function setTheme(theme) {
    const light = theme === "light";
    document.documentElement.dataset.theme = light ? "light" : "dark";
    themeToggle.textContent = light ? "☾ Dark" : "☼ Light";
    themeToggle.setAttribute("aria-label", `Switch to ${light ? "dark" : "light"} theme`);
    themeToggle.title = `Switch to ${light ? "dark" : "light"} theme`;
    try { localStorage.setItem("pyramidReconTheme", light ? "light" : "dark"); } catch { /* Theme still works for this page. */ }
  }

  function setExportButtonsDisabled(disabled) {
    downloadButton.disabled = disabled;
    downloadPdfButton.disabled = disabled;
    downloadDocxButton.disabled = disabled;
  }

  async function checkBackend() {
    backendAvailable = false;
    backendStatus.dataset.state = "checking";
    backendStatus.lastElementChild.textContent = "Python backend যাচাই হচ্ছে…";
    try {
      const response = await fetch("/api/health", { headers: { "Accept": "application/json" }, cache: "no-store" });
      const health = response.ok ? await response.json() : null;
      backendAvailable = Boolean(health && health.status === "ok" && health.phases === 10);
      backendStatus.dataset.state = backendAvailable ? "online" : "offline";
      backendStatus.lastElementChild.textContent = backendAvailable ? `Python backend online · ${health.phases} phases` : "Python backend unavailable · retry";
    } catch {
      backendStatus.dataset.state = "offline";
      backendStatus.lastElementChild.textContent = "Python backend unavailable · retry";
    }
    updateReadyState();
  }

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function makePhaseCard(index) {
    const card = document.createElement("details");
    card.className = "phase-card queued";
    card.id = `phase-${index}`;
    const summary = document.createElement("summary");
    const number = node("span", "phase-number", String(index));
    const title = node("span", "phase-title");
    title.append(node("strong", "", PHASES[index][0]), node("small", "", PHASES[index][1]));
    const duration = node("span", "phase-duration", "—");
    const badge = node("span", "status-badge", "Queued");
    badge.dataset.role = "status";
    summary.append(number, title, duration, badge);
    const details = node("div", "phase-details");
    const placeholder = node("p", "phase-placeholder", "এই phase-এর report আসার অপেক্ষায়।");
    placeholder.dataset.role = "placeholder";
    details.append(placeholder);
    card.append(summary, details);
    return card;
  }

  function resetCards() {
    phaseList.replaceChildren(...PHASES.map((_, index) => makePhaseCard(index)));
    progressBar.style.width = "0%";
    progressValue.textContent = "0 / 10";
    progressLabel.textContent = "অপেক্ষায় আছে";
    finalCard.hidden = true;
    emptyState.hidden = false;
    currentReports = [];
    currentFinal = null;
    reportHint.textContent = "প্রতিটি ধাপের input, analysis ও output এখানে জমা হবে।";
  }

  function markRunning(index) {
    const card = document.getElementById(`phase-${index}`);
    if (!card) return;
    card.classList.remove("queued");
    card.classList.add("active");
    const badge = card.querySelector('[data-role="status"]');
    if (badge) badge.textContent = "Running";
    progressLabel.textContent = `Phase ${index} চলছে · ${PHASES[index][0]}`;
    statePill.classList.add("running");
    statePill.classList.remove("error");
    stateLabel.textContent = "Serial pipeline running";
  }

  function renderPhase(report) {
    const card = document.getElementById(`phase-${report.phase}`);
    if (!card) return;
    card.classList.remove("active", "queued", "completed", "completed_with_warnings", "blocked", "failed");
    card.classList.add(report.status);
    const badge = card.querySelector('[data-role="status"]');
    if (badge) badge.textContent = report.status.replaceAll("_", " ");
    const duration = card.querySelector(".phase-duration");
    if (duration) duration.textContent = `${report.duration_ms} ms`;

    const details = card.querySelector(".phase-details");
    details.replaceChildren();
    if (report.input && report.input.from_phase !== null && report.input.from_phase !== undefined) {
      const handoff = node("div", "handoff");
      handoff.append(node("span", "", `Phase ${report.input.from_phase} report`), node("b", "", "→"), node("span", "", `Phase ${report.phase} input`));
      details.append(handoff);
    } else {
      details.append(node("div", "handoff", "Initial input · domain and authorization"));
    }
    details.append(node("p", "analysis", report.analysis || "No analysis note."));

    const inputBlock = node("div", "report-block");
    inputBlock.append(node("label", "", "COMPLETE PREVIOUS PHASE REPORT"));
    const inputPre = node("pre", "", JSON.stringify(report.input?.report ?? {}, null, 2));
    inputBlock.append(inputPre);
    details.append(inputBlock);

    const outputBlock = node("div", "report-block");
    outputBlock.append(node("label", "", "THIS PHASE OUTPUT"));
    const outputPre = node("pre", "", JSON.stringify(report.outputs ?? {}, null, 2));
    outputBlock.append(outputPre);
    details.append(outputBlock);

    if (Array.isArray(report.warnings) && report.warnings.length) {
      const list = node("ul", "warning-list");
      for (const warning of report.warnings) list.append(node("li", "", warning));
      details.append(list);
    }
    card.open = report.phase === currentReports.length - 1;
  }

  function metric(value, label) {
    const item = node("div", "summary-metric");
    item.append(node("strong", "", String(value ?? 0)), node("span", "", label));
    return item;
  }

  function renderFinal(report) {
    currentFinal = report;
    const summary = report.summary || {};
    finalSummary.replaceChildren(
      metric(summary.overall_status || "unknown", "overall status"),
      metric(summary.phases_completed ?? 0, "phases completed"),
      metric(summary.live_hosts ?? 0, "live hosts"),
      metric(summary.findings_for_manual_review ?? 0, "items for review"),
    );
    const findings = report.final_findings || [];
    if (findings.length) {
      const list = node("div", "finding-list");
      for (const finding of findings.slice(0, 12)) {
        const item = node("div", "finding-item");
        item.append(node("span", "finding-severity", finding.severity || "review"));
        const body = node("div", "");
        body.append(node("strong", "", finding.title || "Review item"), node("small", "", `${finding.asset || "asset"} · ${finding.evidence || "Manual review required."}`));
        item.append(body);
        list.append(item);
      }
      finalSummary.append(list);
    } else {
      finalSummary.append(node("p", "tiny-note", "কোনো finding তৈরি হয়নি, অথবা Phase 9 পর্যন্ত পৌঁছানো যায়নি। Phase report-গুলো আলাদাভাবে দেখুন।"));
    }
    finalJson.textContent = JSON.stringify(report, null, 2);
    finalCard.hidden = false;
    emptyState.hidden = true;
    const completed = summary.phases_completed || 0;
    progressValue.textContent = `${completed} / 10`;
    progressBar.style.width = `${Math.min(100, completed * 10)}%`;
    progressLabel.textContent = summary.overall_status === "completed" ? "সব phase-এর report সম্পন্ন" : `Pipeline ${summary.overall_status || "শেষ"}`;
    reportHint.textContent = `${summary.domain || report.domain} · প্রতিটি phase report সংরক্ষিত`;
    statePill.classList.remove("running");
    statePill.classList.toggle("error", summary.overall_status === "blocked" || summary.overall_status === "partial");
    stateLabel.textContent = summary.overall_status === "completed" ? "Run completed" : `Run ${summary.overall_status || "ended"}`;
    setExportButtonsDisabled(false);
  }

  function saveRun(report) {
    try {
      const previous = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
      const runs = Array.isArray(previous) ? previous.filter(item => item.job_id !== report.job_id) : [];
      runs.unshift(report);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(runs.slice(0, 5)));
    } catch {
      toastMessage("Browser storage is full; download the report to keep a copy");
    }
  }

  function handleEvent(event) {
    if (event.type === "phase") {
      const report = event.report;
      currentReports.push(report);
      renderPhase(report);
      emptyState.hidden = true;
      progressValue.textContent = `${currentReports.length} / 10`;
      progressBar.style.width = `${Math.min(98, currentReports.length * 10)}%`;
      if (report.status === "blocked" || report.status === "failed") {
        statePill.classList.remove("running");
        statePill.classList.add("error");
        stateLabel.textContent = `Phase ${report.phase} ${report.status}`;
      } else if (report.phase < 9) {
        markRunning(report.phase + 1);
      }
    }
    if (event.type === "final") {
      renderFinal(event.report);
      saveRun(event.report);
    }
  }

  async function runScan() {
    const domain = normalizeInputDomain(domainInput.value);
    if (!domain) {
      toastMessage("শুধু সঠিক root domain দিন, যেমন example.com");
      domainInput.focus();
      return;
    }
    if (!authorization.checked || !providerConsent.checked) {
      toastMessage("চালানোর আগে অনুমতি ও public-provider সম্মতি দিন");
      return;
    }
    resetCards();
    emptyState.hidden = true;
    activeController = new AbortController();
    stopButton.hidden = false;
    runButton.disabled = true;
    markRunning(0);
    setExportButtonsDisabled(true);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/x-ndjson" },
        body: JSON.stringify({
          domain,
          authorization_confirmed: authorization.checked,
          provider_consent: providerConsent.checked,
        }),
        signal: activeController.signal,
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || `Request failed (${response.status})`);
      }
      if (!response.body) throw new Error("Streaming response is unavailable in this browser.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          try { handleEvent(JSON.parse(line)); } catch { /* Ignore malformed stream fragments. */ }
        }
      }
      buffer += decoder.decode();
      if (buffer.trim()) {
        try { handleEvent(JSON.parse(buffer)); } catch { /* Ignore malformed final fragment. */ }
      }
      if (!currentFinal && activeController) {
        statePill.classList.remove("running");
        stateLabel.textContent = "Run stopped or stream ended";
        progressLabel.textContent = "শেষ event পাওয়া যায়নি";
        toastMessage("Stream ended before the final report arrived");
      }
    } catch (error) {
      if (error.name === "AbortError") {
        stateLabel.textContent = "Run stopped";
        progressLabel.textContent = "ব্যবহারকারী run থামিয়েছেন";
        toastMessage("Run stopped");
      } else {
        statePill.classList.remove("running");
        statePill.classList.add("error");
        stateLabel.textContent = "Run could not complete";
        progressLabel.textContent = "Connection or server error";
        toastMessage(error.message || "Could not reach the Python backend");
      }
    } finally {
      activeController = null;
      stopButton.hidden = true;
      updateReadyState();
    }
  }

  function restoreLastRun() {
    try {
      const runs = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
      if (!Array.isArray(runs) || !runs.length) return;
      const report = runs[0];
      resetCards();
      currentReports = report.phase_reports || [];
      for (const phaseReport of currentReports) renderPhase(phaseReport);
      if (report.summary) renderFinal(report);
      emptyState.hidden = true;
      reportHint.textContent = `${report.domain} · saved in this browser`;
      stateLabel.textContent = "Last saved run";
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
  }

  domainInput.addEventListener("input", updateReadyState);
  authorization.addEventListener("change", updateReadyState);
  providerConsent.addEventListener("change", updateReadyState);
  backendStatus.addEventListener("click", checkBackend);
  form.addEventListener("submit", event => { event.preventDefault(); runScan(); });
  stopButton.addEventListener("click", () => activeController?.abort());
  clearHistoryButton.addEventListener("click", () => {
    if (activeController) return;
    localStorage.removeItem(STORAGE_KEY);
    resetCards();
    statePill.classList.remove("error", "running");
    stateLabel.textContent = "Ready to configure";
    setExportButtonsDisabled(true);
    toastMessage("Saved browser history cleared");
  });
  downloadButton.addEventListener("click", () => {
    if (!currentFinal) return;
    const blob = new Blob([JSON.stringify(currentFinal, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `pyramid-recon-${currentFinal.domain}-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  async function downloadOfficeReport(button, format) {
    if (!currentFinal) return;
    button.disabled = true;
    try {
      const response = await fetch(`/api/report/${format}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": format === "pdf" ? "application/pdf" : "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
        body: JSON.stringify({ report: currentFinal }),
      });
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.detail || error.error || `Export failed (${response.status})`);
      }
      const blob = await response.blob();
      const date = new Date().toISOString().slice(0, 10);
      const extension = format === "pdf" ? "pdf" : "docx";
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `pyramid-recon-${currentFinal.domain}-${date}.${extension}`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    } catch (error) {
      toastMessage(error.message || "Could not export the report");
    } finally {
      button.disabled = !currentFinal;
    }
  }

  downloadPdfButton.addEventListener("click", () => downloadOfficeReport(downloadPdfButton, "pdf"));
  downloadDocxButton.addEventListener("click", () => downloadOfficeReport(downloadDocxButton, "docx"));
  themeToggle.addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light"));

  try {
    setTheme(localStorage.getItem("pyramidReconTheme") || "dark");
  } catch {
    setTheme("dark");
  }

  resetCards();
  restoreLastRun();
  updateReadyState();
  checkBackend();
})();

