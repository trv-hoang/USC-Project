const $ = (s) => document.querySelector(s);
const presetSel = $("#preset");
const analyzeBtn = $("#analyze");

async function loadPresets() {
  const presets = await (await fetch("/api/presets")).json();
  presetSel.innerHTML = presets
    .map((p) => `<option value="${p.id}">${p.scenario} — ${p.label}</option>`)
    .join("");
  loadSource();
}

async function loadSource() {
  const id = presetSel.value;
  const [v1, v2] = await Promise.all([
    fetch(`/api/source?preset=${id}&version=v1`).then((r) => r.json()),
    fetch(`/api/source?preset=${id}&version=v2`).then((r) => r.json()),
  ]);
  $("#code-v1").textContent = v1.code;
  $("#code-v2").textContent = v2.code;
}

function resetView() {
  $("#source-flag").textContent = "";
  $("#terminal").innerHTML = "";
  document.querySelectorAll(".stage").forEach((s) => s.classList.remove("done", "active"));
  document.querySelectorAll(".anno").forEach((a) => (a.textContent = ""));
  ["#verdict", "#slot-card", "#findings-card", "#matched-card", "#checklist-card"]
    .forEach((s) => ($(s).hidden = true));
}

function appendLog(line) {
  let cls = "term-cmd";
  if (line.startsWith("$")) cls = "term-cmd";
  else if (line.startsWith("[!]")) cls = "term-err";
  else if (line.includes("⏱") || line.startsWith("Pipeline complete")) cls = "term-done";
  else if (line.trimStart().startsWith("[")) cls = "term-action";
  else if (line.trimStart().startsWith("->") || line.includes("-> ")) cls = "term-detail";
  else if (line.startsWith("Stage")) cls = "term-stage";
  const term = $("#terminal");
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = line + "\n";
  term.appendChild(span);
  term.scrollTop = term.scrollHeight;
}

function setAnnotations(p) {
  const fired = (p.findings.v2 || []).length;
  const conf = (p.matched_pairs || [])[0];
  const collided = (p.storage.collisions || []).length;
  $("#anno-1").textContent = "2 file .sol";
  $("#anno-2").textContent = collided ? `collision ×${collided}` : "no collision";
  $("#anno-3").textContent = fired ? `detector fired ×${fired}` : "0 finding";
  $("#anno-4").textContent = conf ? `conf ${conf.confidence.toFixed(2)}` : "0 cặp";
  $("#anno-5").textContent = `risk ${p.risk_level}`;
}

function setStage(n) {
  document.querySelectorAll(".stage").forEach((s) => {
    const k = +s.dataset.stage;
    s.classList.toggle("done", k <= n);
    s.classList.toggle("active", k === n + 1);
  });
}

function escapeHtml(t) {
  return t.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function renderSlots(el, slots, collidedSlots) {
  el.innerHTML = Object.keys(slots)
    .sort((a, b) => a - b)
    .map((k) => {
      const v = slots[k];
      const hit = collidedSlots.has(+k) ? " collision" : "";
      return `<div class="slot${hit}">slot ${k} · ${escapeHtml(v.name)} : ${escapeHtml(v.type)}</div>`;
    })
    .join("");
}

function renderFindings(f) {
  const row = (x, cls) =>
    `<div class="finding ${cls}"><span class="det">${escapeHtml(x.detector_id)}</span>` +
    `<span class="sev ${x.severity}">${x.severity}</span>` +
    `<div>${escapeHtml(x.description || "")}</div></div>`;
  const intro = (f.introduced || []).map((x) => row(x, "introduced")).join("");
  const fixed = (f.fixed || []).map((x) => row(x, "fixed")).join("");
  $("#findings").innerHTML =
    (intro || fixed) ? intro + fixed : `<div class="ok-note" style="padding:12px 14px">✓ Không có lỗ hổng được đưa vào</div>`;
}

function renderMatched(pairs) {
  const dims = ["pos", "pattern", "semantic", "type", "slot"];
  $("#matched").innerHTML = (pairs || [])
    .map((p) => {
      const bars = dims
        .map((d) => `<div class="dim">${d} ${p.scores[d].toFixed(2)}<div class="bar"><i style="width:${p.scores[d] * 100}%"></i></div></div>`)
        .join("");
      return `<div class="mp"><b>Confidence ${p.confidence.toFixed(2)}</b>` +
        `<div class="rc">${escapeHtml(p.root_cause || "")}</div><div class="dims">${bars}</div></div>`;
    })
    .join("") || `<div class="ok-note" style="padding:12px 14px">Không có cặp ánh xạ</div>`;
}

function renderChecklist(md) {
  // minimal markdown: headings + list items (offline-safe, no CDN)
  const html = (md || "")
    .split("\n")
    .map((l) => {
      if (l.startsWith("### ")) return `<h3>${escapeHtml(l.slice(4))}</h3>`;
      if (l.startsWith("## ")) return `<h2>${escapeHtml(l.slice(3))}</h2>`;
      if (/^\s*-\s/.test(l)) return `<li>${escapeHtml(l.replace(/^\s*-\s/, ""))}</li>`;
      return l.trim() ? `<p>${escapeHtml(l)}</p>` : "";
    })
    .join("");
  $("#checklist").innerHTML = html;
}

function renderResult(p) {
  setStage(5);
  $("#badge-behavior").innerHTML = `<small>HÀNH VI NÂNG CẤP</small>${p.behavior}`;
  const risk = $("#badge-risk");
  risk.innerHTML = `<small>RISK LEVEL</small>${p.risk_level}`;
  risk.classList.toggle("low", ["Low", "Smooth Upgrade"].includes(p.risk_level));
  $("#verdict").hidden = false;

  const collided = new Set((p.storage.collisions || []).map((c) => c.slot));
  renderSlots($("#slots-v1"), p.storage.v1_slots, collided);
  renderSlots($("#slots-v2"), p.storage.v2_slots, collided);
  $("#no-collision").hidden = collided.size > 0;
  $("#slot-card").hidden = false;

  renderFindings(p.findings);
  $("#findings-card").hidden = false;
  renderMatched(p.matched_pairs);
  $("#matched-card").hidden = false;
  renderChecklist(p.checklist_md);
  $("#checklist-card").hidden = false;

  setAnnotations(p);
  if (p.source === "cached") $("#source-flag").textContent = "⚠ chế độ dự phòng (cache)";
  analyzeBtn.disabled = false;
}

function analyze() {
  resetView();
  analyzeBtn.disabled = true;
  const es = new EventSource(`/api/analyze?preset=${presetSel.value}`);
  es.addEventListener("log", (e) => appendLog(JSON.parse(e.data).line));
  es.addEventListener("stage", (e) => setStage(JSON.parse(e.data).stage));
  es.addEventListener("fallback", () => {
    $("#source-flag").textContent = "⚠ live lỗi → dùng cache";
  });
  es.addEventListener("result", (e) => {
    renderResult(JSON.parse(e.data));
    es.close();
  });
  es.addEventListener("error", () => {
    es.close();
    analyzeBtn.disabled = false;
    alert("Phân tích thất bại và không có cache dự phòng.");
  });
}

async function loadAlgorithms() {
  const algos = await (await fetch("/api/algorithm")).json();
  const tabs = $("#algo-tabs");
  tabs.innerHTML = algos
    .map((a, i) => `<div class="algo-tab${i === 0 ? " active" : ""}" data-i="${i}">${escapeHtml(a.name)}</div>`)
    .join("");
  const show = (i) => {
    $("#algo-pseudo").textContent = algos[i].pseudo || "";
    $("#algo-code").textContent = `# ${algos[i].file}\n\n${algos[i].code}`;
    $("#algo-mod").textContent = algos[i].module ? `· ${algos[i].module}` : "";
    tabs.querySelectorAll(".algo-tab").forEach((t) => t.classList.toggle("active", +t.dataset.i === i));
  };
  tabs.querySelectorAll(".algo-tab").forEach((t) => t.addEventListener("click", () => show(+t.dataset.i)));
  if (algos.length) show(0);
}

// ---------- Dataset & Evaluation view ----------
function pct(x) { return (x * 100).toFixed(x === 1 ? 0 : 2) + "%"; }

function metricCard(title, cls, m) {
  const row = (lbl, v) =>
    `<div class="metric-row"><span class="lbl">${lbl}</span>` +
    `<span class="mbar"><i style="width:${v * 100}%"></i></span>` +
    `<span class="num">${pct(v)}</span></div>`;
  return `<div class="eval-card ${cls}"><h4>${title}</h4>` +
    row("Precision", m.precision) + row("Recall", m.recall) + row("F1-score", m.f1) + `</div>`;
}

function distBlock(title, items) {
  const max = Math.max(...items.map((i) => i.count), 1);
  const rows = items
    .map((i) => `<div class="drow"><span class="dl">${escapeHtml(i.label)}</span>` +
      `<span class="db"><i style="width:${(i.count / max) * 100}%"></i></span>` +
      `<span class="dc">${i.count}</span></div>`)
    .join("");
  return `<div class="dist-block"><h4>${title}</h4>${rows}</div>`;
}

async function loadDataset() {
  const d = await (await fetch("/api/dataset")).json();
  const m = d.metrics;
  $("#eval-metrics").innerHTML =
    `<div class="eval-grid">${metricCard("EADF (đề tài)", "eadf", m.eadf)}` +
    `${metricCard("Slither đơn thuần (baseline)", "base", m.baseline)}</div>` +
    `<div class="gap-note"><b>Khoảng cách recall:</b> EADF ${pct(m.eadf.recall)} vs Slither ${pct(m.baseline.recall)} ` +
    `→ baseline bỏ sót ~${Math.round((1 - m.baseline.recall) * 100)}% lỗ hổng đặc thù nâng cấp. ` +
    `Độ chính xác phân loại hành vi: EADF ${pct(m.eadf_behavior_acc)} vs Slither ${pct(m.baseline_behavior_acc)}.</div>`;
  $("#dist-charts").innerHTML =
    distBlock(`Hành vi nâng cấp (tổng ${d.total} cặp)`, d.behavior) +
    distBlock("Loại lỗ hổng (detector_id, ground truth)", d.vulns) +
    distBlock("Mẫu proxy", d.proxy);
}

function switchView(view) {
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $("#view-analyze").hidden = view !== "analyze";
  $("#view-dataset").hidden = view !== "dataset";
  $("#analyze-controls").style.display = view === "analyze" ? "flex" : "none";
}

document.querySelectorAll(".nav-btn").forEach((b) =>
  b.addEventListener("click", () => switchView(b.dataset.view)));

presetSel.addEventListener("change", () => { resetView(); loadSource(); });
analyzeBtn.addEventListener("click", analyze);
loadPresets();
loadAlgorithms();
loadDataset();
