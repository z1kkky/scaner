"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const byID = (id) => document.getElementById(id);
const state = {
  targets: [], jobs: [], page: "overview", filter: "all", selectedReportJobID: "",
  modalStep: 0, modalTarget: null, modalMethod: "dns", refreshing: false,
};

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = String(text);
  return item;
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function showNotice(message, error = false) {
  const notice = byID("notice");
  notice.textContent = message;
  notice.classList.toggle("error", error);
  notice.hidden = false;
  window.clearTimeout(showNotice.timer);
  showNotice.timer = window.setTimeout(() => { notice.hidden = true; }, 6500);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.method && options.method !== "GET" && options.method !== "HEAD") headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, headers, credentials: "same-origin", cache: "no-store" });
  const text = await response.text();
  const type = response.headers.get("Content-Type") || "";
  let body = text;
  if (type.includes("application/json") && text) {
    try { body = JSON.parse(text); } catch (_) { body = text; }
  }
  if (!response.ok) {
    const message = typeof body === "string" ? body.trim() : body.error || body.message || response.statusText;
    throw new Error(message || `HTTP ${response.status}`);
  }
  return body;
}

function sortedJobs() {
  return [...state.jobs].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
}

function resultOf(job) {
  if (!job?.result) return {};
  if (typeof job.result === "object") return job.result;
  try { return JSON.parse(job.result); } catch (_) { return {}; }
}

function targetByID(id) { return state.targets.find((target) => target.id === id); }
function jobByID(id) { return state.jobs.find((job) => job.id === id); }

function showPage(page) {
  if (!["overview", "domains", "report"].includes(page)) return;
  state.page = page;
  const titles = { overview: "Обзор", domains: "Мои сайты", report: "Отчёт" };
  for (const section of document.querySelectorAll(".page")) {
    const active = section.id === page;
    section.classList.toggle("active", active);
    section.hidden = !active;
  }
  for (const button of document.querySelectorAll(".nav button[data-page]")) {
    const active = button.dataset.page === page;
    button.classList.toggle("active", active);
    button.setAttribute("aria-current", active ? "page" : "false");
  }
  byID("breadcrumb").textContent = titles[page];
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function formatDate(value, style = "short") {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : new Intl.DateTimeFormat("ru-RU", { dateStyle: style, timeStyle: "short" }).format(date);
}

function statusText(status) {
  return ({ completed: "Завершена", incomplete: "Неполная", failed: "Ошибка", running: "Выполняется", queued: "В очереди", cancelled: "Отменена", interrupted: "Прервана", skipped: "Пропущена" })[status] || status || "Нет данных";
}

function coverageText(status) {
  return ({ completed: "Без замечаний", incomplete: "Проверено частично", failed: "Не удалось проверить", skipped: "Не входит в охват", cancelled: "Отменено" })[status] || "Нет данных";
}

const checkMeta = {
  tls: ["HTTPS и сертификат", "Сертификат, TLS и переход на HTTPS"],
  headers: ["Заголовки и cookies", "Защитные заголовки и настройки cookies"],
  email: ["Доменная почта", "SPF, DKIM и DMARC"],
  exposures: ["Служебные ресурсы", "Фиксированные чувствительные пути"],
  ports: ["Открытые порты", "Только согласованные TCP-порты"],
  cms: ["Признаки CMS", "Пассивное определение платформы"],
  nuclei: ["Nuclei", "Встроенные безопасные HTTP GET-шаблоны"],
};

function reportCategories(job) {
  const report = resultOf(job);
  const grouped = new Map();
  for (const host of report.hosts || []) {
    for (const category of host.categories || []) {
      const entry = grouped.get(category.check) || { check: category.check, statuses: [], findings: [], hosts: [], probes: [] };
      entry.statuses.push(category.status || "incomplete");
      entry.findings.push(...(category.findings || []));
      entry.hosts.push(host.host);
      entry.probes.push(...(category.probes || []));
      grouped.set(category.check, entry);
    }
  }
  if (report.nuclei) {
    const entry = grouped.get("nuclei") || { check: "nuclei", statuses: [], findings: [], hosts: [], probes: [] };
    entry.statuses.push(report.nuclei.status || "incomplete");
    entry.findings.push(...(report.nuclei.findings || []));
    if (report.nuclei.error) entry.error = report.nuclei.error;
    grouped.set("nuclei", entry);
  }
  if (job?.simulation && grouped.size === 0) {
    // These are explicitly synthetic demo categories, never live-scan claims.
    const sample = [
      ["tls", "completed", 0], ["headers", "completed", 1], ["email", "incomplete", 0],
      ["exposures", "completed", 0], ["ports", "completed", 1], ["cms", "completed", 0],
    ];
    for (const [check, status, findingCount] of sample) grouped.set(check, { check, statuses: [status], findings: Array.from({ length: findingCount }, () => ({})), hosts: ["demo.invalid"], probes: [] });
  }
  return [...grouped.values()].sort((a, b) => {
    const order = ["tls", "headers", "email", "exposures", "ports", "cms", "nuclei"];
    return order.indexOf(a.check) - order.indexOf(b.check);
  });
}

function categoryStatus(category) {
  if (category.statuses.includes("failed")) return "failed";
  if (category.statuses.includes("incomplete")) return "incomplete";
  if (category.statuses.includes("skipped")) return "skipped";
  if (category.statuses.includes("cancelled")) return "cancelled";
  return category.statuses[0] || "incomplete";
}

function renderCategoryList(root, categories) {
  root.replaceChildren();
  if (!categories.length) {
    root.append(node("div", "empty-note", "Категории появятся после завершения проверки."));
    return;
  }
  for (const category of categories) {
    const [name, detail] = checkMeta[category.check] || [category.check || "Проверка", "Результат проверки"];
    const status = categoryStatus(category);
    const kind = status === "completed" ? (category.findings.length ? "warn" : "ok") : (status === "failed" || status === "cancelled" ? "bad" : "partial");
    const row = node("div", "check-row");
    row.append(node("span", `check-symbol ${kind}`, kind === "ok" ? "✓" : kind === "warn" ? "!" : kind === "bad" ? "×" : "◐"));
    const label = node("span", "check-label");
    label.append(node("b", "", name));
    const probeCount = category.probes.length ? ` · ${category.probes.length} подпроб` : "";
    label.append(node("small", "", `${detail}${probeCount}`));
    row.append(label);
    row.append(node("span", `check-status ${kind}`, status === "completed" && category.findings.length ? `${category.findings.length} замеч.` : coverageText(status)));
    root.append(row);
  }
}

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    const severity = String(finding.severity || "info").toLowerCase();
    if (Object.hasOwn(counts, severity)) counts[severity]++;
  }
  return counts;
}

function scoreFor(job, categories) {
  const report = resultOf(job);
  if (!job || job.status !== "completed" || report.status === "incomplete") return null;
  if (job.simulation && Number.isInteger(report.score)) return { value: report.score, grade: report.grade || gradeFor(report.score) };
  if (!categories.length || categories.some((category) => categoryStatus(category) !== "completed")) return null;
  const penalties = new Map();
  for (const category of categories) {
    for (const finding of category.findings) {
      const severity = String(finding.severity || "info").toLowerCase();
      const points = ({ info: 0, low: 5, medium: 10, high: 20, critical: 35 })[severity];
      if (points === undefined) return null;
      const identity = finding.id || finding.probe_id || finding.title || "";
      const key = `${category.check}\0${identity}`;
      penalties.set(key, Math.max(penalties.get(key) || 0, points));
    }
  }
  const value = Math.max(0, 100 - [...penalties.values()].reduce((sum, points) => sum + points, 0));
  return { value, grade: gradeFor(value) };
}

function gradeFor(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  if (score >= 50) return "E";
  return "F";
}

function allFindings(job) {
  const report = resultOf(job);
  if (Array.isArray(report.findings)) return report.findings;
  return reportCategories(job).flatMap((category) => category.findings);
}

function renderScore(job, categories, { overview = false } = {}) {
  const score = scoreFor(job, categories);
  const findings = allFindings(job);
  const heading = overview ? byID("scoreValue") : byID("reportScore");
  if (overview) {
    byID("scoreRing").setAttribute("aria-label", score ? `Оценка безопасности ${score.value} из 100` : "Оценка безопасности недоступна");
    byID("scoreArc").setAttribute("stroke-dasharray", score ? `${score.value} ${100 - score.value}` : "0 100");
    byID("scoreValue").textContent = score ? String(score.value) : "—";
    byID("scoreScale").textContent = score ? "из 100" : "нет оценки";
    byID("scoreGrade").textContent = score ? `ОЦЕНКА ${score.grade}` : (job?.simulation ? "ДЕМО · ПРИМЕР" : "НЕТ ОЦЕНКИ");
    byID("scoreHeading").textContent = score ? (score.value >= 90 ? "Хороший результат" : "Есть что улучшить") : "Нужен полный охват";
    byID("scoreDescription").textContent = score ? (score.value >= 90 ? "Проверка завершена. Рекомендации и охват доступны в отчёте." : "Найдены настройки, которые стоит исправить. Начните с рекомендаций в отчёте.") : "Оценка рассчитывается только по полному отчёту. Неполные данные не превращаются в балл.";
  } else {
    byID("reportScore").textContent = score ? String(score.value) : "—";
    byID("reportGrade").innerHTML = score ? `из 100<br>Оценка ${escapeHTML(score.grade)}` : "из 100<br>Нет оценки";
  }
  const critical = findings.filter((finding) => finding.severity === "critical").length;
  const attention = findings.filter((finding) => ["high", "medium", "low"].includes(finding.severity)).length;
  const clean = categories.filter((category) => categoryStatus(category) === "completed" && category.findings.length === 0).length;
  const partial = categories.filter((category) => categoryStatus(category) !== "completed").length;
  if (overview) {
    byID("summaryCritical").textContent = job ? String(critical) : "—";
    byID("summaryAttention").textContent = job ? String(attention) : "—";
    byID("summaryClean").textContent = job ? String(clean) : "—";
    byID("summaryPartial").textContent = job ? String(partial) : "—";
    byID("summaryNote").textContent = job?.simulation ? (resultOf(job).disclaimer || "Демо: учебный пример, сетевые проверки не выполнялись.") : "Частичная проверка не означает, что проблем нет. Отчёт показывает, каких данных не хватило.";
  }
  return { score, findings, critical, attention, clean, partial };
}

function renderTimeline() {
  const timeline = byID("activityTimeline");
  timeline.replaceChildren();
  const jobs = sortedJobs().slice(0, 3);
  for (const job of jobs) {
    const host = job.simulation ? "Демо · имитация" : ((job.hosts || []).join(", ") || "Сканирование");
    const event = node("div", "event");
    event.append(node("b", "", `${job.simulation ? "Демо сохранено" : `Проверка: ${statusText(job.status).toLowerCase()}`}`));
    event.append(node("small", "", `${host} · ${formatDate(job.created_at)}`));
    timeline.append(event);
  }
  for (const target of state.targets.slice(0, Math.max(0, 3 - jobs.length))) {
    const event = node("div", "event");
    event.append(node("b", "", target.verified ? "Домен подтверждён" : "Домен добавлен"));
    event.append(node("small", "", target.host));
    timeline.append(event);
  }
  if (!timeline.childElementCount) {
    const event = node("div", "event");
    event.append(node("b", "", "Начните с добавления сайта"), node("small", "", "Проверки появятся здесь после запуска"));
    timeline.append(event);
  }
}

function renderOverview() {
  const latest = sortedJobs()[0];
  const target = latest ? targetByID(latest.target_id) : state.targets.find((item) => item.verified) || state.targets[0];
  const categories = latest ? reportCategories(latest) : [];
  const summary = renderScore(latest, categories, { overview: true });
  byID("spotDomain").textContent = latest ? (latest.simulation ? "Демонстрационный отчёт" : ((latest.hosts || []).join(", ") || target?.host || "Сканирование")) : (target?.host || "Пока нет добавленных сайтов");
  byID("spotMeta").textContent = latest ? `${latest.simulation ? "Учебный пример" : "Последняя проверка"} · ${formatDate(latest.finished_at || latest.created_at)}` : (target ? (target.verified ? "Домен подтверждён · запуск доступен с разрешением" : "Ожидается TXT-подтверждение") : "Добавьте свой домен, чтобы начать");
  byID("spotFoot").textContent = latest ? `${target?.verified ? "✓ Домен подтверждён" : latest.simulation ? "Демо · сетевые проверки не выполнялись" : "Область цели"} · ${categories.length} категорий` : "◎ Добавьте сайт и подтвердите DNS";
  const overviewChecks = byID("overviewChecks");
  renderCategoryList(overviewChecks, categories);
  renderTimeline();
}

function findingNode(finding, index) {
  const type = String(finding.severity || "info").toLowerCase();
  const card = node("article", "card finding");
  const head = node("div", "finding-head");
  head.append(node("span", `severity ${type}`, type === "partial" ? "Частично" : type === "critical" ? "Критично" : type === "high" ? "Высокий" : type === "medium" ? "Средний" : type === "low" ? "Низкий" : "Инфо"));
  const title = node("div", "finding-title");
  title.append(node("h3", "", finding.title || finding.template_id || "Находка"));
  title.append(node("p", "", `${finding.check || "Проверка"}${finding.location || finding.matched_at ? ` · ${finding.location || finding.matched_at}` : ""}`));
  const toggle = node("button", "chevron", "⌄");
  toggle.type = "button";
  toggle.dataset.action = "toggle-finding";
  toggle.setAttribute("aria-label", "Развернуть рекомендации");
  toggle.setAttribute("aria-expanded", "false");
  head.append(title, toggle);
  card.append(head);
  const body = node("div", "finding-body");
  const context = node("div"); context.append(node("h4", "", "Почему это важно"), node("p", "", finding.description || finding.evidence || "Проверка обнаружила настройку, которую стоит изучить."));
  const fix = node("div", "fix"); fix.append(node("h4", "", "Что сделать"), node("p", "", finding.fix || "Проверьте настройку и повторите сканирование после исправления."));
  body.append(context, fix);
  card.append(body);
  card.dataset.severity = type;
  card.dataset.index = String(index);
  return card;
}

function renderFindings(job) {
  const root = byID("findings");
  root.replaceChildren();
  const findings = allFindings(job);
  let filtered;
  if (state.filter === "partial") {
    filtered = reportCategories(job).filter((category) => categoryStatus(category) !== "completed").map((category) => ({
      severity: "partial", check: category.check, title: `${(checkMeta[category.check] || [category.check])[0]} проверена не полностью`,
      description: category.error || "По этой категории нет полного результата. Отсутствие находок не означает, что проблема отсутствует.",
      fix: "Проверьте сообщение/подпробы в охвате категории и повторите сканирование после устранения причины.",
    }));
  } else {
    filtered = findings.filter((finding) => state.filter === "all" || String(finding.severity || "info").toLowerCase() === state.filter);
  }
  if (!filtered.length) {
    const message = node("div", "empty-note", job ? (findings.length ? "Для этого фильтра находок нет." : "В этом отчёте находки не зафиксированы. Смотрите статус и охват каждой категории выше.") : "Сначала запустите демо или выберите задачу с результатом.");
    root.append(message);
    return;
  }
  for (const [index, finding] of filtered.entries()) root.append(findingNode(finding, index));
}

function renderReport() {
  const job = jobByID(state.selectedReportJobID) || sortedJobs()[0];
  if (job) state.selectedReportJobID = job.id;
  const report = resultOf(job);
  const target = job ? targetByID(job.target_id) : null;
  const categories = job ? reportCategories(job) : [];
  const summary = renderScore(job, categories);
  byID("reportDomain").textContent = job ? (job.simulation ? "Демо · вымышленная цель" : ((job.hosts || []).join(", ") || target?.host || "Отчёт")) : "Нет выбранного отчёта";
  byID("reportMeta").textContent = job ? `${job.simulation ? (report.disclaimer || "ИМИТАЦИЯ: это пример, а не результат сканирования.") : `Статус: ${statusText(job.status)}`} · ${formatDate(job.finished_at || job.created_at)}` : "Запустите демо или откройте завершённую задачу из обзора.";
  byID("reportCategories").textContent = job ? String(categories.length) : "—";
  byID("reportFindingCount").textContent = job ? String(summary.findings.length) : "—";
  byID("reportPartialCount").textContent = job ? String(summary.partial) : "—";
  byID("reportCriticalCount").textContent = job ? String(summary.critical) : "—";
  renderCategoryList(byID("reportChecks"), categories);
  renderFindings(job);
  const incomplete = byID("reportIncomplete");
  incomplete.hidden = !job || summary.partial === 0;
  incomplete.textContent = job && summary.partial ? `Частичный охват: ${summary.partial} категорий не завершены или пропущены. Это не означает, что проблем нет.` : "";
  renderJobHistory();
}

function statusClass(status) {
  return status === "completed" ? "completed" : status || "neutral";
}

function renderJobHistory() {
  const root = byID("jobHistory");
  if (!root) return;
  root.replaceChildren();
  const jobs = sortedJobs();
  if (!jobs.length) { root.append(node("div", "empty-note", "Задач пока нет.")); return; }
  for (const job of jobs) {
    const card = node("article", "card history-job");
    const info = node("div", "history-job-info");
    info.append(node("strong", "", job.simulation ? "Демо · имитация" : (job.hosts || []).join(", ") || "Сканирование"));
    info.append(node("small", "", `${formatDate(job.created_at)} · ${statusText(job.status)}`));
    card.append(info);
    if (job.simulation) card.append(node("span", "badge neutral", "ДЕМО"));
    const actions = node("div", "domain-actions");
    const open = node("button", "secondary", "Открыть отчёт"); open.type = "button"; open.dataset.action = "open-report"; open.dataset.jobId = job.id;
    actions.append(open);
    if (["queued", "running"].includes(job.status)) {
      const cancel = node("button", "secondary", "Отменить"); cancel.type = "button"; cancel.dataset.action = "cancel-job"; cancel.dataset.jobId = job.id; actions.append(cancel);
    } else {
      const remove = node("button", "subtle", "Удалить"); remove.type = "button"; remove.dataset.action = "delete-job"; remove.dataset.jobId = job.id; actions.append(remove);
    }
    card.append(actions);
    root.append(card);
  }
}

function renderDomains() {
  const root = byID("domainList");
  root.replaceChildren();
  const targets = [...state.targets].sort((a, b) => a.host.localeCompare(b.host));
  byID("domainCount").textContent = `${targets.length} ${targets.length === 1 ? "сайт" : targets.length > 1 && targets.length < 5 ? "сайта" : "сайтов"}`;
  if (!targets.length) { root.append(node("div", "empty-note", "Сайтов пока нет. Добавьте домен, которым вы управляете.")); return; }
  for (const target of targets) {
    const card = node("article", "card domain-card");
    card.append(node("span", "site-icon", "◎"));
    const info = node("div");
    info.append(node("h3", "", target.host));
    info.append(node("p", "", target.verified ? `Область: ${(target.scope_hosts || []).join(", ")} · порты ${(target.ports || []).join(", ")}` : "TXT-подтверждение ожидается"));
    card.append(info);
    card.append(node("span", `badge ${target.verified ? "verified" : "neutral"}`, target.verified ? "✓ Подтверждён" : "◐ Ожидает TXT"));
    const actions = node("div", "domain-actions");
    const primary = node("button", "secondary", target.verified ? "Запустить проверку" : "Подтвердить DNS");
    primary.type = "button"; primary.dataset.action = target.verified ? "scan-target" : "verify-target"; primary.dataset.targetId = target.id;
    const remove = node("button", "subtle", "Удалить сайт"); remove.type = "button"; remove.dataset.action = "delete-target"; remove.dataset.targetId = target.id;
    actions.append(primary, remove); card.append(actions); root.append(card);
  }
}

function refreshViews() {
  renderDomains();
  renderOverview();
  renderReport();
}

async function refresh() {
  if (state.refreshing) return;
  state.refreshing = true;
  try {
    const [targets, jobs] = await Promise.all([api("/api/targets"), api("/api/jobs")]);
    state.targets = Array.isArray(targets) ? targets : [];
    state.jobs = Array.isArray(jobs) ? jobs : [];
    if (!jobByID(state.selectedReportJobID)) state.selectedReportJobID = sortedJobs()[0]?.id || "";
    refreshViews();
    byID("apiState").textContent = "Локально · подключено";
  } catch (error) {
    byID("apiState").textContent = "Нет связи с API";
    showNotice(`Не удалось загрузить локальные данные: ${error.message}`, true);
  } finally { state.refreshing = false; }
}

function openModal(step = 1, target = null) {
  state.modalStep = step;
  state.modalTarget = target;
  state.modalMethod = "dns";
  renderModal();
  byID("overlay").classList.add("show");
  setTimeout(() => $("#domainInput")?.focus(), 25);
}

function closeModal() {
  byID("overlay").classList.remove("show");
  byID("modal").replaceChildren();
  state.modalStep = 0;
  state.modalTarget = null;
}

function modalFrame(title, body) {
  const step = state.modalStep;
  byID("modal").innerHTML = `<div class="modal-head"><div><small>Новый сайт · шаг ${step} из 3</small><h2 id="modalTitle">${escapeHTML(title)}</h2></div><button class="close" data-action="close" aria-label="Закрыть">×</button></div><div class="steps"><span class="done"></span><span class="${step > 1 ? "done" : ""}"></span><span class="${step > 2 ? "done" : ""}"></span></div>${body}`;
}

function renderModal(errorMessage = "") {
  const step = state.modalStep;
  if (step === 1) {
    modalFrame("Добавьте свой сайт", `<label class="field-label" for="domainInput">Адрес сайта</label><input class="input" id="domainInput" type="text" inputmode="url" placeholder="например, mysite.ru" autocomplete="off"><div class="hint">Укажите домен, которым вы владеете или управляете. Будет создана уникальная DNS TXT-проверка.</div><div class="error" id="modalError" aria-live="polite">${escapeHTML(errorMessage)}</div><div class="modal-actions"><span class="hint">Шаг 1 из 3</span><button class="primary" data-action="next-domain">Продолжить →</button></div>`);
    return;
  }
  if (step === 2 && state.modalTarget) {
    const target = state.modalTarget;
    const method = state.modalMethod;
    const instruction = method === "dns" ? "Добавьте эту TXT-запись в DNS-панели домена. После распространения записи нажмите «Проверить TXT»." : "Создайте TXT-запись у DNS-провайдера. В этой версии доступно только подтверждение DNS; загрузка файла не поддерживается.";
    modalFrame("Подтвердите домен", `<p>Чтобы запретить проверку чужих сайтов, подтвердите контроль над доменом <b>${escapeHTML(target.host)}</b>.</p><div class="method-switch"><button data-method="dns" class="${method === "dns" ? "active" : ""}">DNS-запись</button><button data-method="instruction" class="${method === "instruction" ? "active" : ""}">Инструкция</button></div><p>${instruction}</p><div class="code-box"><code>${escapeHTML(target.challenge.record)} = ${escapeHTML(target.challenge.value)}</code><button data-action="copy">Копировать</button></div><label class="field-label" for="modalSubdomains">Поддомены (необязательно, по одному на строку)</label><textarea class="input" id="modalSubdomains" rows="2" placeholder="app.${escapeHTML(target.host)}&#10;api.${escapeHTML(target.host)}"></textarea><label class="field-label" for="modalPorts">Порты</label><input class="input" id="modalPorts" value="${escapeHTML((target.ports || [80, 443]).join(", "))}" inputmode="numeric"><div class="hint">Только явно перечисленные имена и разрешённые порты. Поддомены не обнаруживаются автоматически.</div><div class="error" id="modalError" aria-live="polite">${escapeHTML(errorMessage)}</div><div class="modal-actions"><button class="subtle" data-action="close">Закрыть</button><button class="primary" data-action="verify-target">Проверить TXT →</button></div>`);
    return;
  }
  if (step === 3 && state.modalTarget) {
    const target = state.modalTarget;
    modalFrame("Сайт подтверждён", `<div class="success-icon">✓</div><p>Контроль DNS для <b>${escapeHTML(target.host)}</b> подтверждён. Область зафиксирована: ${(target.scope_hosts || []).map(escapeHTML).join(", ")}; порты ${(target.ports || []).join(", ")}.</p><div class="incomplete">TXT подтверждает контроль над DNS, но не право на тестирование.</div><label class="field-label" for="modalAuthorizationNote">Примечание к письменному разрешению</label><input class="input" id="modalAuthorizationNote" placeholder="Например, разрешение владельца от 18.11.2026"><label class="attestation"><input id="modalAuthorized" type="checkbox"><span>Подтверждаю, что у меня есть <strong>письменное разрешение</strong> на проверку выбранных целей.</span></label><div class="error" id="modalError" aria-live="polite">${escapeHTML(errorMessage)}</div><div class="modal-actions"><button class="subtle" data-action="close">Позже</button><button id="modalStartScan" class="primary" data-action="start-scan" disabled>Запустить проверку →</button></div>`);
    return;
  }
  closeModal();
}

function parsePorts(value) {
  const ports = value.split(/[\s,;]+/).filter(Boolean).map(Number);
  if (!ports.length || ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) throw new Error("Укажите порты числами от 1 до 65535.");
  return [...new Set(ports)];
}

async function createTarget() {
  const host = $("#domainInput")?.value.trim();
  if (!host) { renderModal("Введите домен."); return; }
  try {
    state.modalTarget = await api("/api/targets/challenge", { method: "POST", body: JSON.stringify({ host }) });
    await refresh();
    state.modalStep = 2;
    renderModal();
  } catch (error) { renderModal(error.message); }
}

async function verifyTarget() {
  const target = state.modalTarget;
  if (!target) return;
  const subdomains = $("#modalSubdomains").value.split(/[\n,;]+/).map((host) => host.trim()).filter(Boolean);
  try {
    const verified = await api("/api/targets/verify", { method: "POST", body: JSON.stringify({ target_id: target.id, subdomains, ports: parsePorts($("#modalPorts").value) }) });
    state.modalTarget = verified;
    await refresh();
    state.modalStep = 3;
    renderModal();
  } catch (error) { renderModal(error.message); }
}

function updateLaunchAvailability() {
  const button = byID("modalStartScan");
  if (button) button.disabled = !byID("modalAuthorized")?.checked || !byID("modalAuthorizationNote")?.value.trim();
}

async function launchScan(target = state.modalTarget) {
  if (!target?.verified || !byID("modalAuthorized")?.checked) return;
  const authorization = byID("modalAuthorizationNote").value.trim();
  if (!authorization) return;
  try {
    const job = await api("/api/jobs", { method: "POST", body: JSON.stringify({ target_id: target.id, hosts: target.scope_hosts, ports: target.ports, authorized: true, authorization }) });
    state.selectedReportJobID = job.id;
    await refresh();
    closeModal();
    showPage("report");
    showNotice(`Задача ${job.id.slice(0, 8)} добавлена в очередь.`);
  } catch (error) { renderModal(error.message); }
}

function openReport(jobID = "") {
  state.selectedReportJobID = jobID || sortedJobs()[0]?.id || "";
  renderReport();
  showPage("report");
}

async function runDemo() {
  try {
    const job = await api("/api/demo", { method: "POST", body: "{}" });
    state.selectedReportJobID = job.id;
    await refresh();
    openReport(job.id);
    showNotice(`Демо-отчёт сохранён как имитация. Сетевых проверок не было.`);
  } catch (error) { showNotice(error.message, true); }
}

async function deleteTarget(id) {
  const target = targetByID(id);
  if (!target || !window.confirm(`Удалить ${target.host} и связанную историю с этого компьютера?`)) return;
  try { await api(`/api/targets/${encodeURIComponent(id)}`, { method: "DELETE" }); await refresh(); showNotice("Домен и связанные данные удалены."); }
  catch (error) { showNotice(error.message, true); }
}

async function deleteJob(id) {
  try { await api(`/api/jobs/${encodeURIComponent(id)}`, { method: "DELETE" }); await refresh(); showNotice("Задача удалена из истории."); }
  catch (error) { showNotice(error.message, true); }
}

async function cancelJob(id) {
  try { await api(`/api/jobs/${encodeURIComponent(id)}/cancel`, { method: "POST", body: "{}" }); await refresh(); showNotice("Отмена задачи запрошена."); }
  catch (error) { showNotice(error.message, true); }
}

async function retryReport() {
  const job = jobByID(state.selectedReportJobID) || sortedJobs()[0];
  const target = job ? targetByID(job.target_id) : state.targets.find((item) => item.verified);
  if (!target?.verified) { showPage("domains"); showNotice("Добавьте и подтвердите домен перед запуском проверки.", true); return; }
  openModal(3, target);
}

document.addEventListener("click", async (event) => {
  const pageButton = event.target.closest("[data-page]");
  if (pageButton) {
    event.preventDefault();
    if (pageButton.dataset.page === "report") openReport(); else showPage(pageButton.dataset.page);
    return;
  }
  const filter = event.target.closest("[data-filter]");
  if (filter) {
    state.filter = filter.dataset.filter;
    for (const button of document.querySelectorAll(".filters button")) button.classList.toggle("selected", button === filter);
    renderFindings(jobByID(state.selectedReportJobID));
    return;
  }
  const method = event.target.closest("[data-method]");
  if (method) { state.modalMethod = method.dataset.method; renderModal(); return; }
  const action = event.target.closest("[data-action]");
  if (!action) return;
  switch (action.dataset.action) {
    case "add": openModal(1); break;
    case "close": closeModal(); break;
    case "next-domain": await createTarget(); break;
    case "verify-target":
      if (state.modalStep === 2) await verifyTarget();
      else { const target = targetByID(action.dataset.targetId); if (target) openModal(2, target); }
      break;
    case "scan-target": { const target = targetByID(action.dataset.targetId); if (target) openModal(3, target); break; }
    case "start-scan": await launchScan(); break;
    case "retry": await retryReport(); break;
    case "run-demo": await runDemo(); break;
    case "open-report": openReport(action.dataset.jobId); break;
    case "delete-target": await deleteTarget(action.dataset.targetId); break;
    case "delete-job": await deleteJob(action.dataset.jobId); break;
    case "cancel-job": await cancelJob(action.dataset.jobId); break;
    case "copy":
      try { await navigator.clipboard.writeText(`${state.modalTarget.challenge.record} ${state.modalTarget.challenge.value}`); showNotice("TXT-запись скопирована."); }
      catch (_) { showNotice("Не удалось скопировать; выделите запись и скопируйте вручную.", true); }
      break;
    case "toggle-finding": {
      const card = action.closest(".finding");
      card.classList.toggle("open");
      action.setAttribute("aria-expanded", card.classList.contains("open") ? "true" : "false");
      break;
    }
  }
});

document.addEventListener("input", (event) => {
  if (event.target.id === "modalAuthorizationNote") updateLaunchAvailability();
});
document.addEventListener("change", (event) => {
  if (event.target.id === "modalAuthorized") updateLaunchAvailability();
});
byID("overlay").addEventListener("click", (event) => { if (event.target.id === "overlay") closeModal(); });
document.addEventListener("keydown", (event) => { if (event.key === "Escape" && byID("overlay").classList.contains("show")) closeModal(); });
byID("topDate").textContent = new Intl.DateTimeFormat("ru-RU", { dateStyle: "long" }).format(new Date());
refresh();
window.setInterval(refresh, 2500);
