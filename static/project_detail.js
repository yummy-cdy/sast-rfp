requireLogin();
renderNav("projects");

const params = new URLSearchParams(location.search);
const projectId = params.get("id");
if (!projectId) location.href = "/static/projects.html";

const statusMessage = document.getElementById("statusMessage");

async function loadProject() {
  const res = await apiFetch(`/api/projects/${projectId}`);
  if (!res.ok) {
    document.getElementById("projectTitle").textContent = "프로젝트를 찾을 수 없거나 접근 권한이 없습니다.";
    return;
  }
  const p = await res.json();
  document.getElementById("projectTitle").textContent = p.name;
  document.getElementById("projectMeta").textContent =
    `언어: ${p.target_language} | 소스 상태: ${p.source_type} | 설명: ${p.description || "-"}`;

  if (isAdmin()) {
    document.getElementById("adminPanel").classList.remove("hidden");
    document.getElementById("permissionPanel").classList.remove("hidden");
    loadPermissionPanel();
  }
}

// --- 업로드 / 분석 실행 (관리자 전용) ---
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const analyzeBtn = document.getElementById("analyzeBtn");

if (dropzone) {
  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("is-dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("is-dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("is-dragover");
    if (e.dataTransfer.files.length) handleUpload(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) handleUpload(fileInput.files[0]);
  });
}

async function handleUpload(file) {
  if (!file.name.endsWith(".zip")) {
    showToast("ZIP 압축 파일만 허용됩니다.", "error");
    return;
  }
  const formData = new FormData();
  formData.append("file", file);
  statusMessage.textContent = "소스코드 업로드 중...";

  const res = await apiFetch(`/api/projects/${projectId}/source`, { method: "POST", body: formData });
  const data = await res.json();
  statusMessage.textContent = res.ok ? `업로드 완료: ${data.source_path}` : `업로드 실패: ${data.detail}`;
}

if (analyzeBtn) {
  analyzeBtn.addEventListener("click", async () => {
    statusMessage.textContent = "분석 엔진 실행 중...";
    const res = await apiFetch(`/api/projects/${projectId}/analyze`, { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      statusMessage.textContent = `분석 완료 (발견된 항목: ${data.findings_count}건)`;
      loadExecutions();
      loadResults();
    } else {
      statusMessage.textContent = `분석 실패: ${data.detail}`;
    }
  });
}

// --- 분석 이력 (SFR-016) ---
async function loadExecutions() {
  const res = await apiFetch(`/api/projects/${projectId}/executions`);
  const executions = await res.json();
  const tbody = document.getElementById("executionTableBody");

  if (!res.ok || executions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7">${emptyStateHtml("분석 이력이 없습니다.")}</td></tr>`;
    return;
  }

  const statusLabel = { WAIT: "대기", PROG: "진행중", COMP: "완료", FAIL: "실패" };
  tbody.innerHTML = executions
    .map(
      (e) => `
    <tr>
      <td class="sast-mono sast-text-faint">${e.execution_id}</td>
      <td><span class="${statusBadgeClass(e.status)}">${statusLabel[e.status] || e.status}</span></td>
      <td>${escapeHtml(e.executed_by || "")}</td>
      <td class="sast-text-faint">${e.start_time?.replace("T", " ").slice(0, 19) || "-"}</td>
      <td class="sast-text-faint">${e.end_time?.replace("T", " ").slice(0, 19) || "-"}</td>
      <td>${e.summary?.findings_count ?? "-"}</td>
      <td class="text-red-600">${escapeHtml(e.error_info || "")}</td>
    </tr>`
    )
    .join("");
}

// --- 최신 결과 + 필터 (SFR-017) ---
const SEVERITY_STAT_SPEC = [
  { key: "High", color: "var(--sast-danger)", track: "#fee2e2" },
  { key: "Medium", color: "#d97706", track: "#fef3c7" },
  { key: "Low", color: "#64748b", track: "#e2e8f0" },
];

function renderSeveritySummary(results) {
  const summaryEl = document.getElementById("severitySummary");
  const total = results.length;
  if (total === 0) {
    summaryEl.innerHTML = "";
    return;
  }
  const counts = { High: 0, Medium: 0, Low: 0 };
  for (const r of results) {
    if (counts[r.severity] !== undefined) counts[r.severity]++;
  }
  summaryEl.innerHTML = SEVERITY_STAT_SPEC.map((spec) => {
    const count = counts[spec.key];
    const pct = Math.round((count / total) * 100);
    return `
    <div class="sast-stat" title="전체 ${total}건 중 ${spec.key} ${count}건 (${pct}%)">
      <div class="sast-stat-head">
        <span class="sast-stat-dot" style="background:${spec.color}"></span>
        <span class="sast-stat-label">${spec.key}</span>
      </div>
      <div class="sast-stat-value">${count}</div>
      <div class="sast-stat-bar-track" style="background:${spec.track}">
        <div class="sast-stat-bar-fill" style="width:${pct}%;background:${spec.color}"></div>
      </div>
    </div>`;
  }).join("");
}

async function loadResults() {
  const res = await apiFetch(`/api/projects/${projectId}/results`);
  const allResults = await res.json();
  const tbody = document.getElementById("resultTableBody");
  const summaryEl = document.getElementById("severitySummary");

  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml("결과를 불러오지 못했습니다.")}</td></tr>`;
    summaryEl.innerHTML = "";
    return;
  }

  renderSeveritySummary(allResults);

  const severity = document.getElementById("severityFilter").value;
  const results = severity ? allResults.filter((r) => r.severity === severity) : allResults;

  if (results.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml("발견된 항목이 없습니다.", "분석을 실행하거나 필터 조건을 변경해보세요.")}</td></tr>`;
    return;
  }

  tbody.innerHTML = results
    .map(
      (r) => `
    <tr>
      <td>${escapeHtml(r.criteria_name)} <span class="sast-text-faint sast-mono">(${r.criteria_id})</span></td>
      <td class="text-center"><span class="${severityBadgeClass(r.severity)}">${r.severity}</span></td>
      <td class="truncate max-w-xs" title="${escapeHtml(r.file_path)}">${escapeHtml(r.file_path.split("\\\\").pop().split("/").pop())}</td>
      <td class="truncate max-w-sm sast-mono" title="${escapeHtml(r.evidence)}">${escapeHtml(r.evidence)}</td>
      <td class="sast-text-muted">${escapeHtml(r.recommendation || "")}</td>
    </tr>`
    )
    .join("");
}

document.getElementById("severityFilter").addEventListener("change", loadResults);

// --- 권한 관리 (관리자 전용, SFR-005) ---
async function loadPermissionPanel() {
  const [usersRes, permsRes] = await Promise.all([
    apiFetch("/api/users"),
    apiFetch(`/api/projects/${projectId}/permissions`),
  ]);
  const users = await usersRes.json();
  const grantedIds = await permsRes.json();

  const select = document.getElementById("userSelect");
  select.innerHTML = users.map((u) => `<option value="${u.user_id}">${u.user_id} (${u.role})</option>`).join("");

  renderPermissionList(grantedIds);
}

function renderPermissionList(grantedIds) {
  const list = document.getElementById("permissionList");
  if (grantedIds.length === 0) {
    list.innerHTML = '<li class="text-gray-500">부여된 권한이 없습니다.</li>';
    return;
  }
  list.innerHTML = grantedIds
    .map(
      (uid) => `
    <li class="flex items-center justify-between border-b py-1">
      <span>${escapeHtml(uid)}</span>
      <button class="text-red-600 text-xs hover:underline" onclick="revokePermission('${uid}')">해제</button>
    </li>`
    )
    .join("");
}

document.getElementById("grantBtn")?.addEventListener("click", async () => {
  const userId = document.getElementById("userSelect").value;
  if (!userId) return;
  await apiFetch(`/api/projects/${projectId}/permissions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userId }),
  });
  loadPermissionPanel();
});

async function revokePermission(userId) {
  await apiFetch(`/api/projects/${projectId}/permissions/${encodeURIComponent(userId)}`, { method: "DELETE" });
  loadPermissionPanel();
}

loadProject();
loadExecutions();
loadResults();
