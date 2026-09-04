requireLogin();
renderNav("projects");

const tableBody = document.getElementById("projectTableBody");
const newProjectBtn = document.getElementById("newProjectBtn");
const newProjectForm = document.getElementById("newProjectForm");

if (isAdmin()) {
  newProjectBtn.classList.remove("hidden");
}

newProjectBtn.addEventListener("click", () => newProjectForm.classList.toggle("hidden"));
document.getElementById("cancelCreateBtn").addEventListener("click", () => newProjectForm.classList.add("hidden"));

document.getElementById("createProjectBtn").addEventListener("click", async () => {
  const name = document.getElementById("projectName").value.trim();
  const description = document.getElementById("projectDescription").value.trim();
  const target_language = document.getElementById("targetLanguage").value;

  if (!name) {
    showToast("프로젝트명을 입력하세요.", "error");
    return;
  }

  const res = await apiFetch("/api/projects", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, description: description || null, target_language }),
  });

  if (res.ok) {
    newProjectForm.classList.add("hidden");
    loadProjects();
  } else {
    const data = await res.json();
    showToast(data.detail || "프로젝트 생성에 실패했습니다.", "error");
  }
});

async function loadProjects() {
  const res = await apiFetch("/api/projects");
  const projects = await res.json();

  if (projects.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="6">${emptyStateHtml(
      "조회 가능한 프로젝트가 없습니다.",
      isAdmin() ? "우측 상단의 '+ 새 프로젝트'로 시작하세요." : "관리자에게 프로젝트 접근 권한을 요청하세요."
    )}</td></tr>`;
    return;
  }

  tableBody.innerHTML = projects
    .map(
      (p) => `
      <tr class="is-clickable" onclick="location.href='/static/project_detail.html?id=${p.project_id}'">
        <td class="sast-text-faint sast-mono">${p.project_id}</td>
        <td class="font-semibold text-blue-600">${escapeHtml(p.name)}</td>
        <td>${escapeHtml(p.target_language)}</td>
        <td class="sast-text-muted">${escapeHtml(p.description || "")}</td>
        <td class="sast-text-faint">${p.created_at?.slice(0, 10) || ""}</td>
        <td class="text-right">${
          isAdmin()
            ? `<button class="text-red-600 text-xs hover:underline" onclick="event.stopPropagation(); deleteProject(${p.project_id}, '${escapeHtml(p.name).replace(/'/g, "\\'")}')">삭제</button>`
            : ""
        }</td>
      </tr>`
    )
    .join("");
}

async function deleteProject(projectId, name) {
  if (!confirm(`"${name}" 프로젝트를 삭제하시겠습니까?\n분석 이력과 결과가 모두 함께 삭제되며 되돌릴 수 없습니다.`)) {
    return;
  }
  const res = await apiFetch(`/api/projects/${projectId}`, { method: "DELETE" });
  if (res.ok) {
    showToast("프로젝트가 삭제되었습니다.", "success");
    loadProjects();
  } else {
    const data = await res.json().catch(() => ({}));
    showToast(data.detail || "프로젝트 삭제에 실패했습니다.", "error");
  }
}

loadProjects();
