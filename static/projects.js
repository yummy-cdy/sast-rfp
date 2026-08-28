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
    alert("프로젝트명을 입력하세요.");
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
    alert(data.detail || "프로젝트 생성에 실패했습니다.");
  }
});

async function loadProjects() {
  const res = await apiFetch("/api/projects");
  const projects = await res.json();

  if (projects.length === 0) {
    tableBody.innerHTML =
      '<tr><td colspan="5" class="text-center py-6 text-gray-500">조회 가능한 프로젝트가 없습니다.</td></tr>';
    return;
  }

  tableBody.innerHTML = projects
    .map(
      (p) => `
      <tr class="hover:bg-gray-50 cursor-pointer" onclick="location.href='/static/project_detail.html?id=${p.project_id}'">
        <td class="py-2 px-4 border-b">${p.project_id}</td>
        <td class="py-2 px-4 border-b font-semibold text-blue-600">${escapeHtml(p.name)}</td>
        <td class="py-2 px-4 border-b">${escapeHtml(p.target_language)}</td>
        <td class="py-2 px-4 border-b text-gray-600">${escapeHtml(p.description || "")}</td>
        <td class="py-2 px-4 border-b text-gray-500 text-sm">${p.created_at?.slice(0, 10) || ""}</td>
      </tr>`
    )
    .join("");
}

loadProjects();
