requireLogin();
renderNav("criteria");

const categoryFilter = document.getElementById("categoryFilter");
const statusFilter = document.getElementById("statusFilter");

async function loadCriteria() {
  const params = new URLSearchParams();
  if (categoryFilter.value) params.set("category", categoryFilter.value);
  if (statusFilter.value) params.set("implementation_status", statusFilter.value);

  const res = await apiFetch(`/api/criteria?${params.toString()}`);
  const items = await res.json();

  if (categoryFilter.options.length === 0) {
    const categories = [...new Set(items.map((i) => i.category))];
    categoryFilter.innerHTML =
      '<option value="">전체 분류</option>' +
      categories.map((c) => `<option value="${c}">${c}</option>`).join("");
  }

  const implementedCount = items.filter((i) => i.implementation_status === "IMPLEMENTED").length;
  document.getElementById("summaryLine").textContent = `총 ${items.length}개 항목 중 ${implementedCount}개 구현됨`;

  const rows = items
    .map(
      (i) => `
    <tr>
      <td class="sast-text-faint">${escapeHtml(i.item_number)}</td>
      <td class="sast-mono sast-text-faint">${escapeHtml(i.criteria_id)}</td>
      <td class="font-semibold">${escapeHtml(i.name)}</td>
      <td class="sast-text-muted">${escapeHtml(i.category)}</td>
      <td class="text-center"><span class="${severityBadgeClass(i.default_severity)}">${i.default_severity}</span></td>
      <td class="text-center">
        ${
          i.implementation_status === "IMPLEMENTED"
            ? '<span class="sast-badge sast-badge-green">구현됨</span>'
            : '<span class="sast-badge sast-badge-slate">계획됨</span>'
        }
      </td>
    </tr>`
    )
    .join("");

  document.getElementById("criteriaTableBody").innerHTML =
    rows || `<tr><td colspan="6">${emptyStateHtml("조건에 맞는 진단 기준이 없습니다.")}</td></tr>`;
}

categoryFilter.addEventListener("change", loadCriteria);
statusFilter.addEventListener("change", loadCriteria);
loadCriteria();
