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

  document.getElementById("criteriaTableBody").innerHTML = items
    .map(
      (i) => `
    <tr class="hover:bg-gray-50">
      <td class="py-2 px-3 border-b text-gray-500">${escapeHtml(i.item_number)}</td>
      <td class="py-2 px-3 border-b font-mono text-xs">${escapeHtml(i.criteria_id)}</td>
      <td class="py-2 px-3 border-b font-semibold">${escapeHtml(i.name)}</td>
      <td class="py-2 px-3 border-b">${escapeHtml(i.category)}</td>
      <td class="py-2 px-3 border-b text-center"><span class="px-2 py-0.5 rounded text-xs font-bold ${severityBadgeClass(i.default_severity)}">${i.default_severity}</span></td>
      <td class="py-2 px-3 border-b text-center">
        ${
          i.implementation_status === "IMPLEMENTED"
            ? '<span class="text-green-700 font-bold">구현됨</span>'
            : '<span class="text-gray-400">계획됨</span>'
        }
      </td>
    </tr>`
    )
    .join("");
}

categoryFilter.addEventListener("change", loadCriteria);
statusFilter.addEventListener("change", loadCriteria);
loadCriteria();
