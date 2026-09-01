requireLogin();
renderNav("criteria");

const categoryFilter = document.getElementById("categoryFilter");
const statusFilter = document.getElementById("statusFilter");

function renderCategoryProgress(allItems) {
  const order = [];
  const byCategory = new Map();
  for (const item of allItems) {
    if (!byCategory.has(item.category)) {
      byCategory.set(item.category, { total: 0, implemented: 0 });
      order.push(item.category);
    }
    const bucket = byCategory.get(item.category);
    bucket.total += 1;
    if (item.implementation_status === "IMPLEMENTED") bucket.implemented += 1;
  }

  document.getElementById("categoryProgress").innerHTML = order
    .map((category) => {
      const { total, implemented } = byCategory.get(category);
      const pct = total ? Math.round((implemented / total) * 100) : 0;
      return `
      <div class="sast-meter-row" title="${escapeHtml(category)}: ${implemented}/${total} 구현">
        <div class="sast-meter-label">${escapeHtml(category)}</div>
        <div class="sast-meter-track"><div class="sast-meter-fill" style="width:${pct}%"></div></div>
        <div class="sast-meter-value">${implemented}/${total}</div>
      </div>`;
    })
    .join("");
}

async function loadAllCriteriaOnce() {
  const res = await apiFetch("/api/criteria");
  const allItems = await res.json();

  const categories = [...new Set(allItems.map((i) => i.category))];
  categoryFilter.innerHTML =
    '<option value="">전체 분류</option>' +
    categories.map((c) => `<option value="${c}">${c}</option>`).join("");

  renderCategoryProgress(allItems);
}

async function loadCriteria() {
  const params = new URLSearchParams();
  if (categoryFilter.value) params.set("category", categoryFilter.value);
  if (statusFilter.value) params.set("implementation_status", statusFilter.value);

  const res = await apiFetch(`/api/criteria?${params.toString()}`);
  const items = await res.json();

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
loadAllCriteriaOnce();
loadCriteria();
