requireLogin();
renderNav("users");

if (!isAdmin()) {
  document.body.innerHTML =
    '<div class="min-h-screen flex items-center justify-center"><div class="sast-card text-red-600 text-sm">관리자만 접근할 수 있습니다.</div></div>';
  throw new Error("forbidden");
}

async function loadUsers() {
  const res = await apiFetch("/api/users");
  const users = await res.json();
  const rows = users
    .map(
      (u) => `
    <tr>
      <td class="font-semibold">${escapeHtml(u.user_id)}</td>
      <td><span class="${roleBadgeClass(u.role)}">${u.role === "ADMIN" ? "시스템 관리자" : "일반 사용자"}</span></td>
      <td><span class="sast-badge ${u.is_active ? "sast-badge-green" : "sast-badge-slate"}">${u.is_active ? "활성" : "비활성"}</span></td>
    </tr>`
    )
    .join("");
  document.getElementById("userTableBody").innerHTML =
    rows || `<tr><td colspan="3">${emptyStateHtml("등록된 사용자가 없습니다.")}</td></tr>`;
}

document.getElementById("createUserBtn").addEventListener("click", async () => {
  const user_id = document.getElementById("newUserId").value.trim();
  const password = document.getElementById("newUserPassword").value;
  const role = document.getElementById("newUserRole").value;
  const msgEl = document.getElementById("createUserMessage");
  msgEl.textContent = "";

  const res = await apiFetch("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id, password, role }),
  });

  if (res.ok) {
    document.getElementById("newUserId").value = "";
    document.getElementById("newUserPassword").value = "";
    loadUsers();
  } else {
    const data = await res.json();
    msgEl.textContent = typeof data.detail === "string" ? data.detail : "생성에 실패했습니다.";
  }
});

loadUsers();
