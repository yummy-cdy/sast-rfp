requireLogin();
renderNav("users");

if (!isAdmin()) {
  document.body.innerHTML = '<p class="p-6 text-red-600">관리자만 접근할 수 있습니다.</p>';
  throw new Error("forbidden");
}

async function loadUsers() {
  const res = await apiFetch("/api/users");
  const users = await res.json();
  document.getElementById("userTableBody").innerHTML = users
    .map(
      (u) => `
    <tr class="hover:bg-gray-50">
      <td class="py-2 px-3 border-b">${escapeHtml(u.user_id)}</td>
      <td class="py-2 px-3 border-b">${escapeHtml(u.role)}</td>
      <td class="py-2 px-3 border-b">${u.is_active ? "활성" : "비활성"}</td>
    </tr>`
    )
    .join("");
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
