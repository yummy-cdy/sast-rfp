if (getToken()) {
  window.location.href = "/static/projects.html";
}

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const userId = document.getElementById("userId").value;
  const password = document.getElementById("password").value;
  const errorEl = document.getElementById("errorMessage");
  errorEl.textContent = "";

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: userId, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.detail || "로그인에 실패했습니다.";
      return;
    }

    const meRes = await fetch("/api/auth/me", {
      headers: { Authorization: `Bearer ${data.access_token}` },
    });
    const me = await meRes.json();

    saveSession(data.access_token, me.role, me.user_id);
    window.location.href = "/static/projects.html";
  } catch (err) {
    errorEl.textContent = "서버에 연결할 수 없습니다.";
  }
});
