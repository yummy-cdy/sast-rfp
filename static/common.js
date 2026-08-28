// SFR-001/002: 인증 토큰 저장 및 전송 공통 유틸리티
const TOKEN_KEY = "sast_access_token";
const ROLE_KEY = "sast_role";
const USER_KEY = "sast_user_id";

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function getRole() {
  return localStorage.getItem(ROLE_KEY);
}

function getUserId() {
  return localStorage.getItem(USER_KEY);
}

function isAdmin() {
  return getRole() === "ADMIN";
}

function saveSession(token, role, userId) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(ROLE_KEY, role);
  localStorage.setItem(USER_KEY, userId);
}

function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
  localStorage.removeItem(USER_KEY);
}

function requireLogin() {
  if (!getToken()) {
    window.location.href = "/static/login.html";
  }
}

// 인증 헤더를 자동으로 첨부하고, 401 발생 시 로그인 화면으로 이동시키는 fetch 래퍼
async function apiFetch(path, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    clearSession();
    window.location.href = "/static/login.html";
    throw new Error("인증이 필요합니다.");
  }
  return res;
}

function logout() {
  clearSession();
  window.location.href = "/static/login.html";
}

function renderNav(activeItem) {
  const nav = document.getElementById("nav");
  if (!nav) return;

  const items = [
    { key: "projects", label: "프로젝트", href: "/static/projects.html" },
    { key: "criteria", label: "진단 기준 카탈로그", href: "/static/criteria.html" },
  ];
  if (isAdmin()) {
    items.push({ key: "users", label: "사용자 관리", href: "/static/admin_users.html" });
  }

  nav.innerHTML = `
    <div class="flex items-center justify-between bg-white border-b px-6 py-3 mb-6">
      <div class="flex items-center gap-6">
        <span class="font-bold text-lg">SAST 프로그램</span>
        ${items
          .map(
            (item) => `
          <a href="${item.href}" class="text-sm ${
              item.key === activeItem ? "font-bold text-blue-600" : "text-gray-600 hover:text-blue-600"
            }">${item.label}</a>`
          )
          .join("")}
      </div>
      <div class="flex items-center gap-4 text-sm text-gray-600">
        <span>${getUserId() || ""} (${getRole() || ""})</span>
        <button onclick="logout()" class="text-red-600 hover:underline">로그아웃</button>
      </div>
    </div>
  `;
}

function severityBadgeClass(severity) {
  if (severity === "High") return "bg-red-100 text-red-700";
  if (severity === "Medium") return "bg-yellow-100 text-yellow-700";
  return "bg-gray-100 text-gray-700";
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text ?? "";
  return div.innerHTML;
}
