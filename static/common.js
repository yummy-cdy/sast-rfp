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

const SAST_ICONS = {
  shield:
    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9 8 11 4.6-2 8-6 8-11V5l-8-3Z"/></svg>',
  folder:
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg>',
  clipboard:
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="2" width="8" height="4" rx="1"/><path d="M9 4H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-3"/><path d="M9 11h6M9 15h6M9 19h4"/></svg>',
  users:
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
  logout:
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></svg>',
  inbox:
    '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/></svg>',
};

function renderNav(activeItem) {
  const nav = document.getElementById("nav");
  if (!nav) return;

  const items = [
    { key: "projects", label: "프로젝트", href: "/static/projects.html", icon: SAST_ICONS.folder },
    { key: "criteria", label: "진단 기준 카탈로그", href: "/static/criteria.html", icon: SAST_ICONS.clipboard },
  ];
  if (isAdmin()) {
    items.push({ key: "users", label: "사용자 관리", href: "/static/admin_users.html", icon: SAST_ICONS.users });
  }

  nav.outerHTML = `
    <aside class="sast-sidebar" id="nav">
      <div class="sast-brand">
        ${SAST_ICONS.shield}
        <span>SAST 플랫폼</span>
      </div>
      <nav class="sast-nav">
        ${items
          .map(
            (item) => `
          <a href="${item.href}" class="sast-nav-item ${item.key === activeItem ? "active" : ""}">
            ${item.icon}<span>${item.label}</span>
          </a>`
          )
          .join("")}
      </nav>
      <div class="sast-sidebar-footer">
        <div class="sast-user-chip">
          <span class="name">${escapeHtml(getUserId() || "")}</span>
          <span class="role">${getRole() === "ADMIN" ? "시스템 관리자" : "일반 사용자"}</span>
        </div>
        <button onclick="logout()" class="sast-logout-btn" title="로그아웃">${SAST_ICONS.logout}</button>
      </div>
    </aside>
  `;
}

function severityBadgeClass(severity) {
  if (severity === "High") return "sast-badge sast-badge-red";
  if (severity === "Medium") return "sast-badge sast-badge-amber";
  return "sast-badge sast-badge-slate";
}

function statusBadgeClass(status) {
  if (status === "COMP") return "sast-badge sast-badge-green";
  if (status === "FAIL") return "sast-badge sast-badge-red";
  if (status === "PROG") return "sast-badge sast-badge-blue";
  return "sast-badge sast-badge-slate";
}

function roleBadgeClass(role) {
  return role === "ADMIN" ? "sast-badge sast-badge-purple" : "sast-badge sast-badge-slate";
}

function emptyStateHtml(title, hint) {
  return `
    <div class="sast-empty">
      ${SAST_ICONS.inbox}
      <div class="title">${escapeHtml(title)}</div>
      ${hint ? `<div class="hint">${escapeHtml(hint)}</div>` : ""}
    </div>
  `;
}

function showToast(message, type = "info") {
  let stack = document.querySelector(".sast-toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.className = "sast-toast-stack";
    document.body.appendChild(stack);
  }
  const toast = document.createElement("div");
  toast.className = `sast-toast ${type}`;
  toast.textContent = message;
  stack.appendChild(toast);
  setTimeout(() => toast.remove(), 3200);
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text ?? "";
  return div.innerHTML;
}
