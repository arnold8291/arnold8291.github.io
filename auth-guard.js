/* ============================================================
 * since2027.com — Auth Guard v1
 * ------------------------------------------------------------
 * 개별 콘텐츠 페이지(lawbrief001.html 등)에 삽입하여
 * 인증 + 페이지 접근 권한을 검증한다.
 *
 * 사용법: 각 페이지의 <head> 안에 이 한 줄만 추가
 *   <script type="module" src="/auth-guard.js"></script>
 *
 * 동작:
 *   1) 페이지 본문을 즉시 숨김 (검증 전 콘텐츠 노출 방지)
 *   2) Firebase Auth 로그인 여부 확인 → 미로그인 시 / 로 리다이렉트
 *   3) allowedUsers/{email} 에서 본인 role 조회
 *   4) pageAccess/{pageId} 에서 허용된 역할 목록 조회
 *      - role 이 admin 이면 항상 통과
 *      - role 이 allowedRoles 배열에 포함되면 통과
 *      - 그 외 (등록 안된 페이지 포함) 차단
 *   5) 통과 시에만 본문 표시
 *
 * pageId 규칙:
 *   - URL 경로에서 / 와 .html 제거, / 를 _ 로 변환
 *   - 예: /bk/lawbrief001.html → bk_lawbrief001
 *        /sh/sh_recipe.html  → sh_sh_recipe
 *        /index.html         → index
 * ============================================================ */

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getAuth, onAuthStateChanged }
  from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { getFirestore, doc, getDoc }
  from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

// ── Firebase 설정 (index.html과 동일) ──────────────────────
const firebaseConfig = {
  apiKey: "AIzaSyAtodnuV2rXtJXHJb2kc0AjeLQIWbv1yzA",
  authDomain: "since2027-3fb3c.firebaseapp.com",
  projectId: "since2027-3fb3c",
  storageBucket: "since2027-3fb3c.firebasestorage.app",
  messagingSenderId: "931680118450",
  appId: "1:931680118450:web:e6c4b67cb77597f5164bab"
};

const app  = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db   = getFirestore(app);

// ── 본문 즉시 숨김 (검증 완료 전 콘텐츠 노출 방지) ───────────
const _styleTag = document.createElement('style');
_styleTag.id = '__auth_guard_style';
_styleTag.textContent = `
  html, body { visibility: hidden !important; }
  #__auth_guard_overlay {
    visibility: visible !important;
    position: fixed; inset: 0;
    background: #ffffff;
    display: flex; align-items: center; justify-content: center;
    z-index: 2147483647;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color: #8a857a; font-size: 12px; letter-spacing: 0.1em;
  }
  #__auth_guard_overlay .ag-box { text-align: center; }
  #__auth_guard_overlay .ag-spinner {
    width: 28px; height: 28px; margin: 0 auto 16px;
    border: 2px solid #e5e2db; border-top-color: #b8913a;
    border-radius: 50%; animation: ag-spin 0.8s linear infinite;
  }
  @keyframes ag-spin { to { transform: rotate(360deg); } }
  #__auth_guard_overlay.deny .ag-spinner { display: none; }
  #__auth_guard_overlay.deny .ag-msg { color: #c0392b; }
  #__auth_guard_overlay .ag-sub {
    margin-top: 12px; font-size: 10px; opacity: 0.7;
    letter-spacing: 0.15em; text-transform: uppercase;
  }
  #__auth_guard_overlay button {
    margin-top: 20px; padding: 8px 18px;
    background: #fff; border: 1px solid #e5e2db; border-radius: 8px;
    color: #1a1916; font-size: 12px; cursor: pointer;
    font-family: inherit;
  }
  #__auth_guard_overlay button:hover { border-color: #b8913a; }
`;
document.documentElement.appendChild(_styleTag);

const _overlay = document.createElement('div');
_overlay.id = '__auth_guard_overlay';
_overlay.innerHTML = `
  <div class="ag-box">
    <div class="ag-spinner"></div>
    <div class="ag-msg">확인 중</div>
    <div class="ag-sub">verifying access</div>
  </div>
`;
// body가 아직 없을 수 있으니 documentElement에 붙인다
(document.body || document.documentElement).appendChild(_overlay);
// DOM이 준비되면 body로 옮겨 z-index 우선순위 확보
document.addEventListener('DOMContentLoaded', () => {
  if (_overlay.parentNode !== document.body) {
    document.body.appendChild(_overlay);
  }
});

function _showDenied(message, allowRetry = false) {
  _overlay.classList.add('deny');
  const msgEl = _overlay.querySelector('.ag-msg');
  const subEl = _overlay.querySelector('.ag-sub');
  msgEl.textContent = message;
  subEl.textContent = 'access denied';
  if (allowRetry) {
    const box = _overlay.querySelector('.ag-box');
    if (!box.querySelector('button')) {
      const btn = document.createElement('button');
      btn.textContent = '로그인 페이지로';
      btn.onclick = () => { window.location.href = '/'; };
      box.appendChild(btn);
    }
  }
}

function _grantAccess() {
  // 검증 통과 → 본문 노출
  _styleTag.remove();
  _overlay.remove();
}

// ── pageId 산출: URL 경로 → 정규화된 식별자 ────────────────
function getPageId() {
  let path = window.location.pathname;
  // 시작 / 제거
  path = path.replace(/^\/+/, '');
  // .html 제거
  path = path.replace(/\.html$/i, '');
  // 빈 경로(루트)는 index
  if (!path || path.endsWith('/')) path += 'index';
  // / 를 _ 로 변환, 그 외 안전하지 않은 문자 제거
  path = path.replace(/\//g, '_').replace(/[^a-zA-Z0-9_\-()]/g, '');
  return path;
}

// ── 메인 검증 로직 ────────────────────────────────────────
const ACCESS_TIMEOUT_MS = 10000; // 10초 내 응답 없으면 차단
let _settled = false;

const timeoutHandle = setTimeout(() => {
  if (!_settled) {
    _settled = true;
    _showDenied('확인 시간이 초과되었습니다.', true);
  }
}, ACCESS_TIMEOUT_MS);

onAuthStateChanged(auth, async (user) => {
  if (_settled) return;

  // 1) 미로그인 → 루트로 리다이렉트 (로그인 후 돌아올 수 있게 from 파라미터 부착)
  if (!user) {
    _settled = true;
    clearTimeout(timeoutHandle);
    const from = encodeURIComponent(window.location.pathname);
    window.location.replace(`/?from=${from}`);
    return;
  }

  try {
    // 2) 본인 role 조회
    const userSnap = await getDoc(doc(db, 'allowedUsers', user.email));
    if (!userSnap.exists()) {
      _settled = true;
      clearTimeout(timeoutHandle);
      _showDenied('접근 권한이 없습니다.', true);
      return;
    }
    const role = userSnap.data().role;

    // 3) admin 은 무조건 통과
    if (role === 'admin') {
      _settled = true;
      clearTimeout(timeoutHandle);
      _grantAccess();
      return;
    }

    // 4) 페이지 권한 조회
    const pageId = getPageId();
    const pageSnap = await getDoc(doc(db, 'pageAccess', pageId));

    // 등록 안된 페이지 → 차단 (사용자 선택: "등록 안된 페이지는 모두 차단")
    if (!pageSnap.exists()) {
      _settled = true;
      clearTimeout(timeoutHandle);
      _showDenied('접근 권한이 없습니다.', true);
      return;
    }

    const allowedRoles = pageSnap.data().allowedRoles || [];
    if (allowedRoles.includes(role)) {
      _settled = true;
      clearTimeout(timeoutHandle);
      _grantAccess();
    } else {
      _settled = true;
      clearTimeout(timeoutHandle);
      _showDenied('접근 권한이 없습니다.', true);
    }
  } catch (err) {
    if (_settled) return;
    _settled = true;
    clearTimeout(timeoutHandle);
    // Firestore Rules에 의한 거부도 여기로 떨어진다 → 동일하게 차단 메시지
    _showDenied('접근 권한이 없습니다.', true);
  }
});

// 외부에서 pageId 확인이 필요한 경우 (디버깅용은 아니고 admin 페이지 통합 시)
window.__authGuard = { getPageId };
