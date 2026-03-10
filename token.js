const CONFIG = {
  oauthStart: "https://your-worker.example/oauth/start",
  tokenEndpoint: "https://your-worker.example/token"
};

const loginButton = document.getElementById("login-button");
const logoutButton = document.getElementById("logout-button");
const tokenValue = document.getElementById("token-value");
const tokenMeta = document.getElementById("token-meta");
const userMeta = document.getElementById("user-meta");

let refreshTimer = null;

function setMeta(text) {
  tokenMeta.textContent = text;
}

function setUser(text) {
  userMeta.textContent = text || "";
}

function setSignedIn(state, login) {
  loginButton.hidden = state;
  logoutButton.hidden = !state;
  setUser(state && login ? `Signed in as ${login}` : "");
}

function getSession() {
  return sessionStorage.getItem("stormed_session") || "";
}

function setSession(session) {
  sessionStorage.setItem("stormed_session", session);
}

function clearSession() {
  sessionStorage.removeItem("stormed_session");
}

function pullSessionFromHash() {
  if (!window.location.hash) {
    return;
  }

  const hash = window.location.hash.slice(1);
  const params = new URLSearchParams(hash);
  const session = params.get("session");

  if (session) {
    setSession(session);
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

function scheduleRefresh(expiresIn) {
  clearTimeout(refreshTimer);
  if (!expiresIn || Number.isNaN(expiresIn)) {
    return;
  }
  const next = Math.max(5, expiresIn - 2) * 1000;
  refreshTimer = setTimeout(fetchToken, next);
}

async function fetchToken() {
  const session = getSession();
  if (!session) {
    setSignedIn(false);
    return;
  }

  setMeta("Checking...");

  try {
    const response = await fetch(CONFIG.tokenEndpoint, {
      headers: {
        Authorization: `Bearer ${session}`
      }
    });

    if (!response.ok) {
      clearSession();
      tokenValue.textContent = "Sign in to view";
      setSignedIn(false);
      setMeta("Access denied.");
      return;
    }

    const data = await response.json();
    tokenValue.textContent = data.token || "Unavailable";

    const expiresIn = Number(data.expires_in || 0);
    setMeta(expiresIn ? `Expires in ${expiresIn}s` : "Token ready");
    setSignedIn(true, data.login);
    scheduleRefresh(expiresIn);
  } catch (error) {
    setMeta("Network error.");
  }
}

function handleLogin() {
  if (CONFIG.oauthStart.includes("your-worker")) {
    setMeta("Set your OAuth start URL in token.js");
    return;
  }
  window.location.href = CONFIG.oauthStart;
}

function handleLogout() {
  clearSession();
  tokenValue.textContent = "Sign in to view";
  setMeta("Signed out.");
  setSignedIn(false);
}

function init() {
  loginButton.addEventListener("click", handleLogin);
  logoutButton.addEventListener("click", handleLogout);

  if (CONFIG.tokenEndpoint.includes("your-worker")) {
    setMeta("Set your token endpoint in token.js");
  }

  pullSessionFromHash();
  fetchToken();
}

window.addEventListener("load", init);
