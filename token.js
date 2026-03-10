const CONFIG = {
  loginEndpoint: "https://your-worker.example/auth/login",
  tokenEndpoint: "https://your-worker.example/token"
};

const form = document.getElementById("auth-form");
const usernameInput = document.getElementById("auth-username");
const passwordInput = document.getElementById("auth-password");
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
  usernameInput.disabled = state;
  passwordInput.disabled = state;
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
    setSignedIn(true, data.login || usernameInput.value.trim());
    scheduleRefresh(expiresIn);
  } catch (error) {
    setMeta("Network error.");
  }
}

async function handleLogin(event) {
  event.preventDefault();

  if (CONFIG.loginEndpoint.includes("your-worker")) {
    setMeta("Set your login endpoint in token.js");
    return;
  }

  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    setMeta("Enter username and password.");
    return;
  }

  loginButton.disabled = true;
  setMeta("Signing in...");

  try {
    const response = await fetch(CONFIG.loginEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({ username, password })
    });

    if (!response.ok) {
      setMeta("Invalid credentials.");
      loginButton.disabled = false;
      return;
    }

    const data = await response.json();
    if (!data.session) {
      setMeta("Login failed.");
      loginButton.disabled = false;
      return;
    }

    setSession(data.session);
    passwordInput.value = "";
    setSignedIn(true, data.login || username);
    loginButton.disabled = false;
    fetchToken();
  } catch (error) {
    setMeta("Network error.");
    loginButton.disabled = false;
  }
}

function handleLogout() {
  clearSession();
  tokenValue.textContent = "Sign in to view";
  setMeta("Signed out.");
  setSignedIn(false);
}

function init() {
  form.addEventListener("submit", handleLogin);
  logoutButton.addEventListener("click", handleLogout);

  if (CONFIG.tokenEndpoint.includes("your-worker")) {
    setMeta("Set your token endpoint in token.js");
  }

  fetchToken();
}

window.addEventListener("load", init);
