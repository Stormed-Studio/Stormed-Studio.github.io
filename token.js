const CONFIG = {
  clientId: "YOUR_GOOGLE_CLIENT_ID",
  tokenEndpoint: "https://your-worker.example/token"
};

const button = document.getElementById("gsi-button");
const loginButton = document.getElementById("login-button");
const logoutButton = document.getElementById("logout-button");
const tokenValue = document.getElementById("token-value");
const tokenMeta = document.getElementById("token-meta");

let idToken = "";
let refreshTimer = null;
let signedIn = false;

function setMeta(text) {
  tokenMeta.textContent = text;
}

function setSignedIn(state) {
  signedIn = state;
  loginButton.hidden = state;
  logoutButton.hidden = !state;
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
  if (!idToken) {
    return;
  }

  setMeta("Checking...");

  try {
    const response = await fetch(CONFIG.tokenEndpoint, {
      headers: {
        Authorization: `Bearer ${idToken}`
      }
    });

    if (!response.ok) {
      setMeta("Access denied.");
      return;
    }

    const data = await response.json();
    tokenValue.textContent = data.token || "Unavailable";

    const expiresIn = Number(data.expires_in || 0);
    setMeta(expiresIn ? `Expires in ${expiresIn}s` : "Token ready");
    scheduleRefresh(expiresIn);
  } catch (error) {
    setMeta("Network error.");
  }
}

function handleCredentialResponse(response) {
  idToken = response.credential;
  setSignedIn(true);
  fetchToken();
}

function handleLogout() {
  idToken = "";
  setSignedIn(false);
  tokenValue.textContent = "Sign in to view";
  setMeta("Signed out.");

  if (window.google?.accounts?.id?.disableAutoSelect) {
    google.accounts.id.disableAutoSelect();
  }
}

function handleLogin() {
  if (window.google?.accounts?.id?.prompt) {
    google.accounts.id.prompt();
  } else {
    setMeta("Google sign-in is not ready.");
  }
}

function initGoogle() {
  setSignedIn(false);
  loginButton.addEventListener("click", handleLogin);
  logoutButton.addEventListener("click", handleLogout);

  if (CONFIG.clientId.includes("YOUR_")) {
    setMeta("Set your Google Client ID in token.js");
    loginButton.disabled = true;
    return;
  }

  if (CONFIG.tokenEndpoint.includes("your-worker")) {
    setMeta("Set your token endpoint in token.js");
    loginButton.disabled = true;
    return;
  }

  if (!window.google || !google.accounts || !google.accounts.id) {
    setTimeout(initGoogle, 250);
    return;
  }

  google.accounts.id.initialize({
    client_id: CONFIG.clientId,
    callback: handleCredentialResponse
  });

  google.accounts.id.renderButton(button, {
    theme: "outline",
    size: "large",
    type: "standard",
    shape: "pill"
  });

  google.accounts.id.prompt();
}

window.addEventListener("load", initGoogle);
