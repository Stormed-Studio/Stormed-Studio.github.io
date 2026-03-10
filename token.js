const CONFIG = {
  clientId: "YOUR_GOOGLE_CLIENT_ID",
  tokenEndpoint: "https://your-worker.example/token"
};

const button = document.getElementById("gsi-button");
const tokenValue = document.getElementById("token-value");
const tokenMeta = document.getElementById("token-meta");

let idToken = "";
let refreshTimer = null;

function setMeta(text) {
  tokenMeta.textContent = text;
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
  fetchToken();
}

function initGoogle() {
  if (CONFIG.clientId.includes("YOUR_")) {
    setMeta("Set your Google Client ID in token.js");
    return;
  }

  if (CONFIG.tokenEndpoint.includes("your-worker")) {
    setMeta("Set your token endpoint in token.js");
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
