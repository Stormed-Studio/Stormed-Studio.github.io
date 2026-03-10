const DEFAULT_STEP_SECONDS = 60;
const DEFAULT_TOKEN_LENGTH = 20;
const DEFAULT_SKEW = 0;
const DEFAULT_SESSION_TTL = 600;

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_API_BASE = "https://api.github.com";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = buildCorsHeaders(env.ACCESS_ORIGIN);

    if (request.method === "OPTIONS") {
      return new Response("", { status: 204, headers: corsHeaders });
    }

    if (url.pathname === "/" || url.pathname === "/health") {
      return textResponse("OK", 200, corsHeaders);
    }

    if (url.pathname === "/oauth/start") {
      return handleOAuthStart(request, env);
    }

    if (url.pathname === "/oauth/callback") {
      return handleOAuthCallback(request, env);
    }

    if (url.pathname === "/token") {
      return handleTokenRequest(request, env, corsHeaders);
    }

    if (url.pathname === "/script") {
      return handleScriptRequest(url, env, corsHeaders);
    }

    return textResponse("NOT_FOUND", 404, corsHeaders);
  }
};

async function handleOAuthStart(request, env) {
  if (!env.GITHUB_CLIENT_ID || !env.SESSION_SECRET) {
    return textResponse("SERVER_MISSING_GITHUB_CONFIG", 500);
  }

  const url = new URL(request.url);
  const redirectUri = env.GITHUB_REDIRECT_URI || new URL("/oauth/callback", url.origin).toString();
  const state = await makeState(env.SESSION_SECRET);

  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: redirectUri,
    state,
    scope: "read:org read:user",
    allow_signup: "false"
  });

  return Response.redirect(`${GITHUB_AUTHORIZE_URL}?${params.toString()}`, 302);
}

async function handleOAuthCallback(request, env) {
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET || !env.SESSION_SECRET) {
    return textResponse("SERVER_MISSING_GITHUB_CONFIG", 500);
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return textResponse("OAUTH_MISSING_CODE", 400);
  }

  const stateOk = await verifyState(state, env.SESSION_SECRET);
  if (!stateOk) {
    return textResponse("OAUTH_BAD_STATE", 400);
  }

  const redirectUri = env.GITHUB_REDIRECT_URI || new URL("/oauth/callback", url.origin).toString();

  const tokenResponse = await fetch(GITHUB_TOKEN_URL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json"
    },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri
    })
  });

  if (!tokenResponse.ok) {
    return textResponse("OAUTH_TOKEN_FAILED", 502);
  }

  const tokenData = await tokenResponse.json();
  const accessToken = tokenData.access_token;
  if (!accessToken) {
    return textResponse("OAUTH_TOKEN_MISSING", 502);
  }

  const user = await fetchGitHubUser(accessToken);
  if (!user) {
    return textResponse("OAUTH_USER_FAILED", 502);
  }

  const org = env.ORG_NAME || "Stormed-Studio";
  const membership = await fetchOrgMembership(accessToken, org);
  if (!membership || membership.state !== "active") {
    return textResponse("UNAUTHORIZED", 403);
  }

  const now = Math.floor(Date.now() / 1000);
  const ttl = toInt(env.SESSION_TTL, DEFAULT_SESSION_TTL);
  const session = await signSession(env.SESSION_SECRET, {
    sub: user.id,
    login: user.login,
    org,
    iat: now,
    exp: now + ttl
  });

  const frontendUrl = resolveFrontendUrl(env);
  if (!frontendUrl) {
    return textResponse("SERVER_MISSING_FRONTEND_URL", 500);
  }

  const redirectUrl = `${frontendUrl}#session=${encodeURIComponent(session)}`;
  return Response.redirect(redirectUrl, 302);
}

async function handleTokenRequest(request, env, corsHeaders) {
  if (!env.SESSION_SECRET || !env.TOKEN_SECRET) {
    return textResponse("SERVER_MISSING_SECRET", 500, corsHeaders);
  }

  const session = extractSession(request);
  if (!session) {
    return textResponse("NO_SESSION", 401, corsHeaders);
  }

  const payload = await verifySession(session, env.SESSION_SECRET);
  if (!payload) {
    return textResponse("BAD_SESSION", 403, corsHeaders);
  }

  const stepSeconds = toInt(env.STEP_SECONDS, DEFAULT_STEP_SECONDS);
  const tokenLength = toInt(env.TOKEN_LENGTH, DEFAULT_TOKEN_LENGTH);
  const token = await currentToken(env.TOKEN_SECRET, stepSeconds, tokenLength);

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = stepSeconds - (now % stepSeconds);

  return jsonResponse(
    {
      token,
      expires_in: expiresIn,
      login: payload.login || ""
    },
    200,
    corsHeaders
  );
}

async function handleScriptRequest(url, env, corsHeaders) {
  if (!env.TOKEN_SECRET) {
    return textResponse("SERVER_MISSING_SECRET", 500, corsHeaders);
  }

  if (!env.SCRIPT) {
    return textResponse("SERVER_MISSING_SCRIPT", 500, corsHeaders);
  }

  const token = (url.searchParams.get("token") || url.searchParams.get("key") || "")
    .replace(/\s+/g, "")
    .toUpperCase();

  if (!token) {
    return textResponse("NO_TOKEN", 401, corsHeaders);
  }

  const stepSeconds = toInt(env.STEP_SECONDS, DEFAULT_STEP_SECONDS);
  const tokenLength = toInt(env.TOKEN_LENGTH, DEFAULT_TOKEN_LENGTH);
  const allowedSkew = toInt(env.ALLOWED_SKEW, DEFAULT_SKEW);

  const ok = await verifyToken(token, env.TOKEN_SECRET, stepSeconds, tokenLength, allowedSkew);
  if (!ok) {
    return textResponse("BAD_TOKEN", 403, corsHeaders);
  }

  return new Response(env.SCRIPT, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": corsHeaders["access-control-allow-origin"],
      "x-content-type-options": "nosniff"
    }
  });
}

function buildCorsHeaders(accessOrigin) {
  const origin = accessOrigin || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, OPTIONS",
    "access-control-allow-headers": "authorization, content-type"
  };
}

function textResponse(body, status, extraHeaders) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function jsonResponse(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders
    }
  });
}

function toInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function resolveFrontendUrl(env) {
  if (env.FRONTEND_TOKEN_URL) {
    return env.FRONTEND_TOKEN_URL;
  }
  if (env.FRONTEND_URL) {
    return new URL("token.html", env.FRONTEND_URL).toString();
  }
  return "";
}

function extractSession(request) {
  const authHeader = request.headers.get("authorization") || "";
  if (authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  const url = new URL(request.url);
  return url.searchParams.get("session") || "";
}

async function verifyToken(input, secret, stepSeconds, length, skew) {
  if (!/^[A-Z2-7]+$/.test(input) || input.length !== length) {
    return false;
  }

  const key = await importHmacKey(secret);
  const counter = Math.floor(Date.now() / 1000 / stepSeconds);

  for (let offset = -skew; offset <= skew; offset += 1) {
    const expected = await makeToken(key, counter + offset, length);
    if (timingSafeEqual(input, expected)) {
      return true;
    }
  }

  return false;
}

async function currentToken(secret, stepSeconds, length) {
  const key = await importHmacKey(secret);
  const counter = Math.floor(Date.now() / 1000 / stepSeconds);
  return makeToken(key, counter, length);
}

async function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function makeToken(key, counter, length) {
  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const sig = await crypto.subtle.sign("HMAC", key, msg);
  const token = base32Encode(new Uint8Array(sig));
  return token.slice(0, length);
}

function base32Encode(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function fetchGitHubUser(accessToken) {
  const response = await fetch(`${GITHUB_API_BASE}/user`, {
    headers: {
      authorization: `Bearer ${accessToken}`,
      accept: "application/vnd.github+json",
      "user-agent": "stormed-hub"
    }
  });

  if (!response.ok) {
    return null;
  }

  return response.json();
}

async function fetchOrgMembership(accessToken, org) {
  const response = await fetch(
    `${GITHUB_API_BASE}/user/memberships/orgs/${encodeURIComponent(org)}`,
    {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/vnd.github+json",
        "user-agent": "stormed-hub"
      }
    }
  );

  if (!response.ok) {
    return null;
  }

  return response.json();
}

async function makeState(secret) {
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  const issued = Math.floor(Date.now() / 1000);
  const payload = `${issued}.${base64UrlFromBytes(nonce)}`;
  const sig = await hmacBase64Url(secret, payload);
  return `${payload}.${sig}`;
}

async function verifyState(state, secret) {
  const parts = state.split(".");
  if (parts.length !== 3) {
    return false;
  }
  const issued = Number.parseInt(parts[0], 10);
  if (!Number.isFinite(issued)) {
    return false;
  }
  const payload = `${parts[0]}.${parts[1]}`;
  const sig = parts[2];
  const expected = await hmacBase64Url(secret, payload);
  if (!timingSafeEqual(sig, expected)) {
    return false;
  }
  const now = Math.floor(Date.now() / 1000);
  return now - issued <= 300;
}

async function signSession(secret, payload) {
  const body = base64UrlFromBytes(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await hmacBase64Url(secret, body);
  return `${body}.${sig}`;
}

async function verifySession(session, secret) {
  const parts = session.split(".");
  if (parts.length !== 2) {
    return null;
  }
  const [body, sig] = parts;
  const expected = await hmacBase64Url(secret, body);
  if (!timingSafeEqual(sig, expected)) {
    return null;
  }
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(body)));
    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp <= now) {
      return null;
    }
    return payload;
  } catch (error) {
    return null;
  }
}

async function hmacBase64Url(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );
  return base64UrlFromBytes(new Uint8Array(sig));
}

function base64UrlFromBytes(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}
