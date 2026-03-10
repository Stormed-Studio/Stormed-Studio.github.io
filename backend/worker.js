const DEFAULT_STEP_SECONDS = 60;
const DEFAULT_TOKEN_LENGTH = 20;
const DEFAULT_SKEW = 0;
const GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = new Set([
  "https://accounts.google.com",
  "accounts.google.com"
]);

let cachedJwks = null;
let cachedJwksAt = 0;
const JWKS_TTL_MS = 60 * 60 * 1000;

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

    if (url.pathname === "/token") {
      return handleTokenRequest(request, env, corsHeaders);
    }

    if (url.pathname !== "/script") {
      return textResponse("NOT_FOUND", 404, corsHeaders);
    }

    return handleScriptRequest(url, env, corsHeaders);
  }
};

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

async function handleTokenRequest(request, env, corsHeaders) {
  if (!env.TOKEN_SECRET) {
    return textResponse("SERVER_MISSING_SECRET", 500, corsHeaders);
  }

  if (!env.GOOGLE_CLIENT_ID) {
    return textResponse("SERVER_MISSING_GOOGLE_CONFIG", 500, corsHeaders);
  }

  if (!env.ALLOWED_EMAILS && !env.ALLOWED_EMAIL_HASHES) {
    return textResponse("SERVER_MISSING_ALLOWED_EMAILS", 500, corsHeaders);
  }

  if (env.ALLOWED_EMAIL_HASHES && !env.EMAIL_HASH_SECRET) {
    return textResponse("SERVER_MISSING_EMAIL_HASH_SECRET", 500, corsHeaders);
  }

  const authHeader = request.headers.get("authorization") || "";
  const idToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  if (!idToken) {
    return textResponse("NO_AUTH", 401, corsHeaders);
  }

  const email = await verifyGoogleIdToken(idToken, env.GOOGLE_CLIENT_ID);
  if (!email) {
    return textResponse("UNAUTHORIZED", 403, corsHeaders);
  }

  const allowed = await isEmailAllowed(email, env);
  if (!allowed) {
    return textResponse("UNAUTHORIZED", 403, corsHeaders);
  }

  const stepSeconds = toInt(env.STEP_SECONDS, DEFAULT_STEP_SECONDS);
  const tokenLength = toInt(env.TOKEN_LENGTH, DEFAULT_TOKEN_LENGTH);
  const token = await currentToken(env.TOKEN_SECRET, stepSeconds, tokenLength);

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = stepSeconds - (now % stepSeconds);

  return jsonResponse({ token, expires_in: expiresIn }, 200, corsHeaders);
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

async function verifyGoogleIdToken(idToken, clientId) {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const header = decodeJwtSection(parts[0]);
  const payload = decodeJwtSection(parts[1]);

  if (!header || !payload) {
    return null;
  }

  if (header.alg !== "RS256" || !header.kid) {
    return null;
  }

  if (!GOOGLE_ISSUERS.has(payload.iss)) {
    return null;
  }

  if (payload.aud !== clientId) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp <= now) {
    return null;
  }

  if (!payload.email || payload.email_verified !== true) {
    return null;
  }

  const key = await getGoogleKey(header.kid);
  if (!key) {
    return null;
  }

  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlToBytes(parts[2]);

  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature,
    data
  );

  if (!verified) {
    return null;
  }

  return String(payload.email).toLowerCase();
}

async function isEmailAllowed(email, env) {
  const normalized = email.trim().toLowerCase();

  if (env.ALLOWED_EMAIL_HASHES) {
    const hashes = env.ALLOWED_EMAIL_HASHES.split(",")
      .map((value) => value.trim())
      .filter(Boolean);

    if (!hashes.length || !env.EMAIL_HASH_SECRET) {
      return false;
    }

    const digest = await hmacBase64Url(env.EMAIL_HASH_SECRET, normalized);
    return hashes.includes(digest);
  }

  if (env.ALLOWED_EMAILS) {
    const allowed = env.ALLOWED_EMAILS.split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    return allowed.includes(normalized);
  }

  return false;
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

async function getGoogleKey(kid) {
  const jwks = await getGoogleJwks();
  let jwk = jwks.find((key) => key.kid === kid);

  if (!jwk) {
    cachedJwks = null;
    cachedJwksAt = 0;
    const fresh = await getGoogleJwks();
    jwk = fresh.find((key) => key.kid === kid);
  }

  if (!jwk) {
    return null;
  }

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function getGoogleJwks() {
  const now = Date.now();
  if (cachedJwks && now - cachedJwksAt < JWKS_TTL_MS) {
    return cachedJwks;
  }

  const response = await fetch(GOOGLE_CERTS_URL, {
    cf: { cacheTtl: 3600, cacheEverything: true }
  });

  if (!response.ok) {
    return [];
  }

  const data = await response.json();
  cachedJwks = Array.isArray(data.keys) ? data.keys : [];
  cachedJwksAt = now;

  return cachedJwks;
}

function decodeJwtSection(section) {
  try {
    const bytes = base64UrlToBytes(section);
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (error) {
    return null;
  }
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
