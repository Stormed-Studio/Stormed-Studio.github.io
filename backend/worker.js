const DEFAULT_STEP_SECONDS = 60;
const DEFAULT_TOKEN_LENGTH = 20;
const DEFAULT_SKEW = 0;
const DEFAULT_SESSION_TTL = 600;
const DEFAULT_PBKDF2_ITERATIONS = 210000;

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

    if (url.pathname === "/auth/login") {
      return handleLogin(request, env, corsHeaders);
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

async function handleLogin(request, env, corsHeaders) {
  if (request.method !== "POST") {
    return textResponse("METHOD_NOT_ALLOWED", 405, corsHeaders);
  }

  if (!env.AUTH_USER || !env.AUTH_SALT || !env.AUTH_HASH || !env.SESSION_SECRET) {
    return textResponse("SERVER_MISSING_AUTH", 500, corsHeaders);
  }

  let body;
  try {
    body = await request.json();
  } catch (error) {
    return textResponse("BAD_REQUEST", 400, corsHeaders);
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!username || !password) {
    return textResponse("BAD_REQUEST", 400, corsHeaders);
  }

  if (username !== env.AUTH_USER) {
    return textResponse("UNAUTHORIZED", 403, corsHeaders);
  }

  const salt = base64ToBytes(env.AUTH_SALT);
  const expected = base64ToBytes(env.AUTH_HASH);
  const iterations = toInt(env.AUTH_ITERATIONS, DEFAULT_PBKDF2_ITERATIONS);

  const derived = await derivePassword(password, salt, iterations);
  if (!timingSafeEqualBytes(derived, expected)) {
    return textResponse("UNAUTHORIZED", 403, corsHeaders);
  }

  const now = Math.floor(Date.now() / 1000);
  const ttl = toInt(env.SESSION_TTL, DEFAULT_SESSION_TTL);
  const session = await signSession(env.SESSION_SECRET, {
    login: username,
    iat: now,
    exp: now + ttl
  });

  return jsonResponse({ session, login: username }, 200, corsHeaders);
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
    "access-control-allow-methods": "GET, POST, OPTIONS",
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

async function derivePassword(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    key,
    256
  );

  return new Uint8Array(bits);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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

function timingSafeEqualBytes(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
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
