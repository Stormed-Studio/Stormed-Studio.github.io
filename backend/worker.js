const DEFAULT_STEP_SECONDS = 60;
const DEFAULT_TOKEN_LENGTH = 20;
const DEFAULT_SKEW = 0;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/health") {
      return textResponse("OK", 200);
    }

    if (url.pathname !== "/script") {
      return textResponse("NOT_FOUND", 404);
    }

    if (!env.TOKEN_SECRET) {
      return textResponse("SERVER_MISSING_SECRET", 500);
    }

    if (!env.SCRIPT) {
      return textResponse("SERVER_MISSING_SCRIPT", 500);
    }

    const token = (url.searchParams.get("token") || url.searchParams.get("key") || "")
      .replace(/\s+/g, "")
      .toUpperCase();

    if (!token) {
      return textResponse("NO_TOKEN", 401);
    }

    const stepSeconds = toInt(env.STEP_SECONDS, DEFAULT_STEP_SECONDS);
    const tokenLength = toInt(env.TOKEN_LENGTH, DEFAULT_TOKEN_LENGTH);
    const allowedSkew = toInt(env.ALLOWED_SKEW, DEFAULT_SKEW);

    const ok = await verifyToken(token, env.TOKEN_SECRET, stepSeconds, tokenLength, allowedSkew);
    if (!ok) {
      return textResponse("BAD_TOKEN", 403);
    }

    return new Response(env.SCRIPT, {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "access-control-allow-origin": "*",
        "x-content-type-options": "nosniff"
      }
    });
  }
};

function textResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store"
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

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const counter = Math.floor(Date.now() / 1000 / stepSeconds);
  for (let offset = -skew; offset <= skew; offset += 1) {
    const expected = await makeToken(key, counter + offset, length);
    if (timingSafeEqual(input, expected)) {
      return true;
    }
  }

  return false;
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
