const crypto = require("crypto");

const secret = process.argv[2] || process.env.TOKEN_SECRET;
if (!secret) {
  console.error("Usage: node generate-token.js <TOKEN_SECRET>");
  process.exit(1);
}

const stepSeconds = parseInt(process.env.STEP_SECONDS || "60", 10);
const tokenLength = parseInt(process.env.TOKEN_LENGTH || "20", 10);
const counter = Math.floor(Date.now() / 1000 / stepSeconds);

const msg = Buffer.alloc(8);
msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
msg.writeUInt32BE(counter >>> 0, 4);

const hmac = crypto.createHmac("sha256", secret).update(msg).digest();
const token = base32Encode(hmac).slice(0, tokenLength);

console.log(token);

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
