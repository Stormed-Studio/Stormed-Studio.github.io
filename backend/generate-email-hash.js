const crypto = require("crypto");

const email = (process.argv[2] || "").trim().toLowerCase();
const secret = process.argv[3] || process.env.EMAIL_HASH_SECRET;

if (!email || !secret) {
  console.error("Usage: node generate-email-hash.js <email> <EMAIL_HASH_SECRET>");
  process.exit(1);
}

const digest = crypto
  .createHmac("sha256", secret)
  .update(email)
  .digest("base64")
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/g, "");

console.log(digest);
