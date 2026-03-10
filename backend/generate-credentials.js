const crypto = require("crypto");

const username = (process.argv[2] || "").trim();
const password = process.argv[3] || "";
const iterations = Number.parseInt(process.argv[4] || "210000", 10);

if (!username || !password) {
  console.error("Usage: node generate-credentials.js <username> <password> [iterations]");
  process.exit(1);
}

const salt = crypto.randomBytes(16);
const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");

console.log("AUTH_USER=", username);
console.log("AUTH_SALT=", salt.toString("base64"));
console.log("AUTH_HASH=", hash.toString("base64"));
console.log("AUTH_ITERATIONS=", iterations);
