# Key backend

Deploy `worker.js` as a Cloudflare Worker (or any platform that supports the Workers runtime).

Env vars
- `TOKEN_SECRET`: long random secret
- `SCRIPT`: raw script text returned when token is valid
- `GOOGLE_CLIENT_ID`: Google OAuth client ID (web)
- `ALLOWED_EMAILS`: comma-separated list of allowed Google emails (plaintext)
- `ALLOWED_EMAIL_HASHES`: comma-separated list of HMAC-SHA256 email hashes (recommended)
- `EMAIL_HASH_SECRET`: secret used to hash emails when using `ALLOWED_EMAIL_HASHES`
- `ACCESS_ORIGIN` (optional, recommended): site origin allowed to call `/token`
- `TOKEN_LENGTH` (optional, default `20`)
- `STEP_SECONDS` (optional, default `60`)
- `ALLOWED_SKEW` (optional, default `0`)

Request
- `GET /script?token=YOUR_TOKEN`
- `GET /token` with header `Authorization: Bearer <Google ID token>`

Generate token locally
- `node generate-token.js <TOKEN_SECRET>`

Generate email hash (recommended)
- `node generate-email-hash.js yfydgf477@gmail.com <EMAIL_HASH_SECRET>`
