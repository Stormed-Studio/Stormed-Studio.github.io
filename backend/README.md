# Key backend

Deploy `worker.js` as a Cloudflare Worker (or any platform that supports the Workers runtime).

Env vars
- `TOKEN_SECRET`: long random secret
- `SCRIPT`: raw script text returned when token is valid
- `TOKEN_LENGTH` (optional, default `20`)
- `STEP_SECONDS` (optional, default `60`)
- `ALLOWED_SKEW` (optional, default `0`)

Request
- `GET /script?token=YOUR_TOKEN`

Generate token locally
- `node generate-token.js <TOKEN_SECRET>`
