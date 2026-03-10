# Key backend

Deploy `worker.js` as a Cloudflare Worker (or any platform that supports the Workers runtime).

Env vars
- `TOKEN_SECRET`: long random secret
- `SCRIPT`: raw script text returned when token is valid
- `SESSION_SECRET`: secret for signing sessions (random, 32+ chars)
- `AUTH_USER`: login username
- `AUTH_SALT`: base64 salt for password hash
- `AUTH_HASH`: base64 PBKDF2 hash
- `AUTH_ITERATIONS` (optional, default `210000`)
- `ACCESS_ORIGIN` (optional, recommended): site origin allowed to call `/token`
- `TOKEN_LENGTH` (optional, default `20`)
- `STEP_SECONDS` (optional, default `60`)
- `ALLOWED_SKEW` (optional, default `0`)
- `SESSION_TTL` (optional, default `600` seconds)

Endpoints
- `POST /auth/login` with JSON `{ "username": "...", "password": "..." }`
- `GET /token` with header `Authorization: Bearer <session>`
- `GET /script?token=YOUR_TOKEN`

Generate credentials
- `node generate-credentials.js StorHum STORHUM111222431`

Generate token locally
- `node generate-token.js <TOKEN_SECRET>`
