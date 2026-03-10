# Key backend

Deploy `worker.js` as a Cloudflare Worker (or any platform that supports the Workers runtime).

Env vars
- `TOKEN_SECRET`: long random secret
- `SCRIPT`: raw script text returned when token is valid
- `SESSION_SECRET`: secret for signing sessions (random, 32+ chars)
- `GITHUB_CLIENT_ID`: GitHub OAuth App client ID
- `GITHUB_CLIENT_SECRET`: GitHub OAuth App client secret
- `ORG_NAME` (optional, default `Stormed-Studio`): GitHub org required for access
- `FRONTEND_URL`: site base URL (used to redirect after login)
- `FRONTEND_TOKEN_URL` (optional): full URL to `token.html` (overrides `FRONTEND_URL`)
- `ACCESS_ORIGIN` (optional, recommended): site origin allowed to call `/token`
- `TOKEN_LENGTH` (optional, default `20`)
- `STEP_SECONDS` (optional, default `60`)
- `ALLOWED_SKEW` (optional, default `0`)
- `SESSION_TTL` (optional, default `600` seconds)

Endpoints
- `GET /oauth/start` -> redirects to GitHub login
- `GET /oauth/callback` -> GitHub OAuth callback
- `GET /token` with header `Authorization: Bearer <session>`
- `GET /script?token=YOUR_TOKEN`

Generate token locally
- `node generate-token.js <TOKEN_SECRET>`
