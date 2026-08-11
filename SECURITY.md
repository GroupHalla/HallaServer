# Server hardening

Secure defaults:

- `adminPassword` empty; known placeholders abort startup.
- ServerQuery disabled (`port=0`), loopback-bound and TLS-only when enabled.
- Query login is rate-limited and only PBKDF2-SHA256 is persisted.
- UDP protocol v4 uses random 128-bit credentials received over TLS.
- Channel passwords are PBKDF2-SHA256 hashed at rest.
- TLS `certFile` and `keyFile` are honored and validated.

Prefer environment variables for secrets:

- `HALLA_SERVER_PASSWORD`, `HALLA_ADMIN_PASSWORD`
- `HALLA_DATABASE_PASSWORD`, `HALLA_QUERY_PASSWORD`
- `HALLA_TURN_URL`, `HALLA_TURN_USERNAME`, `HALLA_TURN_PASSWORD`

Windows releases are currently allowed without Authenticode. When a trusted
certificate becomes available, configure `WINDOWS_SIGNING_PFX_BASE64` and
`WINDOWS_SIGNING_PFX_PASSWORD`; the existing workflow signs automatically.
