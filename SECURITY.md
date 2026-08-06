# Security and public deployment

MyXCape1200 can issue commands to a real motorcycle. Treat it as a safety-sensitive application, not an emergency service.

## Protections implemented

- Encrypted, authenticated, per-browser `HttpOnly`, `Secure`, `SameSite=Strict` session cookies.
- Passwords are never serialized or written to logs.
- CSRF protection on every state-changing route.
- Per-IP login/captcha limits and per-account remote-command limits.
- Six-to-twelve digit safety PIN, PBKDF2-HMAC-SHA256 hashing and a 15-minute lock after five failures.
- Ownership check against the authenticated account before every remote command.
- Command allowlist, advertised-capability validation, state preconditions and duplicate-command suppression.
- HSTS, CSP, clickjacking, MIME-sniffing, referrer and browser-permission headers.
- External map tiles are off by default.
- Automated tests for cookie isolation, expiry, CSRF, ownership, PIN isolation, route responses and concurrency.

The in-memory rate limiter is intended for the single-worker deployment in `render.yaml`. A multi-instance production deployment must replace it with a shared limiter such as Redis.

## Requirements before general public use

1. Obtain written permission or another valid legal basis for use of the Ride MO API and any Moto Morini material. The project disclaimer is not a substitute for permission or compliance with service terms.
2. Use a paid service that does not sleep and has monitoring, incident alerts and predictable retention. Render Free is suitable only for a limited beta.
3. Configure a private privacy/security contact and complete the controller/provider information for the operator's jurisdiction.
4. Vehicle images returned by Ride MO are displayed only as secondary product-identification material; preserve the attribution and independent-project notice, and remove them if the rights holder requests it.
5. Run the automated tests and review dependency alerts before each release.

## Reporting

Do not include credentials, tokens, VINs, vehicle IDs, registration numbers, locations or trip data in public issues. Contact the repository owner privately through the contact method published by the deployed service.
