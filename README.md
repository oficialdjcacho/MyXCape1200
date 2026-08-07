# MyXCape1200

<p align="center">
  <strong>An independent web dashboard for compatible Moto Morini motorcycles.</strong><br>
  Location, telemetry, trips, alerts and remote controls—available from a modern browser.
</p>

<p align="center">
  <a href="https://myxcape1200.onrender.com/"><img alt="Live demo" src="https://img.shields.io/badge/live%20demo-Render-c8102e?style=for-the-badge"></a>
  <a href="https://github.com/oficialdjcacho/MyXCape1200/actions"><img alt="Tests" src="https://img.shields.io/github/actions/workflow/status/oficialdjcacho/MyXCape1200/tests.yml?branch=main&style=for-the-badge&label=tests"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/code%20license-MIT-b79a58?style=for-the-badge"></a>
</p>

> [!IMPORTANT]
> MyXCape1200 is an unofficial community project. It is not affiliated with, sponsored by, authorised by or endorsed by Moto Morini. Remote commands affect a real motorcycle; use them only on a vehicle you own or are authorised to operate.

## What it offers

- Vehicle location with explicit opt-in before loading OpenStreetMap tiles.
- Dashboard telemetry, range, mileage, oil level and tyre readings.
- Trip history, animated route playback and GPX export.
- Movement-alert history.
- Vehicle-specific capability discovery.
- Remote engine start/stop, heated grips, heated seat, movement alarm and motorcycle finder when advertised by the linked vehicle.
- Responsive interface for desktop and mobile.
- Localised UI in Spanish, English, Italian, Portuguese, German, French, Polish, Greek, Dutch, Simplified Chinese and Malay.

Features are shown according to the capability catalogue returned for the linked motorcycle. Availability, freshness and successful execution ultimately depend on the motorcycle, its T-Box and the Ride MO services.

## Security model

MyXCape1200 is deliberately designed without a shared user database:

- The Ride MO password is used only for the login request, is never serialised and is cleared immediately afterwards.
- Session data is encrypted and authenticated inside a per-browser `HttpOnly` cookie.
- Cookies use `SameSite=Strict`; `Secure` is enabled behind HTTPS and trusted reverse proxies.
- State-changing requests require a CSRF token bound to the encrypted browser session.
- Remote engine commands require an additional per-browser safety PIN.
- Vehicle ownership is revalidated before remote operations.
- Duplicate and abuse protections are applied to remote commands.
- Audit logs contain hashed references and command outcomes, never passwords or authorisation tokens.

Read [SECURITY.md](SECURITY.md) before exposing an instance to other users.

## Quick start

Requirements: Python 3.11 or newer.

```powershell
git clone https://github.com/oficialdjcacho/MyXCape1200.git
cd MyXCape1200
py -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python app.py
```

Open `http://127.0.0.1:8765`.

On Linux or macOS, activate the virtual environment with `source .venv/bin/activate` and run `python app.py`.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `RIDE_MO_LOCAL_SECRET` | Stable encryption key for browser sessions. Required in production. | Generated locally in `instance/flask-secret.txt` |
| `RIDE_MO_COOKIE_MAX_AGE` | Session-cookie lifetime in seconds. | `2592000` (30 days) |
| `RIDE_MO_BASE_URL` | Complete regional API root override for diagnostics only. | Automatically discovered per account |

Do not configure `RIDE_MO_BASE_URL` in a normal public deployment: each account should discover its own regional node. Rotating `RIDE_MO_LOCAL_SECRET` safely invalidates every existing browser session.

## Deploy on Render

The included [`render.yaml`](render.yaml) defines a Gunicorn web service, a `/health` check and a generated encryption secret.

1. Fork or clone this repository into your GitHub account.
2. In Render, create a **Blueprint** and connect the repository.
3. Render detects `render.yaml` and creates the `myxcape1200` service.
4. Confirm that `RIDE_MO_LOCAL_SECRET` exists in the service environment.
5. Keep that value stable across deployments and instances.

Render's free tier may sleep while idle. That makes it suitable for evaluation, but not for remote controls that require predictable availability.

## How it works

```text
Browser
  ├─ encrypted HttpOnly session cookie
  ├─ local language and dashboard preferences
  └─ HTTPS requests + CSRF protection
             │
             ▼
MyXCape1200 / Flask
  ├─ account-region discovery
  ├─ request signing compatible with Ride MO
  ├─ ownership and safety checks
  └─ response normalisation
             │
             ▼
Regional Ride MO service ──► Motorcycle T-Box
```

The client reproduces the request headers required by Ride MO, including the authorisation token, timestamp, Android device marker and matching request signature. No official SDK is bundled.

## Development

Run the automated security and API-contract tests with:

```powershell
.\.venv\Scripts\python -m unittest discover -s tests -v
```

Contributions should preserve the multi-user isolation model, avoid logging private vehicle data and include tests for changes affecting authentication or remote commands.

## Licence and third-party material

The original source code in this repository is available under the [MIT License](LICENSE).

That licence does **not** grant rights to Moto Morini names, trademarks, logos, motorcycle imagery, promotional video or server-provided product assets. Bundled Leaflet files and other external material retain their respective licences and terms. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and exclusions.

## Privacy and responsible use

Vehicle location, routes and remote controls are sensitive. Deploy only over HTTPS, protect the server and encryption secret, avoid public debug logs, and never operate a motorcycle without the owner's explicit authorisation. This software is provided without warranty; you remain responsible for its deployment and use.
