# MyXCape1200

Independent, unofficial web client for owners of compatible Moto Morini motorcycles. It provides vehicle location, telemetry, tyre information, trips, movement alerts and the remote functions advertised by the linked vehicle.

This project is not affiliated with, sponsored by, authorised by or endorsed by Moto Morini. Product names, logos and other official materials belong to their respective owners. Remote operations can affect a real motorcycle: deploy only over HTTPS, keep the encryption secret private and use the controls solely on a vehicle you own or are authorised to operate.

```powershell
cd ride-mo-web
py -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python app.py
```

Open `http://127.0.0.1:8765`.

The login is restored automatically after F5 from a per-browser encrypted, authenticated `HttpOnly` cookie. The Ride MO token, regional endpoint and minimal account metadata are not written to a server database or shared session file; the password is never serialized and is cleared from memory immediately after the login attempt. Use **Cerrar sesión** to delete the browser cookie. If Ride MO expires or revokes the token, the login form is shown again because the APK exposes no dedicated refresh-token endpoint.

The generated encryption secret is stored in `instance/flask-secret.txt`, which keeps browser cookies valid across restarts. For production and multiple instances, set the same strong `RIDE_MO_LOCAL_SECRET` environment variable on every instance and never commit it. Losing or rotating this key safely invalidates all browser sessions. Like Ride MO, the client bootstraps through `apiland.motomorini.com` and calls `client/ip/getNodeInfo` to discover the account's regional API. Override the complete API root with `RIDE_MO_BASE_URL` only for diagnostics.

State-changing API calls require a CSRF token bound to the encrypted browser state. Cookies are `SameSite=Strict` and `HttpOnly`; `Secure` is enabled automatically when Flask sees HTTPS (including `X-Forwarded-Proto` from a trusted reverse proxy). Do not expose the development server directly to the Internet. Remote-action audit logs contain hashed operation references and command results, never authorization tokens or passwords.

Authenticated requests reproduce Ride MO's headers: raw token in `Authorization`, `API-TIMESTAMP`, `API-DEVICE: Android`, and the matching `API-SIGN` MD5 signature.

## Despliegue en Render

El archivo `render.yaml` define un Web Service gratuito con Gunicorn, HTTPS gestionado por Render y una clave de cifrado persistente generada como variable de entorno. Para desplegarlo:

1. Publica esta carpeta como la raiz de un repositorio privado de GitHub o GitLab.
2. En el proyecto de Render, selecciona **New > Blueprint** y conecta el repositorio.
3. Render detectara `render.yaml` y creara el servicio `myxcape1200`.
4. Comprueba que `RIDE_MO_LOCAL_SECRET` aparece en **Environment** y no cambies su valor despues de que haya usuarios conectados: rotarlo cierra de forma segura todas las sesiones.

No configures `RIDE_MO_BASE_URL` en produccion: cada cuenta debe descubrir su nodo regional. El plan gratuito de Render suspende el servicio cuando queda inactivo, por lo que la primera visita posterior puede tardar en responder.
