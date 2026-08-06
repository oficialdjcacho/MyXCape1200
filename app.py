import base64
import hashlib
import json
import os
import secrets
import threading
import time
import zlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, g, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

API_SUFFIX = "/motomorini-client/v2"
BOOTSTRAP_URL = "https://apiland.motomorini.com" + API_SUFFIX
BASE_URL_OVERRIDE = os.getenv("RIDE_MO_BASE_URL", "").rstrip("/")
TIMEOUT = (5, 15)

app = Flask(__name__)
os.makedirs(app.instance_path, exist_ok=True)
SECRET_FILE = Path(app.instance_path) / "flask-secret.txt"
REMOTE_LOG_FILE = Path(app.instance_path) / "remote-actions.log"
AUTH_COOKIE = "ride_mo_auth"
AUTH_COOKIE_MAX_AGE = int(os.getenv("RIDE_MO_COOKIE_MAX_AGE", str(30 * 24 * 60 * 60)))
remote_log_lock = threading.Lock()
rate_lock = threading.Lock()
rate_buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)
remote_inflight: dict[str, float] = {}


def local_secret() -> str:
    configured = os.getenv("RIDE_MO_LOCAL_SECRET")
    if configured:
        return configured
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    value = secrets.token_hex(32)
    SECRET_FILE.write_text(value, encoding="utf-8")
    try:
        os.chmod(SECRET_FILE, 0o600)
    except OSError:
        pass
    return value


app.secret_key = local_secret()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
cookie_key = base64.urlsafe_b64encode(
    hashlib.sha256(("ride-mo-cookie-v1:" + app.secret_key).encode("utf-8")).digest()
)
cookie_cipher = Fernet(cookie_key)


@dataclass
class RideSession:
    email: str = ""
    password: str = ""
    token: str = ""
    user: dict[str, Any] = field(default_factory=dict)
    captcha_key: str = ""
    base_url: str = ""
    node: dict[str, Any] = field(default_factory=dict)
    csrf: str = ""
    safety_pin_hash: str = ""
    safety_pin_salt: str = ""
    pin_failures: int = 0
    pin_locked_until: float = 0
    privacy_accepted_at: int = 0
    command_records: set[str] = field(default_factory=set)
    command_meta: dict[str, dict[str, str]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


def state_payload(state: RideSession) -> dict[str, Any]:
    """Return the minimal per-browser state; passwords are deliberately excluded."""
    recent_meta = list(state.command_meta.items())[-8:]
    return {
        "v": 1,
        "token": state.token,
        "user": {key: state.user.get(key) for key in ("id", "nickName", "email") if state.user.get(key) is not None},
        "captchaKey": state.captcha_key,
        "baseUrl": state.base_url,
        "node": {key: state.node.get(key) for key in
                 ("nodeKey", "nodeName", "regionName", "countryName", "apiEndPoint")
                 if state.node.get(key) is not None},
        "csrf": getattr(state, "csrf", ""),
        "pinHash": state.safety_pin_hash,
        "pinSalt": state.safety_pin_salt,
        "pinFailures": state.pin_failures,
        "pinLockedUntil": state.pin_locked_until,
        "privacyAcceptedAt": state.privacy_accepted_at,
        "commands": dict(recent_meta),
    }


def encode_state(state: RideSession) -> str:
    raw = json.dumps(state_payload(state), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    value = cookie_cipher.encrypt(zlib.compress(raw, level=9)).decode("ascii")
    if len(value) > 3800:
        raise RuntimeError("The encrypted Ride MO session is too large for a browser cookie")
    return value


def decode_state(value: str) -> RideSession:
    state = RideSession()
    if not value:
        return state
    try:
        raw = zlib.decompress(cookie_cipher.decrypt(value.encode("ascii"), ttl=AUTH_COOKIE_MAX_AGE))
        saved = json.loads(raw.decode("utf-8"))
        if saved.get("v") != 1:
            return state
        state.token = str(saved.get("token") or "")
        state.user = saved.get("user") if isinstance(saved.get("user"), dict) else {}
        state.captcha_key = str(saved.get("captchaKey") or "")
        state.base_url = str(saved.get("baseUrl") or "")
        state.node = saved.get("node") if isinstance(saved.get("node"), dict) else {}
        state.csrf = str(saved.get("csrf") or "")
        state.safety_pin_hash = str(saved.get("pinHash") or "")
        state.safety_pin_salt = str(saved.get("pinSalt") or "")
        state.pin_failures = int(saved.get("pinFailures") or 0)
        state.pin_locked_until = float(saved.get("pinLockedUntil") or 0)
        state.privacy_accepted_at = int(saved.get("privacyAcceptedAt") or 0)
        state.command_meta = saved.get("commands") if isinstance(saved.get("commands"), dict) else {}
        state.command_records = set(state.command_meta)
    except (InvalidToken, ValueError, TypeError, KeyError, zlib.error, json.JSONDecodeError):
        return RideSession()
    return state


def remote_audit(event: str, **fields: Any) -> None:
    """Append a credential-free diagnostic event for remote-control testing."""
    payload = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    payload.update({key: value for key, value in fields.items() if value is not None})
    with remote_log_lock:
        with REMOTE_LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")


def private_ref(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def local_session() -> RideSession:
    if "ride_state" not in g:
        g.ride_state = decode_state(request.cookies.get(AUTH_COOKIE, ""))
        if not g.ride_state.csrf:
            g.ride_state.csrf = secrets.token_urlsafe(24)
            g.ride_dirty = True
    return g.ride_state


def mark_session_dirty() -> None:
    g.ride_dirty = True


def rate_identity(scope: str) -> str:
    ip = request.remote_addr or "unknown"
    if scope == "account":
        token = local_session().token
        return f"{ip}:{private_ref(token) if token else 'anonymous'}"
    return ip


def rate_limited(scope: str, limit: int, window: int):
    """Small single-instance limiter; Render runs one Gunicorn worker for consistency."""
    now = time.monotonic()
    key = (scope, rate_identity("account" if scope == "remote" else "ip"))
    with rate_lock:
        bucket = rate_buckets[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry = max(1, int(window - (now - bucket[0])))
            response = jsonify(error="Demasiadas solicitudes. Espera antes de volver a intentarlo.")
            response.status_code = 429
            response.headers["Retry-After"] = str(retry)
            return response
        bucket.append(now)
    return None


@app.before_request
def csrf_protection():
    if request.endpoint == "captcha":
        limited = rate_limited("captcha", 12, 600)
        if limited:
            return limited
    elif request.endpoint == "login":
        limited = rate_limited("login", 5, 900)
        if limited:
            return limited
    elif request.endpoint in {"remote_action", "safety_pin"}:
        limited = rate_limited("remote", 8, 60)
        if limited:
            return limited
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    state = local_session()
    supplied = request.headers.get("X-CSRF-Token", "")
    if not supplied or not secrets.compare_digest(supplied, state.csrf):
        return jsonify(error="La sesión de seguridad ha caducado. Recarga la página."), 403
    return None


def envelope(response: requests.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(f"Ride MO returned non-JSON HTTP {response.status_code}") from exc
    if not response.ok:
        raise RuntimeError(payload.get("msg") or payload.get("message") or f"HTTP {response.status_code}")
    if str(payload.get("code", "0")) != "0":
        raise RuntimeError(payload.get("msg") or payload.get("message") or f"Ride MO code {payload.get('code')}")
    return payload


def call(method: str, path: str, *, auth: bool = False, **kwargs) -> dict[str, Any]:
    state = local_session()
    base_url = state.base_url or BASE_URL_OVERRIDE or BOOTSTRAP_URL
    timestamp = str(int(time.time() * 1000))
    signature = hashlib.md5((timestamp + "Androidipzoe*2020").encode("utf-8")).hexdigest()
    headers = {"Accept": "application/json", "Accept-Language": "es-ES",
               "API-TIMESTAMP": timestamp, "API-DEVICE": "Android", "API-SIGN": signature}
    if auth:
        if not state.token:
            raise RuntimeError("Not signed in")
        headers["Authorization"] = state.token
    response = requests.request(method, f"{base_url}/{path.lstrip('/')}", headers=headers,
                                timeout=TIMEOUT, allow_redirects=False, **kwargs)
    return envelope(response)


def login_remote(state: RideSession, code: str, code_key: str) -> None:
    payload = {"email": state.email, "password": state.password,
               "code": code or None, "codeKey": code_key or None}
    data = call("POST", "api/auth/login", json=payload).get("data") or {}
    token = data.get("token")
    if not token:
        raise RuntimeError("Login succeeded without a token")
    state.token, state.user = token, data


@app.after_request
def security_headers(response):
    if request.endpoint == "static" and response.status_code == 200:
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    else:
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; media-src 'self'; connect-src 'self'"
    )
    if getattr(g, "clear_ride_cookie", False):
        response.delete_cookie(AUTH_COOKIE, path="/", secure=request.is_secure,
                               httponly=True, samesite="Strict")
    elif getattr(g, "ride_dirty", False):
        response.set_cookie(
            AUTH_COOKIE,
            encode_state(local_session()),
            max_age=AUTH_COOKIE_MAX_AGE,
            secure=request.is_secure,
            httponly=True,
            samesite="Strict",
            path="/",
        )
    return response


@app.get("/")
def index():
    return render_template(
        "index.html",
        base_url=BASE_URL_OVERRIDE or "nodo regional descubierto por Ride MO",
        official_assets=os.getenv("OFFICIAL_ASSETS_ENABLED", "false").lower() == "true",
    )


@app.get("/health")
def health():
    """Una comprobacion local que no contacta con Ride MO ni expone sesiones."""
    commit = os.getenv("RENDER_GIT_COMMIT", "local")
    return jsonify(status="ok", commit=commit[:7])


def discover_node(state: RideSession) -> None:
    if BASE_URL_OVERRIDE:
        state.base_url = BASE_URL_OVERRIDE
        state.node = {"nodeName": "Manual", "apiEndPoint": BASE_URL_OVERRIDE.removesuffix(API_SUFFIX)}
        return
    data = call("GET", "client/ip/getNodeInfo").get("data") or {}
    endpoint = str(data.get("apiEndPoint") or "").rstrip("/")
    if not endpoint.startswith("https://"):
        raise RuntimeError("Ride MO returned an invalid regional endpoint")
    state.base_url = endpoint + API_SUFFIX
    state.node = data


@app.get("/api/captcha")
def captcha():
    state = local_session()
    discover_node(state)
    data = call("POST", "api/auth/get-code").get("data") or {}
    state.captcha_key = data.get("codeKey") or ""
    mark_session_dirty()
    raw = data.get("code") or ""
    # The API may return either a data URL/base64 image or a printable challenge.
    if raw and not raw.startswith("data:"):
        try:
            base64.b64decode(raw, validate=True)
            raw = "data:image/png;base64," + raw
        except Exception:
            pass
    return jsonify(code=raw, codeKey=state.captcha_key, csrf=state.csrf,
                   node={k: state.node.get(k) for k in ("nodeKey", "nodeName", "regionName", "countryName", "apiEndPoint")})


@app.post("/api/login")
def login():
    body = request.get_json(force=True)
    state = local_session()
    if body.get("acceptPrivacy") is not True:
        return jsonify(error="Debes aceptar la política de privacidad y las condiciones de uso"), 400
    with state.lock:
        state.email = str(body.get("email", "")).strip()
        state.password = str(body.get("password", ""))
        if not state.email or not state.password:
            return jsonify(error="Email and password are required"), 400
        try:
            login_remote(state, str(body.get("code", "")), state.captcha_key)
            state.user = {key: state.user.get(key) for key in ("id", "nickName", "email")
                          if state.user.get(key) is not None}
            state.privacy_accepted_at = int(time.time())
            state.safety_pin_hash = state.safety_pin_salt = ""
            state.pin_failures = 0
            state.pin_locked_until = 0
            mark_session_dirty()
        except Exception as exc:
            state.token = ""
            state.user = {}
            state.email = ""
            mark_session_dirty()
            return jsonify(error=str(exc)), 401
        finally:
            state.password = ""
    return jsonify(ok=True, csrf=state.csrf,
                   user={k: state.user.get(k) for k in ("id", "nickName", "email")})


@app.get("/api/session")
def session_status():
    """Restore this browser's encrypted cookie and validate it against Ride MO."""
    state = local_session()
    if not state.token:
        return jsonify(authenticated=False, csrf=state.csrf)
    try:
        payload = call("GET", "api/vehicle/dashboard-list", auth=True, params={"nature": ""})
    except Exception as exc:
        state.token = ""
        state.user = {}
        mark_session_dirty()
        return jsonify(authenticated=False, csrf=state.csrf)
    mark_session_dirty()  # Renew the encrypted browser session on an explicit restore.
    return jsonify(authenticated=True,
                   csrf=state.csrf,
                   safetyPinSet=bool(state.safety_pin_hash),
                   user={k: state.user.get(k) for k in ("id", "nickName", "email")},
                   vehicles=payload.get("data") or [])


@app.get("/api/vehicles")
def vehicles():
    state = local_session()
    try:
        payload = call("GET", "api/vehicle/dashboard-list", auth=True, params={"nature": ""})
    except Exception as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(vehicles=payload.get("data") or [])


def pin_digest(pin: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200_000).hex()


@app.post("/api/safety-pin")
def safety_pin():
    state = local_session()
    if not state.token:
        return jsonify(error="Inicia sesión antes de configurar el PIN"), 401
    pin = str((request.get_json(silent=True) or {}).get("pin") or "")
    if not pin.isdigit() or not 6 <= len(pin) <= 12:
        return jsonify(error="El PIN debe contener entre 6 y 12 cifras"), 400
    state.safety_pin_salt = secrets.token_hex(16)
    state.safety_pin_hash = pin_digest(pin, state.safety_pin_salt)
    state.pin_failures = 0
    state.pin_locked_until = 0
    mark_session_dirty()
    return jsonify(ok=True, safetyPinSet=True)


def verify_safety_pin(state: RideSession, pin: str) -> bool:
    now = time.time()
    if not state.safety_pin_hash or now < state.pin_locked_until:
        return False
    valid = secrets.compare_digest(pin_digest(pin, state.safety_pin_salt), state.safety_pin_hash)
    if valid:
        state.pin_failures = 0
    else:
        state.pin_failures += 1
        if state.pin_failures >= 5:
            state.pin_locked_until = now + 900
            state.pin_failures = 0
    mark_session_dirty()
    return valid


def owns_vehicle(vehicle_id: str) -> bool:
    vehicles = call("GET", "api/vehicle/dashboard-list", auth=True, params={"nature": ""}).get("data") or []
    return any(str(vehicle.get("id") or "") == vehicle_id for vehicle in vehicles)


@app.get("/api/vehicles/<equipment_code>/location")
def location(equipment_code: str):
    if not equipment_code or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in equipment_code):
        return jsonify(error="Invalid equipment code"), 400
    try:
        payload = call("GET", f"api/vehicle/{equipment_code}/dashboard-heart-data", auth=True)
    except Exception as exc:
        return jsonify(error=str(exc)), 401
    data = payload.get("data") or {}
    allowed = ("id", "equipmentCode", "equipmentState", "electricLockState", "vehicleBrand",
               "vehicleModel", "licensePlateNumber", "latitude", "longitude", "address", "picture")
    return jsonify({key: data.get(key) for key in allowed})


def valid_identifier(value: str) -> bool:
    return bool(value) and all(ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in value)


@app.get("/api/vehicles/<equipment_code>/telemetry")
def telemetry(equipment_code: str):
    if not valid_identifier(equipment_code):
        return jsonify(error="Invalid equipment code"), 400
    vehicle, tires, vehicle_error, tire_error = {}, None, None, None
    try:
        vehicle = call("GET", f"api/data/vehicle/{equipment_code}", auth=True).get("data") or {}
    except Exception:
        # Some X-CAPE 1200 records have no metadata group IDs; try the lighter
        # read-only driving snapshot instead of exposing the backend SQL error.
        try:
            vehicle = call("GET", f"api/data/vehicle/{equipment_code}/drive-situation", auth=True).get("data") or {}
        except Exception:
            vehicle_error = "Telemetría no disponible para este modelo en el servidor de Moto Morini"
    try:
        tires = call("GET", f"api/data/tp/{equipment_code}", auth=True).get("data")
    except Exception:
        tire_error = "El servidor no ofrece datos de neumáticos para esta moto"
    return jsonify(vehicle=vehicle, tires=tires, vehicleError=vehicle_error, tireError=tire_error)


@app.get("/api/vehicles/<vehicle_id>/faults")
def faults(vehicle_id: str):
    if not valid_identifier(vehicle_id):
        return jsonify(error="Invalid vehicle id"), 400
    try:
        data = call("GET", f"api/vehicle/{vehicle_id}/fault-code", auth=True).get("data")
    except Exception:
        return jsonify(faults=None, available=False,
                       message="Los códigos de avería no están disponibles para este vehículo")
    return jsonify(faults=data, available=True)


@app.get("/api/vehicles/<vehicle_id>/capabilities")
def capabilities(vehicle_id: str):
    """Read manuals and server-advertised remote controls; sends no command."""
    if not valid_identifier(vehicle_id):
        return jsonify(error="Invalid vehicle id"), 400
    result: dict[str, Any] = {"manual": None, "control": [], "setting": []}
    errors: list[str] = []
    try:
        result["manual"] = call("GET", f"api/vehicle/{vehicle_id}/instructions-new", auth=True).get("data")
    except Exception:
        errors.append("manual")
    for remote_type in ("control", "setting"):
        try:
            result[remote_type] = call(
                "GET", f"api/vehicle/{vehicle_id}/remote-state/{remote_type}", auth=True
            ).get("data") or []
        except Exception:
            errors.append(remote_type)
    available = bool(result["control"] or result["setting"])
    return jsonify(capabilities=result, available=available, readOnly=True, unavailable=errors,
                   message=None if available else "El servidor no anuncia controles remotos para este vehículo")


SAFE_REMOTE_ACTIONS = {
    "vehicle_search": {"on"},
    "vehicle_shake_switch": {"on", "off"},
    "gh": {"on", "off"},
    "sh": {"on", "off"},
    "kos": {"on", "off"},
    "auto_light_sw": {"on", "off"},
    "tcs_mode": {"0", "1", "2", "3"},
    "driving_mode": {"0", "1", "2", "3", "4"},
}

REMOTE_SETTING_ACTIONS = {"auto_light_sw", "tcs_mode", "driving_mode"}


@app.post("/api/vehicles/<vehicle_id>/remote-actions")
def remote_action(vehicle_id: str):
    """Submit only explicitly enabled commands advertised for this vehicle."""
    if not valid_identifier(vehicle_id):
        return jsonify(error="Invalid vehicle id"), 400
    body = request.get_json(silent=True) or {}
    item_code = str(body.get("itemCode") or "")
    value = str(body.get("value") or "").lower()
    if item_code not in SAFE_REMOTE_ACTIONS or value not in SAFE_REMOTE_ACTIONS[item_code]:
        return jsonify(error="Esta función todavía no está habilitada"), 403
    try:
        if not owns_vehicle(vehicle_id):
            return jsonify(error="La motocicleta no pertenece a la cuenta autenticada"), 403
        if item_code == "kos":
            state = local_session()
            if not state.safety_pin_hash:
                return jsonify(error="Configura primero un PIN de seguridad para el arranque remoto", safetyPinRequired=True), 428
            if not verify_safety_pin(state, str(body.get("safetyPin") or "")):
                message = "PIN temporalmente bloqueado" if time.time() < state.pin_locked_until else "PIN de seguridad incorrecto"
                return jsonify(error=message, safetyPinRequired=True), 403
        operation_key = f"{private_ref(local_session().token)}:{vehicle_id}:{item_code}"
        with rate_lock:
            previous = remote_inflight.get(operation_key, 0)
            if time.monotonic() - previous < 5:
                return jsonify(error="Ya hay una orden equivalente en curso. Espera antes de repetirla."), 409
            remote_inflight[operation_key] = time.monotonic()
        controls = call("GET", f"api/vehicle/{vehicle_id}/remote-state/control", auth=True).get("data") or []
        remote_type = "setting" if item_code in REMOTE_SETTING_ACTIONS else "control"
        catalogue = (call("GET", f"api/vehicle/{vehicle_id}/remote-state/setting", auth=True).get("data") or []) if remote_type == "setting" else controls
        item = next((x for x in catalogue if x.get("itemCode") == item_code), None)
        if not item or str(item.get("state")).lower() != "on":
            return jsonify(error="El servidor no anuncia esta función como disponible"), 409
        if item_code in REMOTE_SETTING_ACTIONS:
            ignition = next((x for x in controls if x.get("itemCode") == "kos"), None)
            if ignition and str(ignition.get("value")).lower() == "on":
                return jsonify(error="Apaga primero la sesión de arranque remoto"), 409
            equipment_code = str(item.get("equipmentCode") or "")
            dashboard = call("GET", f"api/vehicle/{equipment_code}/dashboard-heart-data", auth=True).get("data") or {}
            contact = str(dashboard.get("electricLockState") or "").strip().lower()
            if contact in {"on", "1", "true", "open", "开", "开启"}:
                return jsonify(error="Los ajustes solo pueden cambiarse con la moto detenida y el contacto apagado"), 409
        if item_code == "kos" and value == "on":
            equipment_code = str(item.get("equipmentCode") or "")
            dashboard = call("GET", f"api/vehicle/{equipment_code}/dashboard-heart-data", auth=True).get("data") or {}
            contact = str(dashboard.get("electricLockState") or "").strip().lower()
            if contact in {"on", "1", "true", "open", "开", "开启"}:
                return jsonify(error="El arranque remoto requiere que el contacto físico esté apagado"), 409
        if item_code in {"gh", "sh"}:
            ignition = next((x for x in controls if x.get("itemCode") == "kos"), None)
            if not ignition or str(ignition.get("value")).lower() != "on":
                return jsonify(error="La calefacción remota requiere una sesión de arranque remoto"), 409
            equipment_code = str(item.get("equipmentCode") or "")
            dashboard = call("GET", f"api/vehicle/{equipment_code}/dashboard-heart-data", auth=True).get("data") or {}
            contact = str(dashboard.get("electricLockState") or "").strip().lower()
            if contact in {"on", "1", "true", "open", "开", "开启"}:
                return jsonify(error="La calefacción remota no está permitida con el contacto físico encendido"), 409
        allowed = {str(x.get("value")).lower() for x in item.get("standardValues") or []}
        if value not in allowed:
            return jsonify(error="El valor no figura en el catálogo de la moto"), 409
        result = call("POST", f"api/vehicle/{vehicle_id}/remote-state/{item['id']}",
                      auth=True, json={"value": value})
        record_id = str(result.get("data") or "")
        if not valid_identifier(record_id):
            raise RuntimeError("Ride MO no devolvió un identificador de operación válido")
        state = local_session()
        state.command_records.add(record_id)
        state.command_meta[record_id] = {"vehicleId": vehicle_id, "itemCode": item_code,
                                         "requestedValue": value,
                                         "previousValue": str(item.get("value") or "")}
        while len(state.command_meta) > 8:
            oldest = next(iter(state.command_meta))
            state.command_meta.pop(oldest, None)
            state.command_records.discard(oldest)
        mark_session_dirty()
        remote_audit("submitted", record=private_ref(record_id), itemCode=item_code,
                     requestedValue=value, previousValue=item.get("value"),
                     advertisedState=item.get("state"),
                     remoteStartSession=(str((next((x for x in controls if x.get("itemCode") == "kos"), {}) or {}).get("value") or "").lower() == "on"))
        return jsonify(recordId=record_id, state="pending")
    except Exception as exc:
        remote_audit("submission_error", itemCode=item_code, requestedValue=value,
                     error=str(exc))
        return jsonify(error=str(exc)), 400


@app.get("/api/remote-actions/<record_id>")
def remote_action_result(record_id: str):
    state = local_session()
    if not valid_identifier(record_id) or record_id not in state.command_records:
        return jsonify(error="Operación desconocida"), 404
    try:
        data = call("GET", f"api/command/record/{record_id}", auth=True).get("data") or {}
        response: dict[str, Any] = {"commandState": data.get("commandState"),
                                    "sendState": data.get("sendState"), "result": data.get("result")}
        meta = state.command_meta.get(record_id) or {}
        command_state = str(data.get("commandState") or "").lower()
        if meta and command_state in {"success", "successful", "complete", "fail", "failed", "failure", "error"}:
            remote_type = "setting" if meta["itemCode"] in REMOTE_SETTING_ACTIONS else "control"
            items = call("GET", f"api/vehicle/{meta['vehicleId']}/remote-state/{remote_type}", auth=True).get("data") or []
            item = next((x for x in items if x.get("itemCode") == meta["itemCode"]), None)
            observed = str((item or {}).get("value") or "")
            response["observedValue"] = observed
            response["stateMatches"] = observed.lower() == meta["requestedValue"].lower()
        remote_audit("result", record=private_ref(record_id), itemCode=meta.get("itemCode"),
                     requestedValue=meta.get("requestedValue"), commandState=response.get("commandState"),
                     sendState=response.get("sendState"), result=response.get("result"),
                     observedValue=response.get("observedValue"), stateMatches=response.get("stateMatches"))
        return jsonify(response)
    except Exception as exc:
        remote_audit("result_error", record=private_ref(record_id), error=str(exc))
        return jsonify(error=str(exc)), 400


@app.get("/api/vehicles/<vehicle_id>/trips")
def trips(vehicle_id: str):
    if not valid_identifier(vehicle_id):
        return jsonify(error="Invalid vehicle id"), 400
    try:
        data = call("GET", "api/customer/driving/page-list", auth=True,
                    params={"vehicleId": vehicle_id, "pageNum": 1, "pageSize": 10}).get("data") or {}
    except Exception as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(trips=data)


@app.get("/api/vehicles/<vehicle_id>/movement-alerts")
def movement_alerts(vehicle_id: str):
    """Return vibration alerts without changing their read state."""
    if not valid_identifier(vehicle_id):
        return jsonify(error="Identificador de vehículo no válido"), 400
    last_id = str(request.args.get("lastId") or "").strip()
    if last_id and not valid_identifier(last_id):
        return jsonify(error="Identificador de aviso no válido"), 400
    limit = 20
    try:
        payload = call("GET", f"api/vehicle/message/{vehicle_id}/more-list", auth=True,
                       params={"type": "vehicleShake", "lastId": last_id or None, "limit": limit})
        page = payload.get("data") or {}
        records = page if isinstance(page, list) else page.get("records") or []
        alerts = [{key: record.get(key) for key in ("id", "type", "content", "state", "createTime")}
                  for record in records if isinstance(record, dict)]
        next_last_id = alerts[-1].get("id") if alerts else None
        return jsonify(alerts=alerts, nextLastId=next_last_id,
                       hasMore=bool(next_last_id and len(alerts) >= limit),
                       total=page.get("total") if isinstance(page, dict) else None, readOnly=True)
    except Exception as exc:
        return jsonify(error=str(exc)), 400


@app.get("/api/trips/<trajectory_id>")
def trip_detail(trajectory_id: str):
    if not valid_identifier(trajectory_id):
        return jsonify(error="Invalid trajectory id"), 400
    try:
        data = call("GET", f"api/customer/driving/{trajectory_id}", auth=True).get("data") or {}
    except Exception as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(trip=data)


@app.post("/api/logout")
def logout():
    state = local_session()
    state.password = state.token = ""
    state.user.clear()
    state.command_records.clear()
    state.command_meta.clear()
    state.safety_pin_hash = state.safety_pin_salt = ""
    state.pin_failures = 0
    state.pin_locked_until = 0
    state.privacy_accepted_at = 0
    g.clear_ride_cookie = True
    g.ride_dirty = False
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)
