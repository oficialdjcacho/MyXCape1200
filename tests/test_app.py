import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import app as web


class WebSecurityTests(unittest.TestCase):
    def setUp(self):
        web.rate_buckets.clear()
        web.remote_inflight.clear()
        self.client = web.app.test_client()

    def state_client(self, token="token-a", csrf="csrf-a"):
        state = web.RideSession(token=token, csrf=csrf, base_url="https://example.invalid/v2")
        client = web.app.test_client()
        client.set_cookie(web.AUTH_COOKIE, web.encode_state(state))
        return client, state

    def test_security_headers_and_static_cache(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("max-age=31536000", page.headers["Strict-Transport-Security"])
        self.assertIn("default-src 'self'", page.headers["Content-Security-Policy"])
        self.assertEqual(page.headers["Cache-Control"], "no-store")
        static = self.client.get("/static/favicon.svg")
        self.assertIn("immutable", static.headers["Cache-Control"])
        static.close()

    def test_csrf_rejects_state_change(self):
        response = self.client.post("/api/logout", json={})
        self.assertEqual(response.status_code, 403)

    def test_login_requires_privacy_acceptance(self):
        client, state = self.state_client(token="", csrf="privacy-csrf")
        response = client.post("/api/login", json={"email": "a@example.com", "password": "x"},
                               headers={"X-CSRF-Token": state.csrf})
        self.assertEqual(response.status_code, 400)

    def test_password_never_serialized(self):
        state = web.RideSession(password="never-store-this", token="token")
        self.assertNotIn("password", web.state_payload(state))
        self.assertNotIn(b"never-store-this", web.encode_state(state).encode())

    def test_safety_pin_is_isolated_per_browser(self):
        first, state = self.state_client()
        response = first.post("/api/safety-pin", json={"pin": "123456"},
                              headers={"X-CSRF-Token": state.csrf})
        self.assertEqual(response.status_code, 200)
        saved = web.decode_state(first.get_cookie(web.AUTH_COOKIE).value)
        self.assertTrue(saved.safety_pin_hash)
        second, second_state = self.state_client(token="token-b", csrf="csrf-b")
        other = web.decode_state(second.get_cookie(web.AUTH_COOKIE).value)
        self.assertFalse(other.safety_pin_hash)

    def test_expired_cookie_is_rejected(self):
        state = web.RideSession(token="expired", csrf="csrf")
        encoded = web.encode_state(state)
        original = web.AUTH_COOKIE_MAX_AGE
        try:
            web.AUTH_COOKIE_MAX_AGE = -1
            self.assertFalse(web.decode_state(encoded).token)
        finally:
            web.AUTH_COOKIE_MAX_AGE = original

    def test_trips_always_returns_json(self):
        client, _ = self.state_client()
        with patch("app.call", return_value={"data": {"records": [{"id": "trip-1"}]}}):
            response = client.get("/api/vehicles/vehicle-1/trips")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["trips"]["records"][0]["id"], "trip-1")

    def test_remote_action_rejects_unowned_vehicle(self):
        client, state = self.state_client()
        with patch("app.owns_vehicle", return_value=False):
            response = client.post("/api/vehicles/not-mine/remote-actions",
                                   json={"itemCode": "vehicle_search", "value": "on"},
                                   headers={"X-CSRF-Token": state.csrf})
        self.assertEqual(response.status_code, 403)

    def test_health_is_safe_under_concurrency(self):
        def request_health(_):
            return web.app.test_client().get("/health").status_code
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(request_health, range(24))), [200] * 24)


if __name__ == "__main__":
    unittest.main()
