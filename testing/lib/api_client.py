"""
Bokun API Client - HTTP wrapper for API testing
"""
import httpx
import json
import time
import hashlib
import hmac
import base64
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    ACCESS_KEY, SECRET_KEY, BASE_URL, TIMEOUT, FOLLOW_REDIRECTS,
    VERIFY_SSL, DEFAULT_HEADERS, RATE_LIMIT, LOG_DIR
)


class BokunClient:
    """HTTP client for Bokun API with auth and logging."""

    def __init__(self, base_url: str = None, access_key: str = None, secret_key: str = None):
        self.base_url = base_url or BASE_URL
        self.access_key = access_key or ACCESS_KEY
        self.secret_key = secret_key or SECRET_KEY
        self.client = httpx.Client(
            follow_redirects=FOLLOW_REDIRECTS,
            timeout=TIMEOUT,
            verify=VERIFY_SSL,
        )
        self.request_log = []
        self._last_request_time = 0

    def _rate_limit(self):
        """Simple rate limiter."""
        elapsed = time.time() - self._last_request_time
        if elapsed < 1.0 / RATE_LIMIT:
            time.sleep(1.0 / RATE_LIMIT - elapsed)
        self._last_request_time = time.time()

    def _get_auth_headers(self, method: str, path: str) -> Dict[str, str]:
        """Return auth headers with HMAC-SHA1 signature."""
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        # Signature = HMAC-SHA1(secretKey, date + accessKey + method + path)
        message = f"{date_str}{self.access_key}{method.upper()}{path}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha1
        ).digest()
        sig_b64 = base64.b64encode(signature).decode()
        return {
            "X-Bokun-Date": date_str,
            "X-Bokun-AccessKey": self.access_key,
            "X-Bokun-Signature": sig_b64,
        }

    def _log_request(self, method: str, url: str, status: int, response_size: int, duration: float):
        """Log request to memory and file."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "url": url,
            "status": status,
            "response_size": response_size,
            "duration_ms": round(duration * 1000, 2),
        }
        self.request_log.append(entry)

        # Write to log file
        log_path = Path(LOG_DIR) / "requests.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def request(
        self,
        method: str,
        path: str,
        params: Dict = None,
        json_body: Any = None,
        headers: Dict = None,
        use_auth: bool = True,
    ) -> httpx.Response:
        """Make an API request with auth and logging."""
        self._rate_limit()

        url = f"{self.base_url}{path}"
        req_headers = {**DEFAULT_HEADERS}
        if use_auth:
            req_headers.update(self._get_auth_headers(method, path))
        if headers:
            req_headers.update(headers)

        start = time.time()
        try:
            response = self.client.request(
                method=method,
                url=url,
                params=params,
                json=json_body,
                headers=req_headers,
            )
            duration = time.time() - start
            self._log_request(method, url, response.status_code, len(response.content), duration)
            return response
        except Exception as e:
            duration = time.time() - start
            self._log_request(method, url, 0, 0, duration)
            raise

    def get(self, path: str, **kwargs) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> httpx.Response:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", path, **kwargs)

    def patch(self, path: str, **kwargs) -> httpx.Response:
        return self.request("PATCH", path, **kwargs)

    # ============================================================
    # Convenience methods for specific endpoint categories
    # ============================================================

    def activity(self, activity_id: int) -> httpx.Response:
        return self.get(f"/activity.json/{activity_id}")

    def activity_availability(self, activity_id: int, start: str, end: str) -> httpx.Response:
        return self.get(
            f"/activity.json/{activity_id}/availabilities",
            params={"start": start, "end": end}
        )

    def accommodation(self, accom_id: int) -> httpx.Response:
        return self.get(f"/accommodation.json/{accom_id}")

    def route(self, route_id: int) -> httpx.Response:
        return self.get(f"/route.json/{route_id}")

    def booking_summary(self, booking_id: int) -> httpx.Response:
        return self.get(f"/booking.json/{booking_id}/summary")

    def booking_by_code(self, code: str) -> httpx.Response:
        return self.get(f"/booking.json/booking/{code}")

    def cart(self, session_id: str) -> httpx.Response:
        return self.get(f"/cart.json/{session_id}")

    def shopping_cart(self, session_id: str) -> httpx.Response:
        return self.get(f"/shopping-cart.json/session/{session_id}")

    def product_list(self, list_id: int) -> httpx.Response:
        return self.get(f"/product-list.json/{list_id}")

    def active_ids(self) -> httpx.Response:
        return self.get("/activity.json/active-ids")

    def currency_find_all(self) -> httpx.Response:
        return self.get("/currency.json/findAll")

    def language_find_all(self) -> httpx.Response:
        return self.get("/language.json/findAll")

    # ============================================================
    # No-auth requests (for testing auth bypass)
    # ============================================================

    def get_no_auth(self, path: str, **kwargs) -> httpx.Response:
        """Request without auth headers."""
        return self.request("GET", path, use_auth=False, **kwargs)

    def post_no_auth(self, path: str, **kwargs) -> httpx.Response:
        """Request without auth headers."""
        return self.request("POST", path, use_auth=False, **kwargs)

    def get_wrong_auth(self, path: str, **kwargs) -> httpx.Response:
        """Request with wrong/dummy auth headers (HMAC signed with wrong keys)."""
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        wrong_access = "wrong_key_123456789012345678901234"
        wrong_secret = "wrong_secret_678901234567890123456789"
        message = f"{date_str}{wrong_access}GET{path}"
        signature = hmac.new(
            wrong_secret.encode(),
            message.encode(),
            hashlib.sha1
        ).digest()
        sig_b64 = base64.b64encode(signature).decode()
        return self.request(
            "GET", path,
            headers={
                "X-Bokun-Date": date_str,
                "X-Bokun-AccessKey": wrong_access,
                "X-Bokun-Signature": sig_b64,
            },
            **kwargs
        )

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
