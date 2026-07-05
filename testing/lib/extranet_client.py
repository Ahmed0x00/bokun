"""
Extranet Cookie-Based Client
For testing extranet endpoints that require browser session auth
"""
import httpx
import json
import time
from typing import Optional, Dict, Any
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import (
    BASE_URLS, FRONTEND_URLS, TIMEOUT, FOLLOW_REDIRECTS,
    VERIFY_SSL, DEFAULT_HEADERS, RATE_LIMIT, LOG_DIR
)


class ExtranetClient:
    """HTTP client for extranet endpoints with cookie-based auth."""

    def __init__(self, session_cookie: str = None, base_url: str = None):
        """
        Initialize extranet client.
        
        Args:
            session_cookie: The PLAY_SESSION cookie value from browser
            base_url: Base URL (default: https://bokuntest.com)
        """
        self.base_url = base_url or FRONTEND_URLS.get("extranet", "https://extranet.bokuntest.com")
        self.session_cookie = session_cookie
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

    def _get_headers(self) -> Dict[str, str]:
        """Return headers for extranet requests."""
        headers = {
            **DEFAULT_HEADERS,
            "X-Bokun-Fetch": "true",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.session_cookie:
            headers["Cookie"] = f"PLAY_SESSION={self.session_cookie}"
        return headers

    def _log_request(self, method: str, url: str, status: int, response_size: int, duration: float):
        """Log request."""
        entry = {
            "timestamp": time.time(),
            "method": method,
            "url": url,
            "status": status,
            "response_size": response_size,
            "duration_ms": round(duration * 1000, 2),
        }
        self.request_log.append(entry)

    def request(
        self,
        method: str,
        path: str,
        params: Dict = None,
        json_body: Any = None,
        json: Any = None,
        data: Any = None,
        headers: Dict = None,
    ) -> httpx.Response:
        """Make an extranet request with cookie auth."""
        self._rate_limit()

        url = f"{self.base_url}{path}"
        req_headers = self._get_headers()
        if headers:
            req_headers.update(headers)

        # Use json_body if provided, otherwise use json parameter
        json_data = json_body if json_body is not None else json
        
        start = time.time()
        try:
            response = self.client.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                data=data,
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

    def close(self):
        self.client.close()


def extract_session_from_cookies(cookie_string: str) -> Optional[str]:
    """Extract PLAY_SESSION from cookie string."""
    if not cookie_string:
        return None
    
    for part in cookie_string.split(";"):
        part = part.strip()
        if part.startswith("PLAY_SESSION="):
            return part.split("=", 1)[1]
    return None


def main():
    """Test extranet endpoints with cookie auth."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Extranet Cookie Auth Test")
    parser.add_argument("--cookie", "-c", help="PLAY_SESSION cookie value")
    parser.add_argument("--cookie-file", "-f", help="File containing cookie string")
    args = parser.parse_args()
    
    # Get cookie
    session_cookie = None
    if args.cookie:
        session_cookie = args.cookie
    elif args.cookie_file:
        with open(args.cookie_file) as f:
            cookie_string = f.read().strip()
            session_cookie = extract_session_from_cookies(cookie_string)
    
    if not session_cookie:
        print("[!] No session cookie provided")
        print("[!] Usage: python extranet_client.py --cookie <PLAY_SESSION_VALUE>")
        print("[!] Or: python extranet_client.py --cookie-file <cookie_file>")
        print("\n[INFO] To get the cookie:")
        print("  1. Login to https://extranet.bokuntest.com")
        print("  2. Open DevTools -> Application -> Cookies")
        print("  3. Copy the PLAY_SESSION value")
        return
    
    print("="*60)
    print("EXTRANET COOKIE AUTH TEST")
    print("="*60)
    
    client = ExtranetClient(session_cookie=session_cookie)
    
    # Test endpoints
    test_endpoints = [
        # Admin endpoints
        ("GET", "/admin/users/json"),
        ("GET", "/admin/system-settings"),
        ("GET", "/admin/white-labels"),
        
        # User management
        ("GET", "/user-management/roles"),
        ("GET", "/user-management/agents"),
        ("GET", "/user-management/users"),
        
        # Connections
        ("GET", "/connections/api-keys"),
        ("GET", "/connections/mcp"),
        
        # Vendor management
        ("GET", "/vendor-management/email-settings"),
        ("GET", "/vendor-management/contact-info"),
        ("GET", "/vendor-management/company-profile"),
        
        # SaaS
        ("GET", "/saas/subscription-status"),
        
        # Products
        ("GET", "/products/activities/json"),
        
        # Bookings
        ("GET", "/bookings/agent"),
    ]
    
    print(f"\nTesting {len(test_endpoints)} endpoints...")
    print("-"*60)
    
    for method, endpoint in test_endpoints:
        try:
            if method == "GET":
                r = client.get(endpoint)
            else:
                r = client.post(endpoint, json_body={})
            
            ct = r.headers.get("content-type", "")
            is_json = "json" in ct
            
            status_icon = "+" if r.status_code == 200 else "-"
            print(f"[{status_icon}] {method} {endpoint}: {r.status_code} ({ct[:20]})")
            
            if r.status_code == 200 and is_json:
                try:
                    data = r.json()
                    if isinstance(data, list):
                        print(f"    -> List with {len(data)} items")
                    elif isinstance(data, dict):
                        print(f"    -> Object with keys: {list(data.keys())[:5]}")
                except:
                    pass
                    
        except Exception as e:
            print(f"[!] {method} {endpoint}: Error - {str(e)[:50]}")
    
    client.close()


if __name__ == "__main__":
    main()
