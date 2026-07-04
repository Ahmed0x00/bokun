"""
Auth Bypass Tests
Tests for authentication bypass on various endpoints
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY


# Endpoints that should require auth
AUTH_REQUIRED_ENDPOINTS = [
    ("GET", "/activity.json/active-ids"),
    ("GET", "/activity.json/1"),
    ("GET", "/accommodation.json/1"),
    ("GET", "/route.json/list"),
    ("GET", "/currency.json/findAll"),
    ("GET", "/language.json/findAll"),
    ("GET", "/booking.json/1/summary"),
    ("GET", "/cart.json/test123"),
    ("POST", "/activity.json/search"),
    ("POST", "/accommodation.json/search"),
]

# Different auth bypass techniques
BYPASS_TECHNIQUES = [
    # Header variations
    {"headers": {"X-Bokun-AccessKey": "test"}},
    {"headers": {"Authorization": "Bearer test"}},
    {"headers": {"Authorization": "Basic dGVzdDp0ZXN0"}},  # test:test
    {"headers": {"X-Forwarded-For": "127.0.0.1"}},
    {"headers": {"X-Real-IP": "127.0.0.1"}},
    {"headers": {"X-Original-URL": "/admin"}},
    {"headers": {"X-Rewrite-URL": "/admin"}},
    # Query parameter auth
    {"params": {"access_key": "test"}},
    {"params": {"api_key": "test"}},
    {"params": {"token": "test"}},
    # Empty auth
    {"headers": {"access-key": "", "secret-key": ""}},
    {"headers": {"access-key": "", "secret-key": ""}},
]


def run(client, reporter):
    """Test for auth bypass vulnerabilities."""
    print("\n[AUTH] Testing authentication bypass...")

    for method, endpoint in AUTH_REQUIRED_ENDPOINTS:
        # Test 1: No auth headers
        try:
            if method == "GET":
                r = client.get_no_auth(endpoint)
            else:
                r = client.post_no_auth(endpoint)

            if r.status_code == 200:
                reporter.add(Finding(
                    title=f"Auth Bypass - No auth on {endpoint}",
                    severity=SEVERITY["CRITICAL"],
                    endpoint=endpoint,
                    method=method,
                    description=f"Endpoint accessible without any authentication headers",
                    evidence={
                        "status": r.status_code,
                        "response_size": len(r.content),
                        "content_type": r.headers.get("content-type", ""),
                    },
                    impact="Complete authentication bypass - attacker can access all API endpoints",
                    remediation="Enforce authentication on all endpoints",
                    cwe="CWE-306",
                    tags=["auth-bypass", "critical"],
                ))
            elif r.status_code not in [401, 403]:
                print(f"    No auth {endpoint}: {r.status_code}")
        except:
            pass

        # Test 2: Wrong auth headers
        try:
            if method == "GET":
                r = client.get_wrong_auth(endpoint)
            else:
                r = client.post_no_auth(endpoint, headers={"access-key": "wrong", "secret-key": "wrong"})

            if r.status_code == 200:
                reporter.add(Finding(
                    title=f"Auth Bypass - Wrong auth accepted on {endpoint}",
                    severity=SEVERITY["CRITICAL"],
                    endpoint=endpoint,
                    method=method,
                    description=f"Endpoint accepts invalid authentication credentials",
                    evidence={
                        "status": r.status_code,
                        "response_size": len(r.content),
                    },
                    impact="Attacker can access API with stolen/guessed credentials",
                    remediation="Validate credentials against database",
                    cwe="CWE-287",
                    tags=["auth-bypass", "critical"],
                ))
        except:
            pass

        # Test 3: Bypass techniques
        for technique in BYPASS_TECHNIQUES:
            try:
                if method == "GET":
                    r = client.get(endpoint, **technique, use_auth=False)
                else:
                    r = client.post(endpoint, **technique, use_auth=False)

                if r.status_code == 200:
                    reporter.add(Finding(
                        title=f"Auth Bypass via {list(technique.keys())[0]} on {endpoint}",
                        severity=SEVERITY["HIGH"],
                        endpoint=endpoint,
                        method=method,
                        description=f"Endpoint accessible via {technique}",
                        evidence={
                            "technique": technique,
                            "status": r.status_code,
                        },
                        impact="Authentication bypass via header manipulation",
                        remediation="Remove trust in client-supplied headers",
                        cwe="CWE-287",
                        tags=["auth-bypass", "header-injection"],
                    ))
                    break  # Found bypass, no need to test more techniques
            except:
                pass

    # Test for debug endpoints
    print("\n[AUTH] Testing debug/admin endpoints...")
    debug_endpoints = [
        "/debug",
        "/admin",
        "/internal",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/swagger-ui.html",
        "/api-docs",
        "/graphql",
        "/graphiql",
    ]

    for endpoint in debug_endpoints:
        try:
            r = client.get_no_auth(endpoint)
            if r.status_code == 200:
                reporter.add(Finding(
                    title=f"Debug endpoint accessible: {endpoint}",
                    severity=SEVERITY["MEDIUM"],
                    endpoint=endpoint,
                    method="GET",
                    description=f"Debug/admin endpoint accessible without authentication",
                    evidence={"status": r.status_code, "response_size": len(r.content)},
                    impact="Information disclosure, potential for further exploitation",
                    remediation="Disable debug endpoints in production",
                    cwe="CWE-215",
                    tags=["info-disclosure", "debug"],
                ))
        except:
            pass
