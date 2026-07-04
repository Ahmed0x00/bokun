"""
IDOR Test - Accommodation Endpoints
Tests for Insecure Direct Object Reference on /accommodation.json/{id}
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY


ENDPOINTS = [
    "/accommodation.json/{id}",
    "/accommodation.json/{id}/rooms",
    "/accommodation.json/{id}/check-availability",
]

TEST_IDS = [1, 2, 3, 5, 10, 50, 100, 999, 999999]


def run(client, reporter):
    """Test accommodation endpoints for IDOR."""
    print("\n[IDOR] Testing accommodation endpoints...")

    for endpoint_template in ENDPOINTS:
        for test_id in TEST_IDS:
            endpoint = endpoint_template.replace("{id}", str(test_id))

            try:
                if "check-availability" in endpoint:
                    # POST endpoint with body
                    r = client.post(
                        endpoint,
                        json_body={
                            "checkIn": "2026-07-15",
                            "checkOut": "2026-07-20",
                            "rooms": 1,
                        }
                    )
                else:
                    r = client.get(endpoint)

                if r.status_code == 200:
                    data = r.json() if "json" in r.headers.get("content-type", "") else None

                    if data and isinstance(data, dict):
                        keys = list(data.keys())
                        sensitive_fields = []
                        for key in keys:
                            val = str(data.get(key, "")).lower()
                            if any(x in val for x in ["email", "phone", "address", "price", "cost", "guest"]):
                                sensitive_fields.append(key)

                        if sensitive_fields:
                            reporter.add(Finding(
                                title=f"IDOR - Accommodation {test_id} exposes sensitive data",
                                severity=SEVERITY["MEDIUM"],
                                endpoint=endpoint,
                                method="GET" if "check-availability" not in endpoint else "POST",
                                description=f"Accommodation endpoint returns sensitive fields: {sensitive_fields}",
                                evidence={
                                    "status": r.status_code,
                                    "response_keys": keys[:10],
                                    "sensitive_fields": sensitive_fields,
                                },
                                impact="Attacker can access other users' accommodation data",
                                remediation="Implement object-level authorization checks",
                                cwe="CWE-639",
                                tags=["idor", "accommodation"],
                            ))

                        print(f"    {endpoint}: {r.status_code} (keys: {keys[:5]})")
                    else:
                        print(f"    {endpoint}: {r.status_code}")

                elif r.status_code in [401, 404]:
                    pass  # Expected
                else:
                    print(f"    {endpoint}: {r.status_code}")

            except Exception as e:
                print(f"    Error: {str(e)[:80]}")

    # Test slug-based access (might bypass IDOR checks)
    print("\n[IDOR] Testing slug-based access...")
    test_slugs = ["test", "demo", "hotel", "apartment", " Reykjavik"]
    for slug in test_slugs:
        try:
            r = client.get(f"/accommodation.json/slug/{slug}")
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and data:
                    reporter.add(Finding(
                        title=f"IDOR - Accommodation accessible via slug: {slug}",
                        severity=SEVERITY["LOW"],
                        endpoint=f"/accommodation.json/slug/{slug}",
                        method="GET",
                        description=f"Accommodation data accessible via predictable slug '{slug}'",
                        evidence={"status": r.status_code, "keys": list(data.keys())[:5]},
                        impact="Attacker can access accommodation data via slug enumeration",
                        remediation="Implement authorization checks on slug-based lookups",
                        cwe="CWE-639",
                        tags=["idor", "accommodation", "slug"],
                    ))
        except:
            pass
