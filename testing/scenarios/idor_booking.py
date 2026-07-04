"""
IDOR Test - Booking Endpoints
Tests for Insecure Direct Object Reference on /booking.json/{id}
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY
from config import TEST_CODES


ENDPOINTS = [
    "/booking.json/{id}/summary",
    "/booking.json/booking/{code}",
    "/booking.json/activity-booking/{id}",
    "/booking.json/route-booking/{id}",
    "/booking.json/accommodation-booking/{id}",
]

TEST_IDS = [1, 2, 3, 5, 10, 50, 100, 999]


def run(client, reporter):
    """Test booking endpoints for IDOR."""
    print("\n[IDOR] Testing booking endpoints...")

    # Test numeric IDs
    for endpoint_template in ["/booking.json/{id}/summary",
                               "/booking.json/activity-booking/{id}",
                               "/booking.json/route-booking/{id}",
                               "/booking.json/accommodation-booking/{id}"]:
        for test_id in TEST_IDS:
            endpoint = endpoint_template.replace("{id}", str(test_id))
            try:
                r = client.get(endpoint)
                if r.status_code == 200:
                    data = r.json() if "json" in r.headers.get("content-type", "") else None
                    if data and isinstance(data, dict):
                        keys = list(data.keys())
                        sensitive_fields = []
                        for key in keys:
                            val = str(data.get(key, "")).lower()
                            if any(x in val for x in ["email", "phone", "address", "name", "guest", "payment", "total", "price"]):
                                sensitive_fields.append(key)

                        if sensitive_fields:
                            reporter.add(Finding(
                                title=f"IDOR - Booking {test_id} exposes PII via {endpoint_template.split('/')[-2]}",
                                severity=SEVERITY["HIGH"],
                                endpoint=endpoint,
                                method="GET",
                                description=f"Booking endpoint leaks PII fields: {sensitive_fields}",
                                evidence={
                                    "status": r.status_code,
                                    "sensitive_fields": sensitive_fields,
                                    "response_keys": keys[:10],
                                },
                                impact="Attacker can access other users' booking data including PII and payment info",
                                remediation="Implement booking-level authorization (verify user owns the booking)",
                                cwe="CWE-639",
                                tags=["idor", "booking", "pii"],
                            ))
                        print(f"    {endpoint}: {r.status_code} (keys: {keys[:5]})")
                elif r.status_code in [401, 404]:
                    pass
                else:
                    print(f"    {endpoint}: {r.status_code}")
            except Exception as e:
                print(f"    Error: {str(e)[:80]}")

    # Test confirmation code enumeration
    print("\n[IDOR] Testing confirmation code enumeration...")
    for code in TEST_CODES:
        endpoint = f"/booking.json/booking/{code}"
        try:
            r = client.get(endpoint)
            if r.status_code == 200:
                data = r.json() if "json" in r.headers.get("content-type", "") else None
                if data and isinstance(data, dict) and data:
                    reporter.add(Finding(
                        title=f"IDOR - Booking accessible via code: {code}",
                        severity=SEVERITY["HIGH"],
                        endpoint=endpoint,
                        method="GET",
                        description=f"Booking data accessible via confirmation code '{code}'",
                        evidence={
                            "status": r.status_code,
                            "response_keys": list(data.keys())[:10],
                        },
                        impact="Attacker can access booking data via code enumeration/brute-force",
                        remediation="Implement rate limiting and authorization checks on confirmation codes",
                        cwe="CWE-639",
                        tags=["idor", "booking", "enumeration"],
                    ))
            elif r.status_code not in [401, 404]:
                print(f"    {endpoint}: {r.status_code}")
        except:
            pass
