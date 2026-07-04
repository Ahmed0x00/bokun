"""
IDOR Test - Activity Endpoints
Tests for Insecure Direct Object Reference on /activity.json/{id}
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY


ENDPOINTS = [
    "/activity.json/{id}",
    "/activity.json/{id}/availabilities",
    "/activity.json/{id}/price-list",
    "/activity.json/{id}/pickup-places",
    "/activity.json/{id}/upcoming-availabilities/5",
]

TEST_IDS = [1, 2, 3, 5, 10, 50, 100, 999, 999999]


def run(client, reporter):
    """Test activity endpoints for IDOR."""
    print("\n[IDOR] Testing activity endpoints...")

    for endpoint_template in ENDPOINTS:
        for test_id in TEST_IDS:
            endpoint = endpoint_template.replace("{id}", str(test_id))

            try:
                # Test with valid auth
                r = client.get(endpoint)

                if r.status_code == 200:
                    data = r.json() if "json" in r.headers.get("content-type", "") else None

                    # Check if we got actual data
                    if data and isinstance(data, dict):
                        keys = list(data.keys())
                        # Look for sensitive fields
                        sensitive_fields = []
                        for key in keys:
                            val = str(data.get(key, "")).lower()
                            if any(x in val for x in ["email", "phone", "address", "price", "cost"]):
                                sensitive_fields.append(key)

                        if sensitive_fields:
                            reporter.add(Finding(
                                title=f"IDOR - Activity {test_id} exposes sensitive data",
                                severity=SEVERITY["MEDIUM"],
                                endpoint=endpoint,
                                method="GET",
                                description=f"Activity endpoint returns sensitive fields: {sensitive_fields}",
                                evidence={
                                    "status": r.status_code,
                                    "response_keys": keys[:10],
                                    "sensitive_fields": sensitive_fields,
                                    "sample_data": {k: data[k] for k in sensitive_fields[:3]},
                                },
                                impact="Attacker can access other users' activity data including pricing and personal information",
                                remediation="Implement object-level authorization checks",
                                cwe="CWE-639",
                                tags=["idor", "activity"],
                            ))

                        # Check if ID enumeration works (sequential IDs return data)
                        print(f"    {endpoint}: {r.status_code} (keys: {keys[:5]})")
                    else:
                        print(f"    {endpoint}: {r.status_code} (non-dict response)")

                elif r.status_code == 401:
                    pass  # Expected - auth required
                elif r.status_code == 404:
                    pass  # Expected - ID doesn't exist
                else:
                    print(f"    {endpoint}: {r.status_code}")

            except Exception as e:
                print(f"    Error testing {endpoint}: {str(e)[:80]}")

    # Test sequential ID enumeration
    print("\n[IDOR] Testing sequential ID enumeration...")
    sequential_data = []
    for test_id in range(1, 20):
        try:
            r = client.get(f"/activity.json/{test_id}")
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    sequential_data.append({
                        "id": test_id,
                        "keys": list(data.keys())[:5],
                        "has_data": bool(data),
                    })
        except:
            pass

    if len(sequential_data) > 3:
        reporter.add(Finding(
            title="IDOR - Sequential Activity ID Enumeration",
            severity=SEVERITY["LOW"],
            endpoint="/activity.json/{id}",
            method="GET",
            description=f"Sequential activity IDs (1-19) return data for {len(sequential_data)} IDs, enabling enumeration.",
            evidence={
                "enumerated_ids": [d["id"] for d in sequential_data],
                "total_found": len(sequential_data),
            },
            impact="Attacker can enumerate all activities by iterating through sequential IDs",
            remediation="Use UUIDs instead of sequential integers, or implement rate limiting",
            cwe="CWE-639",
            tags=["idor", "enumeration", "activity"],
        ))
