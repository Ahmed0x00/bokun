"""
IDOR Test - Cart/Session Endpoints
Tests for Insecure Direct Object Reference on cart and session endpoints
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY
from config import TEST_SESSIONS


def run(client, reporter):
    """Test cart/session endpoints for IDOR."""
    print("\n[IDOR] Testing cart/session endpoints...")

    # Test cart.json/{sessionId}
    for session_id in TEST_SESSIONS:
        try:
            r = client.get(f"/cart.json/{session_id}")
            if r.status_code == 200:
                data = r.json() if "json" in r.headers.get("content-type", "") else None
                if data and isinstance(data, dict) and data:
                    reporter.add(Finding(
                        title=f"IDOR - Cart accessible via session: {session_id[:30]}",
                        severity=SEVERITY["MEDIUM"],
                        endpoint=f"/cart.json/{session_id}",
                        method="GET",
                        description=f"Cart data accessible via session ID '{session_id[:50]}'",
                        evidence={
                            "status": r.status_code,
                            "response_keys": list(data.keys())[:10],
                        },
                        impact="Attacker can access other users' shopping carts",
                        remediation="Implement session validation and authorization",
                        cwe="CWE-639",
                        tags=["idor", "cart", "session"],
                    ))
            elif r.status_code not in [401, 404]:
                print(f"    /cart.json/{session_id[:20]}: {r.status_code}")
        except:
            pass

    # Test shopping-cart.json/session/{sessionId}
    for session_id in TEST_SESSIONS:
        try:
            r = client.get(f"/shopping-cart.json/session/{session_id}")
            if r.status_code == 200:
                data = r.json() if "json" in r.headers.get("content-type", "") else None
                if data and isinstance(data, dict) and data:
                    reporter.add(Finding(
                        title=f"IDOR - Shopping cart accessible via session: {session_id[:30]}",
                        severity=SEVERITY["MEDIUM"],
                        endpoint=f"/shopping-cart.json/session/{session_id}",
                        method="GET",
                        description=f"Shopping cart data accessible via session ID '{session_id[:50]}'",
                        evidence={
                            "status": r.status_code,
                            "response_keys": list(data.keys())[:10],
                        },
                        impact="Attacker can access other users' shopping carts",
                        remediation="Implement session validation and authorization",
                        cwe="CWE-639",
                        tags=["idor", "cart", "session"],
                    ))
            elif r.status_code not in [401, 404]:
                print(f"    /shopping-cart/.../{session_id[:20]}: {r.status_code}")
        except:
            pass

    # Test session ID in other endpoints
    print("\n[IDOR] Testing session in booking endpoints...")
    for session_id in TEST_SESSIONS[:5]:
        try:
            r = client.get(f"/booking.json/guest/{session_id}/reserved")
            if r.status_code == 200:
                data = r.json() if "json" in r.headers.get("content-type", "") else None
                if data and isinstance(data, dict) and data:
                    reporter.add(Finding(
                        title=f"IDOR - Guest booking accessible via session: {session_id[:30]}",
                        severity=SEVERITY["HIGH"],
                        endpoint=f"/booking.json/guest/{session_id}/reserved",
                        method="GET",
                        description=f"Guest booking data accessible via session ID '{session_id[:50]}'",
                        evidence={
                            "status": r.status_code,
                            "response_keys": list(data.keys())[:10],
                        },
                        impact="Attacker can access other users' reserved bookings",
                        remediation="Implement session validation and booking ownership checks",
                        cwe="CWE-639",
                        tags=["idor", "booking", "session"],
                    ))
            elif r.status_code not in [401, 404]:
                print(f"    /booking.json/guest/{session_id[:20]}/reserved: {r.status_code}")
        except:
            pass
