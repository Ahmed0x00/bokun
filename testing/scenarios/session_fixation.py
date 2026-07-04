"""
Session Fixation Tests
Tests for session fixation vulnerabilities in the booking flow
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY
from config import TEST_SESSIONS


def run(client, reporter):
    """Test for session fixation vulnerabilities."""
    print("\n[SESSION] Testing session fixation...")

    # Test 1: Predictable session IDs
    print("  Testing predictable session IDs...")
    predictable_sessions = [f"session_{i}" for i in range(1, 21)]
    valid_sessions = []

    for session_id in predictable_sessions:
        try:
            r = client.get(f"/cart.json/{session_id}")
            if r.status_code == 200:
                valid_sessions.append(session_id)
        except:
            pass

    if len(valid_sessions) > 5:
        reporter.add(Finding(
            title="Session Fixation - Predictable session IDs accepted",
            severity=SEVERITY["MEDIUM"],
            endpoint="/cart.json/{sessionId}",
            method="GET",
            description=f"Server accepts {len(valid_sessions)} predictable session IDs out of 20 tested",
            evidence={
                "valid_sessions": valid_sessions[:10],
                "total_valid": len(valid_sessions),
            },
            impact="Attacker can predict/guess session IDs and hijack user sessions",
            remediation="Use cryptographically random session IDs with sufficient entropy",
            cwe="CWE-330",
            tags=["session-fixation", "weak-randomness"],
        ))

    # Test 2: Session ID in URL vs cookie
    print("  Testing session ID in URL...")
    test_session = " fixation_test_12345"
    try:
        r = client.get(f"/cart.json/{test_session}")
        if r.status_code == 200:
            # Check if session is accepted via URL
            reporter.add(Finding(
                title="Session Fixation - Session ID accepted in URL",
                severity=SEVERITY["LOW"],
                endpoint=f"/cart.json/{test_session}",
                method="GET",
                description="Session ID accepted via URL parameter, may be logged in server logs and referrer headers",
                evidence={"status": r.status_code, "session_id": test_session},
                impact="Session ID exposure via URL logging, referer headers, and browser history",
                remediation="Use secure cookies for session management instead of URL parameters",
                cwe="CWE-346",
                tags=["session-fixation", "url-session"],
            ))
    except:
        pass

    # Test 3: Session not invalidated on error
    print("  Testing session persistence after errors...")
    test_session = "persistence_test_67890"
    try:
        # Create a cart
        r1 = client.get(f"/cart.json/{test_session}")

        # Try to use the session with invalid data
        r2 = client.post(
            f"/cart.json/{test_session}/activity",
            json_body={"invalid": "data"}
        )

        # Check if session is still valid
        r3 = client.get(f"/cart.json/{test_session}")
        if r1.status_code == r3.status_code == 200:
            print(f"    Session persists after error: {test_session[:30]}")
    except:
        pass

    # Test 4: Concurrent session handling
    print("  Testing concurrent session handling...")
    test_session = "concurrent_test_11111"
    try:
        # Use session from multiple "clients"
        r1 = client.get(f"/cart.json/{test_session}")
        r2 = client.get(f"/cart.json/{test_session}")

        if r1.status_code == r2.status_code == 200:
            print(f"    Concurrent access OK: {test_session[:30]}")
    except:
        pass
