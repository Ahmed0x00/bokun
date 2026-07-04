"""
Cart Manipulation Tests
Tests for price tampering, negative quantities, and cart race conditions
"""
import sys
from pathlib import Path
import threading
import time

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY


def run(client, reporter):
    """Test for cart manipulation vulnerabilities."""
    print("\n[CART] Testing cart manipulation...")

    session_id = "cart_manip_test_001"

    # Test 1: Add item with negative quantity
    print("  Testing negative quantity...")
    try:
        r = client.post(
            f"/cart.json/{session_id}/activity",
            json_body={"activityId": 1, "quantity": -1, "date": "2026-07-15"}
        )
        if r.status_code == 200:
            data = r.json() if "json" in r.headers.get("content-type", "") else None
            if data:
                reporter.add(Finding(
                    title="Cart Manipulation - Negative quantity accepted",
                    severity=SEVERITY["HIGH"],
                    endpoint=f"/cart.json/{session_id}/activity",
                    method="POST",
                    description="Cart accepts negative quantity, potentially resulting in negative pricing",
                    evidence={
                        "status": r.status_code,
                        "request": {"quantity": -1},
                        "response": data,
                    },
                    impact="Attacker can manipulate pricing by using negative quantities",
                    remediation="Validate quantity is positive on server side",
                    cwe="CWE-191",
                    tags=["cart-manipulation", "negative-quantity"],
                ))
        elif r.status_code not in [400, 401, 404]:
            print(f"    Negative quantity: {r.status_code}")
    except:
        pass

    # Test 2: Add item with zero quantity
    print("  Testing zero quantity...")
    try:
        r = client.post(
            f"/cart.json/{session_id}/activity",
            json_body={"activityId": 1, "quantity": 0, "date": "2026-07-15"}
        )
        if r.status_code == 200:
            reporter.add(Finding(
                title="Cart Manipulation - Zero quantity accepted",
                severity=SEVERITY["MEDIUM"],
                endpoint=f"/cart.json/{session_id}/activity",
                method="POST",
                description="Cart accepts zero quantity item",
                evidence={"status": r.status_code},
                impact="May lead to unexpected cart behavior or pricing errors",
                remediation="Validate quantity is greater than zero",
                cwe="CWE-20",
                tags=["cart-manipulation", "zero-quantity"],
            ))
    except:
        pass

    # Test 3: Add item with very large quantity
    print("  Testing large quantity...")
    try:
        r = client.post(
            f"/cart.json/{session_id}/activity",
            json_body={"activityId": 1, "quantity": 999999999, "date": "2026-07-15"}
        )
        if r.status_code == 200:
            data = r.json() if "json" in r.headers.get("content-type", "") else None
            if data:
                reporter.add(Finding(
                    title="Cart Manipulation - Extreme quantity accepted",
                    severity=SEVERITY["MEDIUM"],
                    endpoint=f"/cart.json/{session_id}/activity",
                    method="POST",
                    description="Cart accepts extremely large quantity without validation",
                    evidence={
                        "status": r.status_code,
                        "request": {"quantity": 999999999},
                    },
                    impact="May cause integer overflow or excessive pricing",
                    remediation="Implement server-side quantity limits",
                    cwe="CWE-190",
                    tags=["cart-manipulation", "overflow"],
                ))
    except:
        pass

    # Test 4: Apply promo code with special characters
    print("  Testing promo code injection...")
    promo_codes = [
        "'; DROP TABLE promos; --",
        "${7*7}",
        "{{7*7}}",
        "../../etc/passwd",
        "<script>alert(1)</script>",
        "admin' OR '1'='1",
    ]
    for code in promo_codes:
        try:
            r = client.get(f"/cart.json/{session_id}/apply-promo-code/{code}")
            if r.status_code == 200:
                data = r.json() if "json" in r.headers.get("content-type", "") else None
                if data and isinstance(data, dict):
                    # Check if error reveals SQL or internal info
                    error_msg = str(data.get("message", ""))
                    if any(x in error_msg.lower() for x in ["sql", "syntax", "error", "exception", "stack"]):
                        reporter.add(Finding(
                            title=f"Cart Manipulation - Promo code injection: {code[:30]}",
                            severity=SEVERITY["HIGH"],
                            endpoint=f"/cart.json/{session_id}/apply-promo-code/{code}",
                            method="GET",
                            description=f"Promo code endpoint may be vulnerable to injection",
                            evidence={
                                "status": r.status_code,
                                "promo_code": code,
                                "error_message": error_msg,
                            },
                            impact="Potential SQL injection or server-side code execution",
                            remediation="Sanitize promo code input and use parameterized queries",
                            cwe="CWE-89",
                            tags=["injection", "promo-code"],
                        ))
            elif r.status_code not in [400, 401, 404]:
                print(f"    Promo code {code[:20]}: {r.status_code}")
        except:
            pass

    # Test 5: Gift card code enumeration
    print("  Testing gift card code enumeration...")
    gift_cards = ["TEST", "GIFT001", "PROMO", "FREE", "000000", "AAAAAA"]
    for code in gift_cards:
        try:
            r = client.get(f"/cart.json/{session_id}/apply-gift-card/{code}")
            if r.status_code == 200:
                data = r.json() if "json" in r.headers.get("content-type", "") else None
                if data and isinstance(data, dict):
                    msg = str(data.get("message", ""))
                    # Different responses for valid vs invalid codes = enumeration
                    if "not found" not in msg.lower() and "invalid" not in msg.lower():
                        reporter.add(Finding(
                            title=f"Cart Manipulation - Gift card response差异: {code}",
                            severity=SEVERITY["MEDIUM"],
                            endpoint=f"/cart.json/{session_id}/apply-gift-card/{code}",
                            method="GET",
                            description="Gift card endpoint returns different responses, enabling brute-force enumeration",
                            evidence={"status": r.status_code, "message": msg},
                            impact="Attacker can enumerate valid gift card codes",
                            remediation="Return generic error messages and implement rate limiting",
                            cwe="CWE-209",
                            tags=["enumeration", "gift-card"],
                        ))
        except:
            pass
