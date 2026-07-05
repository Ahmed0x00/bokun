"""
Extranet Security Test Scenario
Tests CSRF, IDOR, and privilege escalation on extranet endpoints
Requires: PLAY_SESSION cookie from browser
"""
import sys
import json
import time
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import LOG_DIR
from testing.lib.findings import Finding, FindingReporter


class ExtranetSecurityTest:
    """Test extranet endpoints for security vulnerabilities."""

    def __init__(self, session_cookie: str):
        self.session_cookie = session_cookie
        self.findings: List[Finding] = []
        self.request_log: List[Dict] = []
        
        # Import here to avoid circular imports
        from testing.lib.extranet_client import ExtranetClient
        self.client = ExtranetClient(session_cookie=session_cookie)

    def _log(self, message: str):
        """Log message."""
        print(f"  {message}")

    def _add_finding(self, title: str, severity: str, description: str, 
                     endpoint: str, method: str, evidence: str = "",
                     remediation: str = "", impact: str = ""):
        """Add a finding."""
        finding = Finding(
            title=title,
            severity=severity,
            description=description,
            endpoint=endpoint,
            method=method,
            evidence={"details": evidence},
            impact=impact or description,
            remediation=remediation,
        )
        self.findings.append(finding)
        self._log(f"[{severity}] {title}")

    def test_csrf_api_key_creation(self):
        """Test CSRF vulnerability on API key creation."""
        self._log("\n[*] Testing CSRF on API key creation...")
        
        # Test 1: Create API key without any origin
        r = self.client.post('/connections/api-keys', json={
            'title': 'csrf-test-key',
            'role': 1
        })
        
        if r.status_code == 200:
            data = r.json()
            self._add_finding(
                title="CSRF - API Key Creation",
                severity="CRITICAL",
                description="API key can be created without CSRF protection. "
                           "An attacker can create API keys by tricking a logged-in user "
                           "into visiting a malicious page.",
                endpoint="/connections/api-keys",
                method="POST",
                evidence=f"API key created: ID={data.get('id')}, Title={data.get('title')}",
                remediation="Add CSRF token validation to API key creation endpoint. "
                          "Verify Origin/Referer headers."
            )
            
            # Clean up - delete the test key
            self.client.delete(f'/connections/api-keys/{data.get("id")}')
        
        # Test 2: Create with malicious origin
        r = self.client.post('/connections/api-keys', json={
            'title': 'evil-origin-key',
            'role': 1
        }, headers={'Origin': 'https://evil.com'})
        
        if r.status_code == 200:
            data = r.json()
            self._add_finding(
                title="CSRF - No Origin Validation",
                severity="CRITICAL",
                description="API key creation accepts requests from any origin. "
                           "Origin header is not validated.",
                endpoint="/connections/api-keys",
                method="POST",
                evidence=f"Key created with Origin: https://evil.com",
                remediation="Validate Origin header against whitelist of allowed domains."
            )
            
            # Clean up
            self.client.delete(f'/connections/api-keys/{data.get("id")}')

    def test_csrf_api_key_deletion(self):
        """Test CSRF vulnerability on API key deletion."""
        self._log("\n[*] Testing CSRF on API key deletion...")
        
        # Create a test key first
        r = self.client.post('/connections/api-keys', json={
            'title': 'delete-test-key',
            'role': 1
        })
        
        if r.status_code == 200:
            key_id = r.json().get('id')
            
            # Try to delete without CSRF token
            r2 = self.client.delete(f'/connections/api-keys/{key_id}')
            
            if r2.status_code == 200:
                self._add_finding(
                    title="CSRF - API Key Deletion",
                    severity="CRITICAL",
                    description="API key can be deleted without CSRF protection. "
                               "An attacker can delete all API keys by tricking a logged-in user "
                               "into visiting a malicious page.",
                    endpoint=f"/connections/api-keys/{key_id}",
                    method="DELETE",
                    evidence=f"API key {key_id} deleted successfully",
                    remediation="Add CSRF token validation to API key deletion endpoint. "
                              "Require confirmation for sensitive operations."
                )

    def test_mass_assignment(self):
        """Test mass assignment vulnerability."""
        self._log("\n[*] Testing mass assignment...")
        
        # Try to set privileged fields
        r = self.client.post('/connections/api-keys', json={
            'title': 'mass-assignment-test',
            'role': 2,  # Try to set admin role
            'vendorId': 9999,  # Try to change vendor
        })
        
        if r.status_code == 200:
            data = r.json()
            actual_role = data.get('role')
            actual_vendor = data.get('vendorId')
            
            # Check if our values were accepted
            if actual_role == 2 or actual_vendor == 9999:
                self._add_finding(
                    title="Mass Assignment - Privilege Escalation",
                    severity="HIGH",
                    description="API allows setting privileged fields like role and vendorId.",
                    endpoint="/connections/api-keys",
                    method="POST",
                    evidence=f"Attempted role=2, vendorId=9999. Got role={actual_role}, vendorId={actual_vendor}",
                    remediation="Whitelist allowed fields. Never accept role, vendorId, or other "
                              "privileged fields from client input."
                )
            
            # Clean up
            self.client.delete(f'/connections/api-keys/{data.get("id")}')

    def test_sensitive_data_exposure(self):
        """Test for sensitive data exposure in API responses."""
        self._log("\n[*] Testing sensitive data exposure...")
        
        # Check API keys endpoint
        r = self.client.get('/connections/api-keys')
        if r.status_code == 200:
            keys = r.json()
            for key in keys:
                # Check if secret key is exposed
                if 'secretKey' in key or 'secret' in str(key).lower():
                    self._add_finding(
                        title="Sensitive Data Exposure - API Keys",
                        severity="HIGH",
                        description="API key endpoint exposes secret keys in response.",
                        endpoint="/connections/api-keys",
                        method="GET",
                        evidence=f"Secret key exposed for key ID {key.get('id')}",
                        remediation="Never expose secret keys in API responses. "
                                  "Only show access keys."
                    )
        
        # Check user info endpoint
        r = self.client.get('/user-info')
        if r.status_code == 200:
            data = r.json()
            # Check for sensitive fields
            sensitive_fields = ['password', 'secret', 'token', 'apiKey']
            for field in sensitive_fields:
                if field in str(data).lower():
                    self._add_finding(
                        title="Sensitive Data Exposure - User Info",
                        severity="MEDIUM",
                        description=f"User info endpoint may expose sensitive data.",
                        endpoint="/user-info",
                        method="GET",
                        evidence=f"Sensitive field found: {field}",
                        remediation="Review response schema and remove sensitive fields."
                    )

    def test_idor(self):
        """Test for IDOR vulnerabilities."""
        self._log("\n[*] Testing IDOR vulnerabilities...")
        
        # Test accessing other vendors' data
        vendor_ids = [1, 2, 3, 100, 999]
        
        for vendor_id in vendor_ids:
            r = self.client.get(f'/connections/api-keys?vendorId={vendor_id}')
            if r.status_code == 200:
                data = r.json()
                # Check if we got different data
                if data and len(data) > 0:
                    # This might be our own data returned regardless of vendorId
                    # Check if vendorId parameter is being ignored
                    pass
        
        # Test accessing admin endpoints
        admin_endpoints = [
            '/admin/users/json',
            '/admin/white-labels',
            '/admin/plugins',
        ]
        
        for endpoint in admin_endpoints:
            r = self.client.get(endpoint)
            if r.status_code == 200:
                self._add_finding(
                    title=f"IDOR - Admin Endpoint Access",
                    severity="HIGH",
                    description=f"Regular user can access admin endpoint.",
                    endpoint=endpoint,
                    method="GET",
                    evidence=f"Status: {r.status_code}",
                    remediation="Implement proper role-based access control. "
                              "Restrict admin endpoints to admin users only."
                )

    def test_session_security(self):
        """Test session security."""
        self._log("\n[*] Testing session security...")
        
        # Check if session is valid
        r = self.client.get('/user-info')
        if r.status_code == 200:
            data = r.json()
            self._log(f"  Session valid for user: {data.get('email', 'unknown')}")
        
        # Test session fixation
        r = self.client.get('/auth-urls')
        if r.status_code == 200:
            data = r.json()
            self._log(f"  Auth URLs: {data}")

    def run_all_tests(self):
        """Run all extranet security tests."""
        print("="*70)
        print("EXTRANET SECURITY TEST")
        print("="*70)
        
        self.test_csrf_api_key_creation()
        self.test_csrf_api_key_deletion()
        self.test_mass_assignment()
        self.test_sensitive_data_exposure()
        self.test_idor()
        self.test_session_security()
        
        self.client.close()
        
        return self.findings


def generate_report(findings: List[Finding], output_file: str = None):
    """Generate security test report."""
    reporter = FindingReporter()
    
    for finding in findings:
        reporter.add(finding)
    
    if output_file:
        reporter.export_markdown(output_file)
        print(f"\n[+] Report saved to: {output_file}")
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total Findings: {len(findings)}")
    print(f"Critical: {len([f for f in findings if f.severity == 'CRITICAL'])}")
    print(f"High: {len([f for f in findings if f.severity == 'HIGH'])}")
    print(f"Medium: {len([f for f in findings if f.severity == 'MEDIUM'])}")
    print(f"Low: {len([f for f in findings if f.severity == 'LOW'])}")
    
    return reporter


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Extranet Security Test")
    parser.add_argument("--cookie", "-c", required=True, help="PLAY_SESSION cookie value")
    parser.add_argument("--output", "-o", default=None, help="Output report file")
    args = parser.parse_args()
    
    # Run tests
    tester = ExtranetSecurityTest(session_cookie=args.cookie)
    findings = tester.run_all_tests()
    
    # Generate report
    output_file = args.output or str(LOG_DIR / f"extranet_security_{int(time.time())}.md")
    generate_report(findings, output_file)
