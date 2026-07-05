# Bokun API Security Audit Report

**Date**: 2026-07-05
**Target**: bokuntest.com / bokundemo.com
**Total Findings**: 6


============================================================
FINDINGS SUMMARY
============================================================
  CRITICAL: 3
    - CSRF - API Key Creation
    - CSRF - No Origin Validation
    - CSRF - API Key Deletion
  HIGH: 2
    - Sensitive Data Exposure - API Keys
    - Sensitive Data Exposure - API Keys
  MEDIUM: 1
    - Sensitive Data Exposure - User Info

  Total: 6 findings
============================================================

---

## CSRF - API Key Creation

**Severity**: CRITICAL
**Endpoint**: `POST /connections/api-keys`
**CWE**: N/A
**CVSS**: N/A

### Description
API key can be created without CSRF protection. An attacker can create API keys by tricking a logged-in user into visiting a malicious page.

### Evidence
```json
{
  "details": "API key created: ID=7034, Title=csrf-test-key"
}
```

### Impact
API key can be created without CSRF protection. An attacker can create API keys by tricking a logged-in user into visiting a malicious page.

### Remediation
Add CSRF token validation to API key creation endpoint. Verify Origin/Referer headers.

---

## CSRF - No Origin Validation

**Severity**: CRITICAL
**Endpoint**: `POST /connections/api-keys`
**CWE**: N/A
**CVSS**: N/A

### Description
API key creation accepts requests from any origin. Origin header is not validated.

### Evidence
```json
{
  "details": "Key created with Origin: https://evil.com"
}
```

### Impact
API key creation accepts requests from any origin. Origin header is not validated.

### Remediation
Validate Origin header against whitelist of allowed domains.

---

## CSRF - API Key Deletion

**Severity**: CRITICAL
**Endpoint**: `DELETE /connections/api-keys/7036`
**CWE**: N/A
**CVSS**: N/A

### Description
API key can be deleted without CSRF protection. An attacker can delete all API keys by tricking a logged-in user into visiting a malicious page.

### Evidence
```json
{
  "details": "API key 7036 deleted successfully"
}
```

### Impact
API key can be deleted without CSRF protection. An attacker can delete all API keys by tricking a logged-in user into visiting a malicious page.

### Remediation
Add CSRF token validation to API key deletion endpoint. Require confirmation for sensitive operations.

---

## Sensitive Data Exposure - API Keys

**Severity**: HIGH
**Endpoint**: `GET /connections/api-keys`
**CWE**: N/A
**CVSS**: N/A

### Description
API key endpoint exposes secret keys in response.

### Evidence
```json
{
  "details": "Secret key exposed for key ID 7030"
}
```

### Impact
API key endpoint exposes secret keys in response.

### Remediation
Never expose secret keys in API responses. Only show access keys.

---

## Sensitive Data Exposure - API Keys

**Severity**: HIGH
**Endpoint**: `GET /connections/api-keys`
**CWE**: N/A
**CVSS**: N/A

### Description
API key endpoint exposes secret keys in response.

### Evidence
```json
{
  "details": "Secret key exposed for key ID 7026"
}
```

### Impact
API key endpoint exposes secret keys in response.

### Remediation
Never expose secret keys in API responses. Only show access keys.

---

## Sensitive Data Exposure - User Info

**Severity**: MEDIUM
**Endpoint**: `GET /user-info`
**CWE**: N/A
**CVSS**: N/A

### Description
User info endpoint may expose sensitive data.

### Evidence
```json
{
  "details": "Sensitive field found: password"
}
```

### Impact
User info endpoint may expose sensitive data.

### Remediation
Review response schema and remove sensitive fields.

---

