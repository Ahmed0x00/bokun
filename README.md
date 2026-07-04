# Bokun API Security Hunter

TripAdvisor Bug Bounty - Bokun API security testing framework.

## Quick Start

### 1. Setup

```bash
cd /home/ahmex/bokun_hunter
pip install -r requirements.txt
```

### 2. Configure API Keys

Edit `config.py` and add your Bokun API credentials:

```python
ACCESS_KEY = "your_access_key_here"
SECRET_KEY = "your_secret_key_here"
```

### 3. Run All Tests

```bash
cd testing
python runner.py
```

### 4. Run Specific Scenario

```bash
cd testing
python runner.py --scenario scenarios.idor_activity
python runner.py --scenario scenarios.auth_bypass
python runner.py --scenario scenarios.injection
```

### 5. Export Report

```bash
cd testing
python runner.py --export
```

## Directory Structure

```
bokun_hunter/
├── config.py                  # API keys, base URLs, test data
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── docs/                      # Documentation
├── rest-api/                  # Swagger specs and API reference
│   ├── bokun_api_spec.yaml    # v1 OpenAPI spec (11K lines)
│   ├── bokun_api_v2.yaml      # v2 OpenAPI spec
│   ├── endpoints_*.json       # Categorized endpoints
│   ├── idor_candidates.json   # IDOR-prone endpoints
│   └── auth_schemes.json      # Auth scheme details
├── testing/
│   ├── runner.py              # Main test runner
│   ├── lib/
│   │   ├── api_client.py      # HTTP client with auth
│   │   └── findings.py        # Finding reporter
│   ├── scenarios/             # Test scenarios
│   │   ├── idor_activity.py   # Activity IDOR tests
│   │   ├── idor_accommodation.py
│   │   ├── idor_booking.py
│   │   ├── idor_cart.py
│   │   ├── auth_bypass.py     # Auth bypass tests
│   │   ├── session_fixation.py
│   │   ├── cart_manipulation.py
│   │   └── injection.py       # SQL/NoSQL/SSTI tests
│   ├── results/               # Test results (JSON)
│   ├── logs/                  # Request logs
│   └── data/                  # Test data
└── reports/                   # Exported reports
```

## Test Scenarios

### IDOR (Insecure Direct Object Reference)
- `idor_activity` - Activity endpoints with sequential IDs
- `idor_accommodation` - Accommodation endpoints with slug/ID access
- `idor_booking` - Booking endpoints with confirmation codes
- `idor_cart` - Cart/session endpoints with session IDs

### Authentication
- `auth_bypass` - No auth, wrong auth, header manipulation

### Session Management
- `session_fixation` - Predictable session IDs, URL-based sessions

### Business Logic
- `cart_manipulation` - Negative quantities, promo code injection, gift card enumeration

### Injection
- `injection` - SQL injection, NoSQL injection, template injection

## API Reference

### Auth Headers
```
access-key: <your_access_key>
secret-key: <your_secret_key>
```

### Key Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/activity.json/{id}` | GET | Get activity by ID |
| `/accommodation.json/{id}` | GET | Get accommodation by ID |
| `/booking.json/{id}/summary` | GET | Get booking summary |
| `/booking.json/booking/{code}` | GET | Get booking by code |
| `/cart.json/{sessionId}` | GET | Get cart by session |
| `/activity.json/search` | POST | Search activities |

### Error Responses
```json
{"message": "Invalid API key. Missing header: X-Bokun-AccessKey", "fields": {}}
{"message": "Invalid API key.", "fields": {}}
```

## Adding New Scenarios

1. Create a new file in `testing/scenarios/`
2. Define a `run(client, reporter)` function
3. Add the module path to `SCENARIO_MODULES` in `runner.py`

Example:
```python
# testing/scenarios/my_test.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from testing.lib.findings import Finding, SEVERITY

def run(client, reporter):
    r = client.get("/some/endpoint")
    if r.status_code == 200:
        reporter.add(Finding(
            title="My Finding",
            severity=SEVERITY["HIGH"],
            endpoint="/some/endpoint",
            method="GET",
            description="Description of the finding",
            evidence={"status": r.status_code},
            impact="Impact description",
            remediation="Remediation description",
        ))
```

## Notes

- All endpoints require `access-key` + `secret-key` headers
- Rate limiting: 5 requests/second
- Test data uses predictable IDs (1, 2, 3, 5, 10, 50, 100, 999)
- Results saved to `testing/results/` as JSON
- Request logs saved to `testing/logs/requests.jsonl`
