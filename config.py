"""
Bokun API Hunter - Configuration
Target: bokundemo.com / bokuntest.com (TripAdvisor Bug Bounty)
"""

# ============================================================
# API Keys (replace with your actual keys)
# ============================================================
ACCESS_KEY = "74fb5f0a8d1b426e97accfad874bebc4"  # Your Bokun API access key
SECRET_KEY = "d2662b1d06d340ffaea7a51d139a72c5"  # Your Bokun API secret key

# ============================================================
# Base URLs
# ============================================================
BASE_URLS = {
    "bokuntest": "https://api.bokuntest.com",
    "bokundemo": "https://api.bokundemo.com",
    "bokun_prod": "https://api.bokun.io",
}

# Active target
ACTIVE_TARGET = "bokuntest"
BASE_URL = BASE_URLS[ACTIVE_TARGET]

# ============================================================
# Frontend URLs
# ============================================================
FRONTEND_URLS = {
    "bokuntest": "https://bokuntest.com",
    "bokundemo": "https://bokundemo.com",
    "extranet": "https://extranet.bokuntest.com",
    "bookings": "https://bookings.bokuntest.com",
    "travelerchat": "https://travelerchat.bokuntest.com",
}

# ============================================================
# Known test data
# ============================================================
KNOWN_IDS = {
    "activities": [1, 2, 3, 5, 10, 50, 100, 999],
    "accommodations": [1, 2, 3, 5, 10, 50, 100, 999],
    "routes": [1, 2, 3, 5, 10, 50, 100, 999],
    "product_lists": [1, 2, 3, 5, 10],
}

# Test session IDs for cart testing
TEST_SESSIONS = [
    "test_session_001",
    "attacker_session",
    "session_12345",
    "a]b[c",
    "../../etc/passwd",
    "${7*7}",
    "{{7*7}}",
    "null",
    "undefined",
    "0",
    "-1",
    "999999999",
]

# Test confirmation codes
TEST_CODES = [
    "ABC123",
    "TEST-BOOKING-001",
    "999999",
    "000000",
    "../../../test",
    "'; DROP TABLE bookings; --",
]

# ============================================================
# Request settings
# ============================================================
TIMEOUT = 10
FOLLOW_REDIRECTS = True
VERIFY_SSL = False

# Rate limiting (requests per second)
RATE_LIMIT = 5

# ============================================================
# Logging
# ============================================================
LOG_DIR = "testing/logs"
RESULTS_DIR = "testing/results"
DATA_DIR = "testing/data"

# ============================================================
# Headers
# ============================================================
DEFAULT_HEADERS = {
    "User-Agent": "Bokun-Hunter/1.0 (Security Research)",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# ============================================================
# Finding severity levels
# ============================================================
SEVERITY = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}
