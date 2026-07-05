"""
Bokun API Hunter - Configuration
Target: bokundemo.com / bokuntest.com (TripAdvisor Bug Bounty)
"""

# ============================================================
# API Keys - Multi-Privilege Testing
# ============================================================

# ADMIN keys (full access - for reference)
ADMIN_ACCESS_KEY = "9fcba1384d7d4550a4d7f46ee12500a4"
ADMIN_SECRET_KEY = "5b8da0591c964e639e4bbd0f243c1e5a"

# VENDOR keys (create via extranet -> settings -> connections -> api)
# These have vendor-level access, not admin
VENDOR_ACCESS_KEY = ""  # Fill with vendor API key
VENDOR_SECRET_KEY = ""  # Fill with vendor API secret

# BOOKING_AGENT keys (create via extranet -> settings -> user management)
# These have limited agent-level access
AGENT_ACCESS_KEY = ""   # Fill with agent API key
AGENT_SECRET_KEY = ""   # Fill with agent API secret

# READONLY keys (create via extranet -> settings -> connections -> api)
# These should have read-only access
READONLY_ACCESS_KEY = ""  # Fill with readonly API key
READONLY_SECRET_KEY = ""  # Fill with readonly API secret

# Default to admin keys for backward compatibility
ACCESS_KEY = ADMIN_ACCESS_KEY
SECRET_KEY = ADMIN_SECRET_KEY

# Privilege levels for testing
PRIVILEGE_LEVELS = {
    "admin": {
        "access_key": ADMIN_ACCESS_KEY,
        "secret_key": ADMIN_SECRET_KEY,
        "description": "Full admin access",
    },
    "vendor": {
        "access_key": VENDOR_ACCESS_KEY,
        "secret_key": VENDOR_SECRET_KEY,
        "description": "Vendor-level access",
    },
    "agent": {
        "access_key": AGENT_ACCESS_KEY,
        "secret_key": AGENT_SECRET_KEY,
        "description": "Booking agent access",
    },
    "readonly": {
        "access_key": READONLY_ACCESS_KEY,
        "secret_key": READONLY_SECRET_KEY,
        "description": "Read-only access",
    },
}

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
