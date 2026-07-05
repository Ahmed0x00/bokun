#!/usr/bin/env python3
"""
Bokun API Hunter - Test Runner
Runs all registered test scenarios against the target.
"""
import sys
import json
import time
import importlib
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from testing.lib.api_client import BokunClient
from testing.lib.findings import FindingReporter


# ============================================================
# Scenario registry
# ============================================================
SCENARIO_MODULES = [
    # Existing scenarios
    "scenarios.idor_activity",
    "scenarios.idor_accommodation",
    "scenarios.idor_booking",
    "scenarios.idor_booking_mutation",
    "scenarios.idor_cart",
    "scenarios.idor_checkout",
    "scenarios.auth_bypass",
    "scenarios.auth_bypass_write",
    "scenarios.session_fixation",
    "scenarios.cart_manipulation",
    "scenarios.business_logic",
    "scenarios.injection",
    "scenarios.injection_write_payloads",
    "scenarios.race_condition",
    # New privilege escalation scenarios
    "scenarios.privilege_escalation",
    "scenarios.rbac_bypass",
    "scenarios.agent_idor",
    "scenarios.api_key_discovery",
]


def load_scenarios(names=None):
    """Load scenario modules."""
    scenarios = []
    modules = names if names else SCENARIO_MODULES
    for mod_name in modules:
        try:
            mod = importlib.import_module(mod_name)
            if hasattr(mod, "run"):
                scenarios.append((mod_name, mod))
                print(f"  [+] Loaded: {mod_name}")
            else:
                print(f"  [-] No run() in: {mod_name}")
        except ImportError as e:
            print(f"  [-] Failed to import {mod_name}: {e}")
    return scenarios


def run_scenario(name, mod, client, reporter):
    """Run a single scenario."""
    print(f"\n{'='*60}")
    print(f"Running: {name}")
    print(f"{'='*60}")
    start = time.time()
    try:
        mod.run(client, reporter)
        duration = time.time() - start
        print(f"  [OK] {name} completed in {duration:.1f}s")
        return True
    except Exception as e:
        duration = time.time() - start
        print(f"  [ERROR] {name} failed after {duration:.1f}s: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Bokun API Security Hunter")
    parser.add_argument("--scenario", "-s", help="Run specific scenario module")
    parser.add_argument("--list", "-l", action="store_true", help="List all scenarios")
    parser.add_argument("--export", "-e", action="store_true", help="Export report")
    parser.add_argument("--target", "-t", default="bokuntest", help="Target (bokuntest/bokundemo)")
    args = parser.parse_args()

    print("="*60)
    print("BOKUN API SECURITY HUNTER")
    print(f"Target: {args.target}")
    print(f"Time: {datetime.now().isoformat()}")
    print("="*60)

    if args.list:
        print("\nRegistered scenarios:")
        for mod in SCENARIO_MODULES:
            print(f"  - {mod}")
        return

    # Initialize
    client = BokunClient()
    reporter = FindingReporter()

    # Load scenarios
    print("\nLoading scenarios...")
    if args.scenario:
        scenarios = load_scenarios([args.scenario])
    else:
        scenarios = load_scenarios()

    if not scenarios:
        print("No scenarios loaded. Exiting.")
        return

    # Run
    print(f"\nRunning {len(scenarios)} scenario(s)...")
    results = {}
    for name, mod in scenarios:
        results[name] = run_scenario(name, mod, client, reporter)

    # Summary
    print(reporter.summary())
    print(f"\nResults: {sum(results.values())}/{len(results)} passed")

    if args.export:
        reporter.export_markdown()

    client.close()


if __name__ == "__main__":
    main()
