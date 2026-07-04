"""
Scenarios __init__ - auto-discover scenario modules
"""
from pathlib import Path
import importlib

# Auto-discover all scenario modules
_scenarios = []
for f in Path(__file__).parent.glob("*.py"):
    if f.name.startswith("test_") or f.name.startswith("idor_") or f.name.startswith("auth_") or f.name.startswith("cart_") or f.name.startswith("session_") or f.name.startswith("injection_"):
        mod_name = f.stem
        try:
            mod = importlib.import_module(f".{mod_name}", package=__name__)
            _scenarios.append(mod)
        except ImportError:
            pass
