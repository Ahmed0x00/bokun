"""
Finding reporter - structured output for bug bounty submissions
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import RESULTS_DIR, SEVERITY


@dataclass
class Finding:
    """A security finding."""
    title: str
    severity: str
    endpoint: str
    method: str
    description: str
    evidence: Dict[str, Any]
    impact: str
    remediation: str
    cvss: Optional[str] = None
    cwe: Optional[str] = None
    references: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.tags is None:
            self.tags = []
        if self.references is None:
            self.references = []

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_markdown(self) -> str:
        md = f"""## {self.title}

**Severity**: {self.severity}
**Endpoint**: `{self.method} {self.endpoint}`
**CWE**: {self.cwe or 'N/A'}
**CVSS**: {self.cvss or 'N/A'}

### Description
{self.description}

### Evidence
```json
{json.dumps(self.evidence, indent=2)}
```

### Impact
{self.impact}

### Remediation
{self.remediation}
"""
        if self.references:
            md += "\n### References\n"
            for ref in self.references:
                md += f"- {ref}\n"
        if self.tags:
            md += f"\n**Tags**: {', '.join(self.tags)}\n"
        return md


class FindingReporter:
    """Collects and reports findings."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.results_dir = Path(RESULTS_DIR)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def add(self, finding: Finding):
        """Add a finding."""
        self.findings.append(finding)
        self._print_finding(finding)
        self._save_finding(finding)

    def _print_finding(self, finding: Finding):
        """Print finding to console."""
        colors = {
            "CRITICAL": "\033[91m",  # Red
            "HIGH": "\033[93m",      # Yellow
            "MEDIUM": "\033[33m",    # Orange
            "LOW": "\033[36m",       # Cyan
            "INFO": "\033[37m",      # White
        }
        reset = "\033[0m"
        color = colors.get(finding.severity, "")

        print(f"\n{'='*60}")
        print(f"{color}[{finding.severity}] {finding.title}{reset}")
        print(f"  Endpoint: {finding.method} {finding.endpoint}")
        print(f"  Description: {finding.description[:100]}...")
        print(f"{'='*60}")

    def _save_finding(self, finding: Finding):
        """Save finding to JSON file."""
        filename = f"{finding.timestamp.replace(':', '-')}_{finding.severity}_{finding.title.replace(' ', '_')[:50]}.json"
        filepath = self.results_dir / filename
        with open(filepath, "w") as f:
            json.dump(finding.to_dict(), f, indent=2)

    def summary(self) -> str:
        """Print summary of all findings."""
        by_severity = {}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)

        lines = ["\n" + "="*60, "FINDINGS SUMMARY", "="*60]
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in by_severity:
                lines.append(f"  {severity}: {len(by_severity[severity])}")
                for f in by_severity[severity]:
                    lines.append(f"    - {f.title}")
        lines.append(f"\n  Total: {len(self.findings)} findings")
        lines.append("="*60)
        return "\n".join(lines)

    def export_markdown(self, filepath: str = None):
        """Export all findings to markdown."""
        if filepath is None:
            filepath = str(self.results_dir / "findings_report.md")

        with open(filepath, "w") as f:
            f.write("# Bokun API Security Audit Report\n\n")
            f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d')}\n")
            f.write(f"**Target**: bokuntest.com / bokundemo.com\n")
            f.write(f"**Total Findings**: {len(self.findings)}\n\n")
            f.write(self.summary() + "\n\n")
            f.write("---\n\n")

            for finding in self.findings:
                f.write(finding.to_markdown())
                f.write("\n---\n\n")

        print(f"\nReport exported to: {filepath}")
