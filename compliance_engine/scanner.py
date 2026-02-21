"""
Nigerian Fintech DevSecOps Compliance Engine
Core scanner for detecting local secrets and NDPA 2023 violations.
"""

import re
import json
import os
from dataclasses import dataclass, field, asdict
from typing import List
from datetime import datetime, timezone


# ─────────────────────────────────────────────
#  Rule Definitions
# ─────────────────────────────────────────────

RULES = [
    # --- Secret Detection ---
    {
        "id": "NG-SEC-001",
        "name": "Paystack Live Secret Key",
        "severity": "CRITICAL",
        "pattern": r"sk_live_[a-zA-Z0-9]{32,}",
        "category": "secret",
        "description": "Paystack live secret key exposed in source code.",
        "remediation": "Rotate the key immediately and store it in an environment variable or secrets manager.",
    },
    {
        "id": "NG-SEC-002",
        "name": "Flutterwave Secret Key",
        "severity": "CRITICAL",
        "pattern": r"FLWSECK_TEST-[a-zA-Z0-9]{32,}|FLWSECK-[a-zA-Z0-9]{32,}",
        "category": "secret",
        "description": "Flutterwave secret key exposed in source code.",
        "remediation": "Rotate the key immediately and store it in a secrets manager.",
    },
    {
        "id": "NG-SEC-003",
        "name": "Paystack Public Key (Test)",
        "severity": "WARNING",
        "pattern": r"pk_test_[a-zA-Z0-9]{32,}",
        "category": "secret",
        "description": "Paystack test public key found. Avoid hardcoding even test keys.",
        "remediation": "Move to environment variables for consistency and safety.",
    },
    {
        "id": "NG-SEC-004",
        "name": "Hardcoded BVN Pattern",
        "severity": "CRITICAL",
        "pattern": r"\b[0-9]{11}\b",
        "category": "pii",
        "description": "Potential BVN (11-digit number) found in source code.",
        "remediation": "Remove all PII from source code. Use tokenisation or masked references.",
    },
    {
        "id": "NG-SEC-005",
        "name": "Nigerian Phone Number",
        "severity": "WARNING",
        "pattern": r"\b(\+?234|0)[789][01]\d{8}\b",
        "category": "pii",
        "description": "Nigerian phone number pattern detected in source code.",
        "remediation": "Ensure this is not real user data. Remove from code and test fixtures.",
    },

    # --- NDPA 2023 / CBN Compliance ---
    {
        "id": "NG-NDPA-001",
        "name": "Data Sovereignty Violation (us-east-1)",
        "severity": "HIGH",
        "pattern": r"us-east-1",
        "category": "ndpa",
        "description": "AWS us-east-1 region detected. Nigerian user data should be hosted in af-south-1 (Cape Town) per NDPA 2023 data localisation recommendations.",
        "remediation": "Change region to af-south-1 unless an explicit cross-border transfer agreement is in place.",
    },
    {
        "id": "NG-NDPA-002",
        "name": "Data Sovereignty Violation (eu-west)",
        "severity": "HIGH",
        "pattern": r"eu-west-[0-9]",
        "category": "ndpa",
        "description": "EU region detected. Ensure NDPA cross-border data transfer conditions are met.",
        "remediation": "Document lawful basis for transfer or migrate to af-south-1.",
    },
    {
        "id": "NG-NDPA-003",
        "name": "Missing Encryption at Rest",
        "severity": "HIGH",
        "pattern": r"encrypted\s*=\s*false",
        "category": "ndpa",
        "description": "Encryption at rest is disabled. NDPA 2023 requires appropriate technical safeguards.",
        "remediation": "Set encrypted = true for all storage resources.",
    },
    {
        "id": "NG-NDPA-004",
        "name": "Public S3 Bucket",
        "severity": "CRITICAL",
        "pattern": r'acl\s*=\s*["\']public-read["\']',
        "category": "ndpa",
        "description": "Publicly readable S3 bucket detected. This likely violates NDPA data protection obligations.",
        "remediation": "Set bucket ACL to private and use pre-signed URLs for access.",
    },

    # --- Container Security ---
    {
        "id": "NG-CONT-001",
        "name": "Docker Running as Root",
        "severity": "HIGH",
        "pattern": r"USER\s+root",
        "category": "container",
        "description": "Dockerfile runs container as root user.",
        "remediation": "Add a non-root USER instruction, e.g., USER 1001.",
    },
    {
        "id": "NG-CONT-002",
        "name": "Hardcoded Secret in Dockerfile ENV",
        "severity": "CRITICAL",
        "pattern": r"ENV\s+\w*(SECRET|KEY|PASSWORD|TOKEN)\w*\s*=?\s*\S+",
        "category": "container",
        "description": "Secret or credential set via ENV in Dockerfile.",
        "remediation": "Use Docker secrets or pass environment variables at runtime.",
    },
    {
        "id": "NG-CONT-003",
        "name": "Latest Docker Tag",
        "severity": "WARNING",
        "pattern": r"FROM\s+\w[^:]+:latest",
        "category": "container",
        "description": "Docker image using :latest tag is unpinned and non-reproducible.",
        "remediation": "Pin to a specific image digest or version tag.",
    },
]


# ─────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    category: str
    filename: str
    line_number: int
    line_content: str
    description: str
    remediation: str


@dataclass
class ScanResult:
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    files_scanned: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    warning: int = 0
    passed: bool = True
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────
#  Scanner
# ─────────────────────────────────────────────

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tf", ".yml", ".yaml",
    ".json", ".env", ".sh", ".dockerfile", ""
}

# Files to always skip
SKIP_FILENAMES = {"package-lock.json", "yarn.lock", ".DS_Store"}


def should_scan_file(filepath: str) -> bool:
    """Determine if a file should be scanned."""
    basename = os.path.basename(filepath).lower()
    if basename in SKIP_FILENAMES:
        return False
    _, ext = os.path.splitext(filepath)
    if ext.lower() in SCANNABLE_EXTENSIONS:
        return True
    if basename in ("dockerfile", ".env", ".envrc"):
        return True
    return False


def scan_content(content: str, filename: str) -> List[Finding]:
    """Scan file content against all rules and return findings."""
    findings = []
    lines = content.splitlines()

    for rule in RULES:
        pattern = re.compile(rule["pattern"], re.IGNORECASE)
        for line_no, line in enumerate(lines, start=1):
            if pattern.search(line):
                # Redact the matched value in the report for safety
                redacted = pattern.sub("[REDACTED]", line).strip()
                findings.append(Finding(
                    rule_id=rule["id"],
                    name=rule["name"],
                    severity=rule["severity"],
                    category=rule["category"],
                    filename=filename,
                    line_number=line_no,
                    line_content=redacted,
                    description=rule["description"],
                    remediation=rule["remediation"],
                ))
    return findings


def scan_path(path: str) -> ScanResult:
    """Scan a file or directory. Returns a ScanResult."""
    result = ScanResult()

    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for root, _, filenames in os.walk(path):
            # Skip hidden dirs and common non-source dirs
            root_parts = root.replace("\\", "/").split("/")
            if any(p.startswith(".") or p in ("node_modules", "__pycache__", ".git") for p in root_parts):
                continue
            for fname in filenames:
                files.append(os.path.join(root, fname))

    for filepath in files:
        if not should_scan_file(filepath):
            continue
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            result.files_scanned += 1
            findings = scan_content(content, filepath)
            result.findings.extend(findings)
        except Exception as e:
            print(f"[WARN] Could not read {filepath}: {e}")

    # Tally
    result.total_findings = len(result.findings)
    result.critical = sum(1 for f in result.findings if f.severity == "CRITICAL")
    result.high = sum(1 for f in result.findings if f.severity == "HIGH")
    result.warning = sum(1 for f in result.findings if f.severity == "WARNING")

    # Build fails on any CRITICAL or HIGH finding
    result.passed = result.critical == 0 and result.high == 0

    return result


def save_report(result: ScanResult, output_path: str = "reports/scan_report.json"):
    """Save scan result to a JSON report."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[INFO] Report saved to {output_path}")


# ─────────────────────────────────────────────
#  CLI Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Nigerian Fintech DevSecOps Compliance Scanner")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--report", default="reports/scan_report.json", help="Output report path")
    parser.add_argument("--fail-on-warning", action="store_true", help="Also fail on WARNING findings")
    args = parser.parse_args()

    print(f"\n🔍 Scanning: {args.path}\n{'─' * 50}")
    result = scan_path(args.path)

    if args.fail_on_warning:
        result.passed = result.passed and result.warning == 0

    # Print summary
    for finding in result.findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "WARNING": "🟡"}.get(finding.severity, "⚪")
        print(f"{icon} [{finding.severity}] {finding.rule_id} | {finding.filename}:{finding.line_number}")
        print(f"   ↳ {finding.name}")
        print(f"   ↳ {finding.line_content}\n")

    print(f"{'─' * 50}")
    print(f"Files scanned : {result.files_scanned}")
    print(f"Total findings: {result.total_findings} (🔴 {result.critical} critical | 🟠 {result.high} high | 🟡 {result.warning} warnings)")
    print(f"Status        : {'✅ PASSED' if result.passed else '❌ FAILED'}\n")

    save_report(result, args.report)

    # ── Explicit exit code enforcement ──────────────────────────
    # GitHub Actions reads the exit code of this script.
    # Exit 0 = green checkmark (build passes).
    # Exit 1 = red X (build fails, merge is blocked).
    # We MUST be explicit here — relying on result.passed alone is not
    # sufficient because unhandled exceptions would exit 0 and silently pass.
    if result.critical > 0 or result.high > 0:
        sys.exit(1)
    elif args.fail_on_warning and result.warning > 0:
        sys.exit(1)
    else:
        sys.exit(0)
