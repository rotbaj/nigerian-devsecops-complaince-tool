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
        # Paystack live secret keys are exactly sk_live_ followed by 40 hex chars
        "pattern": r"sk_live_[a-fA-F0-9]{40}",
        "category": "secret",
        "description": "Paystack live secret key exposed in source code.",
        "remediation": "Rotate the key immediately and store it in an environment variable or secrets manager.",
    },
    {
        "id": "NG-SEC-002",
        "name": "Flutterwave Secret Key",
        "severity": "CRITICAL",
        # FLWSECK(?:_TEST)? collapses the two alternates into one non-capturing group
        "pattern": r"FLWSECK(?:_TEST)?-[a-fA-F0-9]{32}-X",
        "category": "secret",
        "description": "Flutterwave secret key exposed in source code.",
        "remediation": "Rotate the key immediately and store it in a secrets manager.",
    },
    {
        "id": "NG-SEC-003",
        "name": "Paystack Public Key",
        "severity": "WARNING",
        # Covers both test (pk_test_) and live (pk_live_) public keys — 40 hex chars each
        "pattern": r"pk_test_[a-fA-F0-9]{40}|pk_live_[a-fA-F0-9]{40}",
        "category": "secret",
        "description": "Paystack public key hardcoded in source code. Avoid committing any key, even public ones.",
        "remediation": "Move to environment variables for consistency and safety.",
    },
    {
        "id": "NG-SEC-006",
        "name": "Flutterwave Public Key",
        "severity": "WARNING",
        # FLW public keys are FLWPUBK- followed by 32 hex chars and -X suffix
        "pattern": r"FLWPUBK-[a-fA-F0-9]{32}-X",
        "category": "secret",
        "description": "Flutterwave public key hardcoded in source code.",
        "remediation": "Move to environment variables. Even public keys should not be committed.",
    },
    {
        "id": "NG-SEC-004",
        "name": "Hardcoded BVN",
        "severity": "CRITICAL",
        # Only flag 11-digit numbers that appear within ~40 chars of a BVN keyword.
        # This prevents false positives on phone numbers, amounts, and timestamps.
        # Matches: user_bvn = "22522683105"  (keyword before)
        # Matches: "22522683105"  # bank_verification_number  (keyword after)
        # Ignores: phone_number = "08012345678"
        "pattern": (
            r"(?:bvn|bank_verification|biometric).{0,40}[0-9]{11}"
            r"|[0-9]{11}.{0,40}(?:bvn|bank_verification|biometric)"
        ),
        "category": "pii",
        "description": "BVN (Bank Verification Number) detected in source code.",
        "remediation": "Remove all PII from source code. Use tokenisation or masked references.",
    },
    {
        "id": "NG-SEC-005",
        "name": "Nigerian Phone Number",
        "severity": "WARNING",
        # Only flag a Nigerian phone number when it is assigned to a phone/mobile/tel variable.
        # This avoids BVN overlap and reduces noise from 11-digit numbers in non-PII contexts.
        "pattern": r"(?:phone|mobile|tel)[_\w]{0,20}\s*[:=]\s*['\"]?(?:\+?234|0)[789][01]\d{8}['\"]?",
        "category": "pii",
        "description": "Nigerian phone number assigned to a phone/mobile/tel variable in source code.",
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
        "name": "Unpinned Docker Image",
        "severity": "WARNING",
        # Catches two unpinned cases:
        # 1. Explicit :latest tag  →  FROM node:latest
        # 2. No tag at all (Docker defaults to :latest)  →  FROM node
        # Does NOT fire on pinned versions/digests  →  FROM node:18.20.0  /  FROM node@sha256:...
        "pattern": r"FROM\s+(?:--\S+\s+)*(?:\S+:latest|[a-zA-Z][^\s:@]*(?:\s|$))",
        "category": "container",
        "description": "Docker image is unpinned (explicit :latest or no tag). Builds are non-reproducible.",
        "remediation": "Pin to a specific version tag or image digest, e.g. FROM node:18.20.0-slim.",
    },
]


# Compile every pattern once at import time instead of inside the hot scan loop.
for _rule in RULES:
    _rule["_compiled"] = re.compile(_rule["pattern"], re.IGNORECASE)


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


# NDPA sovereignty/encryption rules are meaningful only in infrastructure files.
# Applying them to .py or .js would flag comments like "# migrated from us-east-1"
# and fail the build on non-infra code.
_INFRA_EXTENSIONS = {".tf", ".yml", ".yaml"}


def scan_content(content: str, filename: str) -> List[Finding]:
    findings = []
    lines = content.splitlines()
    _, ext = os.path.splitext(filename)

    for rule in RULES:
        if rule["category"] == "ndpa" and ext.lower() not in _INFRA_EXTENSIONS:
            continue

        pattern = rule["_compiled"]
        for line_no, line in enumerate(lines, start=1):
            if pattern.search(line):
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

    # Directories that are never scanned, regardless of name convention.
    # .github is intentionally NOT in this set — pipeline YAML files are a
    # primary attack surface for supply-chain issues and must be scanned.
    _SKIP_DIRS = {"node_modules", "__pycache__", ".git", ".venv", "venv"}

    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for root, dirs, filenames in os.walk(path):
            root_parts = root.replace("\\", "/").split("/")
            if any(
                p in _SKIP_DIRS or (p.startswith(".") and p != ".github")
                for p in root_parts
            ):
                # Also prune os.walk's descent into skipped dirs for efficiency
                dirs[:] = []
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
