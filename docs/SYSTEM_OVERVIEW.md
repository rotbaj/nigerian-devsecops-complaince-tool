# Nigerian Fintech DevSecOps Compliance Framework: System Overview

BSc Cybersecurity Project, Miva Open University
Author: Oluwadurotimi Bajomo (2024/C/CYB/0973)
Supervisor: Dr. Bolaji Abigail Omodunbi

This document is a self-contained reference for the system: its purpose, key
concepts, architecture, features, evaluation results, and the key sections of
actual source code. It is written to be shared as standalone context (for
example, pasted into an AI assistant or given to a reader without repository
access), so all essential code is embedded inline. A companion document,
PROJECT_REPORT.md, records the full development history: every problem
encountered and how each was diagnosed and solved.

---

## Table of Contents

1. What the Tool Is
2. Key Concepts
3. System Architecture (diagram)
4. Component Map
5. The Scanner Engine (source code)
6. The Evaluation Corpus Generator (source code)
7. The CI/CD Pipeline (source code)
8. The Dashboard (source code)
9. The Pre-Commit Hook (source code)
10. Container and Risk Acceptance Files (source code)
11. The Unit Test Suite (source code)
12. Data Contracts (report formats)
13. Detection Rules Summary
14. Evaluation Results
15. Technology Stack

---

## 1. What the Tool Is

A DevSecOps compliance toolchain purpose-built for Nigerian fintech companies. It
detects security and regulatory violations that generic scanners miss because
they are specific to the Nigerian financial ecosystem:

- Hardcoded Paystack and Flutterwave API keys (the two dominant Nigerian payment
  providers, each with a distinctive key format)
- Hardcoded Nigerian PII: Bank Verification Numbers (BVN, the 11-digit national
  banking identifier) and Nigerian mobile numbers
- NDPA 2023 (Nigeria Data Protection Act) violations in infrastructure code:
  data hosted outside approved regions, encryption at rest disabled, publicly
  readable storage of customer documents
- Insecure container configuration: root containers, secrets baked into images,
  unpinned base images

Enforcement happens at three points in the delivery lifecycle: on the
developer's machine before a commit is created, in the CI/CD pipeline before
code merges, and on a stakeholder dashboard that always reflects the latest
pipeline run.

## 2. Key Concepts

**Policy as code.** Each compliance requirement is a machine-readable rule: an
ID, a severity, a category, a regular expression, a description, and remediation
text. The rule set is defined once and used by every layer.

**Severity gating.** Findings are CRITICAL, HIGH, or WARNING. Any CRITICAL or
HIGH finding makes the scanner exit with code 1, which fails the build and
blocks the merge. WARNING findings are reported but do not block; a strict mode
(`--fail-on-warning`) treats them as failures too.

**Context-aware detection.** Rules that would otherwise generate false positives
require surrounding context. The BVN rule only fires when an 11-digit number
appears within 40 characters of a keyword such as "bvn" or "bank_verification",
with lookarounds ensuring the number is exactly 11 digits. The phone rule
requires assignment to a variable named like phone, mobile, or tel.

**Rule scoping.** NDPA rules run only on infrastructure file types (.tf, .yml,
.yaml); container rules run only on Dockerfiles. A code comment mentioning
"us-east-1" in a Python file, or a Python "from x import y" statement, cannot
fail a build.

**Shift-left with a backstop.** The pre-commit hook gives the earliest possible
feedback but can be bypassed locally (`git commit --no-verify`); the CI pipeline
re-scans everything on push and cannot be bypassed. Convenience at the edge,
authority at the center.

**Continuous self-evaluation.** The pipeline regenerates a 200-file synthetic
corpus on every run and asserts that the clean half passes with zero findings
and the vulnerable half is caught. For the vulnerable corpus the assertion is
inverted: the job fails only if the scan passes. Every push therefore re-proves
the tool's detection rate.

**Defense in depth.** Trivy, an independent industry scanner, runs alongside the
custom engine: over the same evaluation corpus (infrastructure
misconfigurations), over the repository, and over the built Docker image (known
CVEs). Agreement between two independent engines validates both the corpus and
the detections.

**Documented risk acceptance.** CVEs in the container image that have no
compatible fix are recorded in a .trivyignore file, each with a written
justification of why no attack path reaches the vulnerable code, and a review
date. Detect, assess, accept or remediate, document, re-review.

**Results as a data feed.** CI runners are headless and ephemeral, so the
pipeline publishes every run's reports and an accumulated scan history to a
dedicated scan-results git branch. The dashboard reads that branch over plain
HTTPS, which works identically from a laptop or from the hosted deployment.

**Self-referential hygiene.** A compliance scanner's own artifacts are hostile
input to itself: its test data contains synthetic secrets, its reports quote
findings, and a second scanner's JSON output quotes source lines verbatim. The
system handles this with exclude lists (`--exclude
tests,evaluation_data,reports`), de-fanged construction of test secrets (keys
assembled from string fragments so no complete pattern exists in committed
source), and redaction of matched content in saved reports.

## 3. System Architecture

```
+----------------------------------------------------------------------------------+
|                              DEVELOPER MACHINE                                   |
|                                                                                  |
|   developer ---- git commit ----> pre-commit hook (scripts/hooks/pre-commit)     |
|                                     |                                            |
|                                     v                                            |
|                          compliance scanner (CLI)                                |
|                          CRITICAL/HIGH found? --> commit BLOCKED                 |
|                          clean? ----------------> commit created                 |
+----------------------------------|-----------------------------------------------+
                                   | git push
                                   v
+----------------------------------------------------------------------------------+
|                        GITHUB ACTIONS PIPELINE (CI/CD)                           |
|                                                                                  |
|  Stage 1   Compliance Scan      scanner on repo (excl. test data)   gate: exit 1 |
|  Stage 1b  Evaluation Scan      regenerate 200-file corpus, then:               |
|                                   scanner: clean must PASS (strict)             |
|                                   scanner: vulnerable must FAIL (inverted)      |
|                                   Trivy IaC: vulnerable must FAIL (inverted)    |
|                                   Trivy IaC: clean (informational)              |
|  Stage 1c  Publish Results      reports + merged history -> scan-results branch |
|  Stage 2   Container Scan       docker build; Trivy image CVE scan              |
|                                 (.trivyignore risk acceptances applied)         |
|                                 Trivy IaC scan of repository                    |
|  Stage 3   Unit Tests           regenerate fixtures; pytest (40 tests)          |
|  Stage 4   Summary              result tables on the run's Summary page         |
+-----------------|----------------------------------------------------------------+
                  | force-push (history carried forward, deduplicated)
                  v
+----------------------------------------------------------------------------------+
|                     scan-results BRANCH (data feed, no code)                     |
|   scan_report.json  clean_report.json  vulnerable_report.json                    |
|   trivy_image.json  trivy_clean.json   trivy_vulnerable.json                     |
|   scan_history.json (accumulates one summary row per scan, per target)           |
+-----------------|----------------------------------------------------------------+
                  | HTTPS fetch (raw.githubusercontent.com)
                  v
+----------------------------------------------------------------------------------+
|              STREAMLIT DASHBOARD (local or Streamlit Community Cloud)            |
|                                                                                  |
|   Scan Directory mode:  run scanner interactively (auto-generates corpus)        |
|   Load Report mode:     latest CI results | uploaded artifact | local report     |
|                                                                                  |
|   Status banner -> metric cards -> Compliance Trend (per-target history chart)   |
|   -> sortable/filterable findings -> category chart -> Trivy section (3 tabs)    |
|                                                                                  |
|   Audience: CTO / business team leads (plain-language labels and captions)       |
+----------------------------------------------------------------------------------+

Shared core: compliance_engine/scanner.py is the same engine in all three layers
(hook, pipeline, dashboard). Rules are defined once.
```

Data flow in one sentence: code moves left to right through two gates (hook,
CI), while results flow downward from CI into a git branch that the dashboard
treats as a read-only reporting API.

## 4. Component Map

| Path | Role |
|------|------|
| compliance_engine/scanner.py | Core engine: 16 rules, scanning, severity gating, JSON report, scan history, CLI |
| generate_eval_data.py | Writes 100 vulnerable + 100 clean synthetic files and 2 deterministic pytest fixtures |
| .github/workflows/devsecops-pipeline.yml | Six-job pipeline |
| dashboard/app.py | Streamlit dashboard, all modes and charts |
| scripts/hooks/pre-commit, scripts/install-hooks.sh | Local commit gate; installer sets git core.hooksPath |
| tests/test_scanner.py | 40 unit tests including false-positive and regression cases |
| .trivyignore | Risk-accepted image CVEs with justifications and review date |
| requirements.txt | Fully pinned dependencies |
| Dockerfile | Dashboard container, pinned base image, non-root user |
| evaluation_data/, reports/, tests/fixtures/ | Generated at run time, git-ignored |

---

## 5. The Scanner Engine (compliance_engine/scanner.py)

### 5.1 The complete rule set

Every rule is a dictionary. Patterns are written to match the providers' real
key formats exactly (Paystack live secrets are `sk_live_` plus exactly 40 hex
characters; Flutterwave secrets are `FLWSECK-` or `FLWSECK_TEST-` plus 32 hex
characters plus `-X`).

```python
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
        # Covers both test (pk_test_) and live (pk_live_) public keys, 40 hex chars each
        "pattern": r"pk_test_[a-fA-F0-9]{40}|pk_live_[a-fA-F0-9]{40}",
        "category": "secret",
        "description": "Paystack public key hardcoded in source code. Avoid committing any key, even public ones.",
        "remediation": "Move to environment variables for consistency and safety.",
    },
    {
        "id": "NG-SEC-006",
        "name": "Flutterwave Public Key",
        "severity": "WARNING",
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
        # (?<![0-9]) / (?![0-9]) ensure exactly 11 digits; a 12-digit number is not a BVN.
        "pattern": (
            r"(?:bvn|bank_verification|biometric).{0,40}(?<![0-9])[0-9]{11}(?![0-9])"
            r"|(?<![0-9])[0-9]{11}(?![0-9]).{0,40}(?:bvn|bank_verification|biometric)"
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
        # Trailing (?!\d) prevents matching the first 11 digits of a longer number.
        "pattern": r"(?:phone|mobile|tel)\w{0,20}\s*[:=]\s*['\"]?(?:\+?234|0)[789][01]\d{8}(?!\d)",
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

    # --- NDPA 2023: additional data-security controls (infrastructure files only) ---
    {
        "id": "NG-NDPA-005",
        "name": "Encryption in Transit Not Enforced",
        "severity": "HIGH",
        # Flags a plaintext HTTP listener/target. The closing quote prevents this
        # from matching "HTTPS", so only unencrypted HTTP is caught.
        "pattern": r'protocol\s*=\s*["\']HTTP["\']',
        "category": "ndpa",
        "description": "Plaintext HTTP detected. NDPA 2023 s.39 requires appropriate technical measures; personal data must be encrypted in transit.",
        "remediation": "Use HTTPS/TLS. Set protocol to HTTPS and redirect HTTP to HTTPS, or enable rds.force_ssl.",
    },
    {
        "id": "NG-NDPA-006",
        "name": "Data Hosted Outside Approved Region",
        "severity": "HIGH",
        # Generalised localisation check: flags any well-formed AWS region that is
        # not af-south-1 (Cape Town), the approved region for keeping Nigerian data
        # on the continent. Supersedes the narrow us-east-1 / eu-west checks.
        "pattern": r'region\s*=\s*["\'](?!af-south-1)[a-z]{2}-[a-z]+-\d+["\']',
        "category": "ndpa",
        "description": "Cloud region outside af-south-1 detected. Hosting Nigerian personal data abroad triggers NDPA 2023 s.41 cross-border transfer obligations.",
        "remediation": "Use af-south-1 unless a lawful cross-border transfer basis under s.41-43 is documented.",
    },
    {
        "id": "NG-NDPA-007",
        "name": "Publicly Accessible Database",
        "severity": "CRITICAL",
        # Flags an RDS instance exposed to the public internet.
        "pattern": r'publicly_accessible\s*=\s*true',
        "category": "ndpa",
        "description": "Publicly accessible database detected. This exposes personal data and likely violates NDPA 2023 s.39 confidentiality obligations.",
        "remediation": "Set publicly_accessible = false and place the database in a private subnet.",
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
        # Catches: FROM node:latest, and FROM node (no tag, defaults to :latest).
        # Does NOT fire on pinned versions/digests: FROM node:18.20.0 / FROM node@sha256:...
        "pattern": r"FROM\s+(?:--\S+\s+)*(?:\S+:latest|[a-zA-Z][^\s:@]*(?:\s|$))",
        "category": "container",
        "description": "Docker image is unpinned (explicit :latest or no tag). Builds are non-reproducible.",
        "remediation": "Pin to a specific version tag or image digest, e.g. FROM node:18.20.0-slim.",
    },
]

# Compile every pattern once at import time instead of inside the hot scan loop.
for _rule in RULES:
    _rule["_compiled"] = re.compile(_rule["pattern"], re.IGNORECASE)
```

### 5.2 Data models

```python
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
```

### 5.3 File selection and rule scoping

```python
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


def _is_dockerfile(filename: str) -> bool:
    base = os.path.basename(filename).lower()
    return base.startswith("dockerfile") or base.endswith(".dockerfile")
```

### 5.4 The scan core: matching and redaction

Matched content is redacted before it is stored, so a scan report can never
itself leak the secret it found.

```python
def scan_content(content: str, filename: str) -> List[Finding]:
    findings = []
    lines = content.splitlines()
    _, ext = os.path.splitext(filename)

    for rule in RULES:
        if rule["category"] == "ndpa" and ext.lower() not in _INFRA_EXTENSIONS:
            continue
        # Container rules only make sense in Dockerfiles. Without this gate,
        # every Python "from x import y" line matches the FROM regex.
        if rule["category"] == "container" and not _is_dockerfile(filename):
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
```

### 5.5 Directory walking, excludes, and pass/fail

The in-place pruning of `dirs[:]` fixes a bug where scanning `"."` silently
scanned nothing (the path "." itself starts with a dot). `.github` is
deliberately scanned because pipeline YAML is a supply-chain attack surface.

```python
# Directories that are never scanned, at any depth.
# .github is intentionally NOT skipped: pipeline YAML is a primary
# supply-chain attack surface and must be scanned.
SKIP_DIRS = {"node_modules", "__pycache__", ".git", ".venv", "venv"}


def scan_path(path: str, exclude: Optional[List[str]] = None) -> ScanResult:
    """Scan a file or directory. Returns a ScanResult.

    exclude: extra directory names to skip at any depth (e.g. ["tests"]).
    Useful for excluding directories that intentionally contain synthetic
    secrets, such as test fixtures and evaluation data.
    """
    result = ScanResult()
    skip = SKIP_DIRS | set(exclude or [])

    if os.path.isfile(path):
        files = [path]
    else:
        files = []
        for root, dirs, filenames in os.walk(path):
            # Prune subdirectories in place so os.walk never descends into them.
            # Filtering child names (rather than testing the full root path)
            # means a scan target like "." or a parent dir with a leading dot
            # is still scanned correctly.
            dirs[:] = [
                d for d in dirs
                if d not in skip and (not d.startswith(".") or d == ".github")
            ]
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
```

### 5.6 Reports and scan history

```python
def save_report(result: ScanResult, output_path: str = "reports/scan_report.json"):
    """Save scan result to a JSON report."""
    report_dir = os.path.dirname(output_path)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[INFO] Report saved to {output_path}")


def append_history(result: ScanResult, target: str,
                   history_path: str = "reports/scan_history.json"):
    """Append a one-line summary of this scan to the history log.

    The history file is a JSON list of summaries (not full findings), one entry
    per scan, so results can be tracked over time. The scan target is recorded
    because trends only make sense per target; mixing a scan of the project
    with a scan of evaluation_data/vulnerable would look like a wild swing.
    """
    history = []
    if os.path.exists(history_path):
        try:
            with open(history_path) as f:
                history = json.load(f)
        except (json.JSONDecodeError, IOError):
            history = []

    history.append({
        "scanned_at": result.scanned_at,
        "target": target,
        "files_scanned": result.files_scanned,
        "total_findings": result.total_findings,
        "critical": result.critical,
        "high": result.high,
        "warning": result.warning,
        "passed": result.passed,
    })

    with open(history_path, "w") as f:
        json.dump(history, f, indent=2)
```

### 5.7 CLI entry point and explicit exit codes

```python
    parser = argparse.ArgumentParser(description="Nigerian Fintech DevSecOps Compliance Scanner")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--report", default="reports/scan_report.json", help="Output report path")
    parser.add_argument("--fail-on-warning", action="store_true", help="Also fail on WARNING findings")
    parser.add_argument(
        "--exclude",
        default="",
        help="Comma-separated directory names to skip, e.g. --exclude tests,evaluation_data "
             "(for directories that intentionally contain synthetic secrets)",
    )
    args = parser.parse_args()
    exclude_dirs = [d.strip() for d in args.exclude.split(",") if d.strip()]

    result = scan_path(args.path, exclude=exclude_dirs)
    if args.fail_on_warning:
        result.passed = result.passed and result.warning == 0

    save_report(result, args.report)
    history_path = os.path.join(os.path.dirname(args.report) or ".", "scan_history.json")
    append_history(result, target=args.path, history_path=history_path)

    # ── Explicit exit code enforcement ──────────────────────────
    # GitHub Actions reads the exit code of this script.
    # Exit 0 = green checkmark (build passes).
    # Exit 1 = red X (build fails, merge is blocked).
    # We MUST be explicit here: relying on result.passed alone is not
    # sufficient because unhandled exceptions would exit 0 and silently pass.
    if result.critical > 0 or result.high > 0:
        sys.exit(1)
    elif args.fail_on_warning and result.warning > 0:
        sys.exit(1)
    else:
        sys.exit(0)
```

---

## 6. The Evaluation Corpus Generator (generate_eval_data.py)

### 6.1 De-fanged secret construction

The generator must write files containing scannable secrets without its own
source containing any complete secret pattern (otherwise the scanner would flag
its own tooling). Secrets are therefore assembled at run time:

```python
def gen_hex(n_chars):
    """Return n_chars lowercase hex characters."""
    return random.randbytes(n_chars // 2).hex()


def gen_bvn():
    """Synthetic 11-digit BVN. Real BVNs start with 2."""
    return f"2{random.randint(1000000000, 9999999999)}"


def gen_phone():
    """Synthetic Nigerian mobile number (080xxxxxxxx)."""
    return f"080{random.randint(10000000, 99999999)}"
```

Output directories are deleted and recreated on every run (filenames vary
between runs, so stale files would otherwise accumulate and skew counts).

### 6.2 Vulnerable template: application code

The template is filled by `.format()` with a fresh random key per file
(`content = BAD_PYTHON_MULTI.format(ps_key=gen_hex(40), flw_key=gen_hex(32),
bvn=gen_bvn())`), so no two generated files share credentials:

```python
class PaymentGatewayConfig:
    def __init__(self):
        # TODO: DevOps team to move these to AWS Secrets Manager next sprint.
        # Hardcoding temporarily to fix the production outage.
        self.paystack_key = "sk_live_{ps_key}"
        self.flw_key = "FLWSECK-{flw_key}-X"
        self.environment = "production"


def process_kyc(user_payload):
    """Process KYC data for new customers."""
    user_bvn = "{bvn}"  # Extracted from payload, bank_verification_number
    logger.info(f"Processing KYC for user with BVN: {{user_bvn}}")
    return True
```

### 6.3 Vulnerable template: Terraform (scanner rules plus Trivy targets)

```hcl
# NDPA Violation: Nigerian financial data hosted outside Africa
# Trivy: hardcoded cloud credentials in provider block (synthetic example values)
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket" "user_kyc_documents" {
  bucket = "fintech-kyc-docs-prod"

  # CRITICAL: Publicly accessible bucket containing PII
  acl = "public-read"
}

resource "aws_ebs_volume" "database_storage" {
  availability_zone = "us-east-1a"
  size              = 500

  # NDPA Violation: Encryption at rest disabled
  encrypted = false
}

# Trivy: security group open to the entire internet, including SSH
resource "aws_security_group" "core_banking_sg" {
  name = "core-banking-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# NDPA Violation: plaintext HTTP listener, so card and KYC data crosses the
# network unencrypted (NG-NDPA-005; Trivy also flags plain HTTP on ALBs)
resource "aws_lb_listener" "api_http" {
  load_balancer_arn = aws_lb.api_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api_tg.arn
  }
}

# Trivy: publicly accessible RDS with plaintext password and no encryption
# (the public-access flag below also fires NG-NDPA-007)
resource "aws_db_instance" "customer_db" {
  identifier          = "fintech-customers"
  engine              = "postgres"
  username            = "fintech_admin"
  password            = "SuperSecretDbPass123!"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

# Trivy: IAM policy with full wildcard permissions
resource "aws_iam_policy" "app_policy" {
  name = "fintech-app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
```

### 6.4 Vulnerable template: Dockerfile

```dockerfile
# CRITICAL: Unpinned image tag defaults to :latest
FROM node:latest

# Trivy: ADD used where COPY suffices (ADD can fetch remote URLs / auto-extract)
ADD package*.json ./
RUN npm install

# Trivy: curl piped straight into a shell: unverified remote code execution
RUN curl -sSL https://get.example-tool.io/install.sh | sh

# Trivy: world-writable permissions on the app directory
COPY . .
RUN chmod -R 777 /usr/src/app

# Trivy: apt-get without version pinning or cache cleanup
RUN apt-get update && apt-get install -y curl wget netcat

# SECURITY LEAK: Flutterwave secret embedded in image layer
ENV FLW_SECRET="FLWSECK-{flw_key}-X"

# CRITICAL: Container runs as root
USER root

# Trivy: no HEALTHCHECK instruction defined
EXPOSE 8080
CMD [ "npm", "start" ]
```

### 6.5 Vulnerable template: Kubernetes manifest

```yaml
    spec:
      # Trivy: pod shares the host's network and PID namespaces
      hostNetwork: true
      hostPID: true
      containers:
        - name: core-api
          # Trivy + NG-CONT: unpinned latest image
          image: fintech/core-api:latest
          securityContext:
            # Trivy: privileged container can escape to the host
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
          env:
            # Trivy: secret material passed as a plain env value
            - name: DB_PASSWORD
              value: "SuperSecretDbPass123!"
            - name: AWS_DEFAULT_REGION
              value: "us-east-1"
          # Trivy: no resources.limits, so a runaway pod can starve the node
```

### 6.6 Clean template: Terraform that passes BOTH scanners

The clean template must satisfy not only the project's own 16 rules but also
Trivy's independent checks (customer-managed-key encryption, full public access
block):

```hcl
# NDPA Compliant: Cape Town region keeps Nigerian data on the continent
provider "aws" {
  region = "af-south-1"
}

# Customer-managed key: auditable, rotatable encryption for customer data
resource "aws_kms_key" "kyc_docs_key" {
  description         = "CMK for the KYC document bucket"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "user_kyc_documents" {
  bucket = "fintech-kyc-docs-prod"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kyc_docs_sse" {
  bucket = aws_s3_bucket.user_kyc_documents.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.kyc_docs_key.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "kyc_docs_block" {
  bucket = aws_s3_bucket.user_kyc_documents.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_volume" "database_storage" {
  availability_zone = "af-south-1a"
  size              = 500
  encrypted         = true
}

# Encryption in transit: HTTPS-only listener with a current TLS policy
# (protocol = "HTTPS" must NOT trigger NG-NDPA-005)
resource "aws_lb_listener" "api_https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:af-south-1:123456789012:loadbalancer/app/fintech-api/0f1e2d3c4b5a6978"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:af-south-1:123456789012:certificate/11aa22bb-33cc-44dd-55ee-66ff77aa88bb"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:af-south-1:123456789012:targetgroup/fintech-api/a1b2c3d4e5f60789"
  }
}

# Private, encrypted database with a managed master password
# (publicly_accessible = false must NOT trigger NG-NDPA-007)
resource "aws_db_instance" "customer_db" {
  identifier                          = "fintech-customers"
  engine                              = "postgres"
  instance_class                      = "db.t3.medium"
  allocated_storage                   = 100
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.kyc_docs_key.arn
  manage_master_user_password         = true
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  backup_retention_period             = 30
  skip_final_snapshot                 = false
}
```

A subtlety discovered during evaluation: Trivy parses a scanned folder as one
Terraform root module, so identical resource names across the 100 clean files
collapsed together and broke the association between each bucket and its
protections, making clean files look misconfigured. The generator therefore
makes resource names unique per file:

```python
    elif file_type == "terraform":
        # Resource names must be unique per file: Trivy parses the whole
        # folder as one Terraform module, and duplicate addresses stop it
        # from associating each bucket with its public-access block and
        # encryption config (making clean files look misconfigured).
        content = CLEAN_TERRAFORM
        for name in ("kyc_docs_key", "user_kyc_documents", "kyc_docs_sse",
                     "kyc_docs_block", "database_storage", "api_https",
                     "customer_db"):
            content = content.replace(name, f"{name}_{i}")
        filename = os.path.join(GOOD_DIR, f"aws_infrastructure_{i}.tf")
```

---

## 7. The CI/CD Pipeline (.github/workflows/devsecops-pipeline.yml)

### 7.1 Triggers and the repository gate

```yaml
on:
  push:
    branches: ["main", "develop"]
  pull_request:
    branches: ["main"]
  workflow_dispatch:

jobs:
  compliance-scan:
    name: Compliance & Secret Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run Nigerian Fintech Compliance Engine
        # tests/ and evaluation_data/ intentionally contain synthetic secrets
        # for testing the scanner itself, so they are excluded here.
        # Exit code 1 = CRITICAL or HIGH findings -> pipeline fails and blocks merge
        run: |
          python compliance_engine/scanner.py . --exclude tests,evaluation_data,reports --report reports/scan_report.json
      - name: Upload Compliance Report
        uses: actions/upload-artifact@v4
        if: always()   # Upload even if scan fails so the team can review
        with:
          name: compliance-report
          path: |
            reports/scan_report.json
            reports/scan_history.json
```

### 7.2 The evaluation job: inverted assertions

```yaml
  evaluation:
    name: Evaluation Corpus Scan
    runs-on: ubuntu-latest
    needs: compliance-scan
    steps:
      # (checkout, python setup, pip install omitted for brevity)

      - name: Generate evaluation corpus
        # evaluation_data/ is git-ignored (it contains synthetic secrets),
        # so the 200-file corpus is generated fresh on every run.
        run: python generate_eval_data.py

      - name: Scan clean corpus (must pass with zero findings)
        run: |
          python compliance_engine/scanner.py evaluation_data/clean \
            --fail-on-warning --report reports/clean_report.json

      - name: Scan vulnerable corpus (scanner must catch it)
        # Exit code 1 is the CORRECT outcome here: it means the scanner
        # detected the planted issues. The step fails only if the scan PASSES.
        run: |
          if python compliance_engine/scanner.py evaluation_data/vulnerable \
              --report reports/vulnerable_report.json; then
            echo "::error::Vulnerable corpus passed the scan; detection is broken"
            exit 1
          fi
          echo "Vulnerable corpus correctly failed the scan."

      - name: Trivy IaC scan of vulnerable corpus (must be caught)
        # Second detection engine over the same corpus.
        # continue-on-error lets the next step assert on the outcome.
        id: trivy_vulnerable
        uses: aquasecurity/trivy-action@v0.36.0
        continue-on-error: true
        with:
          scan-type: "config"
          scan-ref: "evaluation_data/vulnerable"
          format: "json"
          output: "reports/trivy_vulnerable.json"
          exit-code: "1"
          severity: "CRITICAL,HIGH"

      - name: Verify Trivy caught the planted misconfigurations
        run: |
          if [ "${{ steps.trivy_vulnerable.outcome }}" != "failure" ]; then
            echo "::error::Trivy found no CRITICAL/HIGH misconfigurations in the vulnerable corpus"
            exit 1
          fi
          echo "Trivy correctly flagged the vulnerable corpus."

      - name: Trivy IaC scan of clean corpus (informational)
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          scan-type: "config"
          scan-ref: "evaluation_data/clean"
          format: "json"
          output: "reports/trivy_clean.json"
          exit-code: "0"
          severity: "CRITICAL,HIGH"
```

The job ends by rendering result tables (files scanned, findings by severity,
detection-rate PASS/FAIL, Trivy misconfiguration counts) onto the run's Summary
page via `$GITHUB_STEP_SUMMARY`, and uploading all report JSONs as artifacts.

### 7.3 Publishing results to the scan-results branch

```yaml
  publish-results:
    name: Publish Results for Dashboard
    runs-on: ubuntu-latest
    needs: [compliance-scan, evaluation, container-scan]
    # Runs even when a scan failed, because failed scans are exactly what the
    # dashboard needs to show. Skipped on PRs (no write access from forks).
    if: ${{ always() && github.event_name != 'pull_request' }}
    permissions:
      contents: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      - name: Download all scan reports
        uses: actions/download-artifact@v4
        with:
          path: ci_reports
      - name: Push reports to scan-results branch
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -e
          mkdir results
          # Carry the accumulated history forward if the branch already exists
          if git fetch origin scan-results 2>/dev/null; then
            git show origin/scan-results:scan_history.json > results/scan_history.json || echo "[]" > results/scan_history.json
          else
            echo "[]" > results/scan_history.json
          fi
          python3 - <<'EOF'
          import glob, json, shutil
          history = json.load(open("results/scan_history.json"))
          seen = {(e["scanned_at"], e["target"]) for e in history}
          for path in sorted(glob.glob("ci_reports/*/scan_history.json")):
              for entry in json.load(open(path)):
                  key = (entry["scanned_at"], entry["target"])
                  if key not in seen:
                      history.append(entry)
                      seen.add(key)
          history.sort(key=lambda e: e["scanned_at"])
          json.dump(history, open("results/scan_history.json", "w"), indent=2)
          for name in ("scan_report.json", "clean_report.json", "vulnerable_report.json",
                       "trivy_image.json", "trivy_clean.json", "trivy_vulnerable.json"):
              for path in glob.glob(f"ci_reports/*/{name}"):
                  shutil.copy(path, f"results/{name}")
          EOF
          cd results
          git init -q -b scan-results
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .
          git commit -q -m "CI scan results for ${GITHUB_SHA}"
          git push -f "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" scan-results
```

### 7.4 Container scanning with risk acceptances

```yaml
  container-scan:
    name: Container Security Scan
    runs-on: ubuntu-latest
    needs: compliance-scan
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      - name: Build Docker image
        run: docker build -t fintech-app:${{ github.sha }} .
      - name: Create reports directory
        # reports/ is git-ignored, and Trivy won't create it for its output file
        run: mkdir -p reports
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          image-ref: "fintech-app:${{ github.sha }}"
          format: "json"
          output: "reports/trivy_image.json"
          exit-code: "1"
          severity: "CRITICAL,HIGH"
          ignore-unfixed: true
          # Documented risk acceptances (see .trivyignore for justifications)
          trivyignores: ".trivyignore"
      - name: Upload image scan report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: trivy-image-report
          path: reports/trivy_image.json
      - name: Trivy IaC scan (Terraform)
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          scan-type: "config"
          scan-ref: "."
          format: "table"
          exit-code: "1"
          severity: "CRITICAL,HIGH"
```

The remaining jobs: `test` regenerates the fixtures (`python
generate_eval_data.py`) and runs `pytest tests/ -v`; `summary` downloads the
compliance report and prints a metric table to the run Summary page.

---

## 8. The Dashboard (dashboard/app.py)

### 8.1 Path scoping and CI results access

```python
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO_NAME = os.path.basename(BASE_DIR)


def repo_relative(path):
    """Show paths scoped to the repo instead of the full file system."""
    p = str(path)
    if os.path.isabs(p):
        rel = os.path.relpath(p, BASE_DIR)
        if rel.startswith(".."):
            return p  # outside the repo; nothing shorter to show
        p = rel
    p = os.path.normpath(p)
    return REPO_NAME if p == "." else p


# Fallback for hosted deployments (e.g. Streamlit Community Cloud), where
# the app may not run from a git checkout so the remote can't be detected.
DEFAULT_GITHUB_REPO = "rotbaj/nigerian-devsecops-complaince-tool"


def detect_github_repo():
    """Owner/name of this repo's GitHub remote, else the deployment default."""
    try:
        url = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=BASE_DIR, text=True, timeout=5,
        ).strip()
    except Exception:
        return DEFAULT_GITHUB_REPO
    m = re.search(r"github\.com[:/]([^/]+/[^/\s]+?)(?:\.git)?$", url)
    return m.group(1) if m else DEFAULT_GITHUB_REPO


def fetch_ci_json(repo_slug, filename):
    """Read a results file from the repo's scan-results branch on GitHub."""
    url = f"https://raw.githubusercontent.com/{repo_slug}/scan-results/{filename}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)
```

### 8.2 Flattening Trivy JSON for a stakeholder table

```python
def summarize_trivy(report):
    """Flatten a Trivy JSON report into severity counts + display rows."""
    counts = {}
    rows = []
    for res in report.get("Results") or []:
        target = res.get("Target", "")
        for m in res.get("Misconfigurations") or []:
            sev = m.get("Severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
            rows.append({
                "Severity": sev,
                "Issue": m.get("Title", m.get("ID", "")),
                "Where": target,
                "How to fix": m.get("Resolution", ""),
            })
        for v in res.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
            fixed = v.get("FixedVersion", "")
            rows.append({
                "Severity": sev,
                "Issue": f"{v.get('VulnerabilityID', '')}: {v.get('Title', '')}",
                "Where": f"{v.get('PkgName', '')} {v.get('InstalledVersion', '')}",
                "How to fix": f"Upgrade to {fixed}" if fixed else "No fix released yet",
            })
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: sev_rank.get(r["Severity"], 9))
    return counts, rows
```

### 8.3 Interactive scanning with on-demand corpus generation

```python
    if run_scan:
        # Relative paths are resolved against the project root, not the
        # process working directory.
        resolved_target = (
            scan_target if os.path.isabs(scan_target)
            else os.path.normpath(os.path.join(BASE_DIR, scan_target))
        )
        display_target = repo_relative(resolved_target)
        # evaluation_data/ is git-ignored (synthetic secrets), so on a fresh
        # clone (including the hosted Streamlit Cloud app) it doesn't exist
        # until generated. Generate it on demand when it's the scan target.
        if not os.path.exists(resolved_target) and display_target.split(os.sep)[0] == "evaluation_data":
            generator = os.path.join(BASE_DIR, "generate_eval_data.py")
            if os.path.exists(generator):
                with st.spinner("Generating the 200-file evaluation corpus (first run only)..."):
                    subprocess.run(
                        [sys.executable, generator],
                        cwd=BASE_DIR, check=True, capture_output=True,
                    )
        ...
                with st.spinner(f"Scanning `{display_target}`..."):
                    result = scan_path(resolved_target, exclude=exclude_dirs)
                    if fail_on_warning:
                        result.passed = result.passed and result.warning == 0
                    save_report(result, report_path)
                    append_history(result, target=display_target, history_path=history_path)
                    # Streamlit reruns this whole script every time ANY widget
                    # changes, and the button only reads True on the run right
                    # after the click. Without session_state the results would
                    # vanish as soon as the user touches a filter or sort control.
                    st.session_state["scan_result"] = result.to_dict()
```

### 8.4 Fetching CI results (Load Report mode)

```python
        if st.button("Fetch latest CI results", type="primary"):
            st.session_state["ci_report"] = fetch_ci_json(repo_slug.strip(), CI_REPORTS[which])
            st.session_state["ci_report_name"] = which
            # Also pull the accumulated CI history so the trend
            # chart can show the pipeline's view, not just local scans.
            try:
                st.session_state["ci_history"] = fetch_ci_json(repo_slug.strip(), "scan_history.json")
            except Exception:
                st.session_state.pop("ci_history", None)
            # And the Trivy reports (best-effort).
            ci_trivy = {}
            for label, fname in TRIVY_REPORTS.items():
                try:
                    ci_trivy[label] = fetch_ci_json(repo_slug.strip(), fname)
                except Exception:
                    pass
            st.session_state["ci_trivy"] = ci_trivy
```

(Error handling wraps this: an HTTP 404 explains that the scan-results branch
is created by the pipeline's Publish Results job and the repository must be
public.)

### 8.5 The compliance trend chart

Per-target history, headline metrics with inverse-colored deltas (a decrease
in issues shows as good), and an Altair line chart whose hour-boundary tick
positions are computed in Python because the Vega runtime's own hour-interval
ticking proved unreliable:

```python
    # Headline: latest scan vs the one before it. Deltas use inverse colors
    # because for security issues, down is good.
    latest = tdf.iloc[-1]
    prev = tdf.iloc[-2] if len(tdf) >= 2 else None
    h1, h2, h3, h4 = st.columns(4)
    for col, label, key in (
        (h1, "Critical issues", "critical"),
        (h2, "High-risk issues", "high"),
        (h3, "Warnings", "warning"),
        (h4, "Total findings", "total_findings"),
    ):
        delta = int(latest[key] - prev[key]) if prev is not None else None
        col.metric(label, int(latest[key]), delta=delta, delta_color="inverse")

    # X-axis pips on hour boundaries. Vega's own hour-interval ticking is
    # unreliable at sub-hour data spans, so compute the tick positions here
    # and cap them at ~12 so multi-day histories don't overcrowd the axis.
    ts = pd.to_datetime(trend_long["scanned_at"])
    tick_start = ts.min().floor("h")
    tick_end = ts.max().ceil("h")
    if tick_end <= tick_start:
        tick_end = tick_start + pd.Timedelta(hours=1)
    span_hours = int((tick_end - tick_start).total_seconds() // 3600)
    step_hours = max(1, -(-span_hours // 12))
    hour_ticks = [
        alt.DateTime(year=t.year, month=t.month, date=t.day, hours=t.hour)
        for t in pd.date_range(tick_start, tick_end, freq=f"{step_hours}h")
    ]
    # Sequential severity ramp (dark -> light = worst -> least severe).
    # Steps validated: monotonic lightness, all >= 3:1 contrast on white.
    trend_chart = (
        alt.Chart(trend_long)
        .mark_line(strokeWidth=2, point=alt.OverlayMarkDef(size=64))
        .encode(
            x=alt.X("scanned_at:T", title="Scan date & time",
                    axis=alt.Axis(values=hour_ticks, format="%b %d, %H:00", labelAngle=0)),
            y=alt.Y("Issues:Q", title="Number of issues found"),
            color=alt.Color("Severity:N",
                            scale=alt.Scale(domain=["Critical", "High", "Warning"],
                                            range=["#9f1710", "#c05702", "#997400"]),
                            legend=alt.Legend(title="Severity")),
            tooltip=[
                alt.Tooltip("scanned_at:T", title="Scan time", format="%b %d, %Y %H:%M"),
                alt.Tooltip("Severity:N", title="Severity"),
                alt.Tooltip("Issues:Q", title="Issues"),
            ],
        )
    )
    st.altair_chart(trend_chart, use_container_width=True)
```

### 8.6 Filtering and sorting findings

```python
    selected_sev = col_sev.multiselect("Severity", all_severities, default=all_severities)
    selected_cat = col_cat.multiselect("Category", all_categories, default=all_categories)
    sort_by = col_sort.selectbox(
        "Sort by",
        ["Severity (critical first)", "File name", "Scan order"],
    )

    filtered = [
        f for f in findings
        if f["severity"] in selected_sev and f["category"] in selected_cat
    ]

    SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2}
    if sort_by == "Severity (critical first)":
        filtered.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f["filename"], f["line_number"]))
    elif sort_by == "File name":
        filtered.sort(key=lambda f: (f["filename"], f["line_number"]))
    # "Scan order" keeps the original order from the report
```

Each finding renders as an expander titled with a severity marker, the rule ID
and name, and the repo-relative file location; inside are the category, file,
line, redacted content, description, and remediation.

### 8.7 The Trivy section

When CI results have been fetched, a dedicated section renders the pipeline's
second-scanner results in three tabs (Docker image CVEs, vulnerable corpus,
clean corpus). Each tab shows a caption stating the expectation (findings on
the vulnerable corpus are expected proof of detection; the clean list should be
empty), severity metric cards, and the severity-sorted table produced by
`summarize_trivy` (columns: Severity, Issue, Where, How to fix).

---

## 9. The Pre-Commit Hook

`scripts/hooks/pre-commit` (complete file):

```sh
#!/bin/sh
# Nigerian Fintech DevSecOps pre-commit compliance gate.
# Installed via scripts/install-hooks.sh (sets core.hooksPath to scripts/hooks).
# Blocks the commit if the scanner finds CRITICAL or HIGH severity issues.
# Bypass in an emergency with: git commit --no-verify

echo "Running compliance scan before commit..."
python3 compliance_engine/scanner.py . --exclude tests,evaluation_data,reports
status=$?

if [ $status -ne 0 ]; then
    echo ""
    echo "Commit blocked: the issues above must be fixed before this code is committed."
    echo "   To inspect them visually, run:"
    echo "       python3 -m streamlit run dashboard/app.py"
    exit $status
fi

echo "Compliance scan passed."
exit 0
```

`scripts/install-hooks.sh` (complete file). Git deliberately never activates
hooks from a cloned repository, so each clone opts in once:

```sh
#!/bin/sh
# One-time setup after cloning: points git at the repo's versioned hooks
# so every commit is scanned for compliance issues before it is created.
cd "$(git rev-parse --show-toplevel)" || exit 1
git config core.hooksPath scripts/hooks
chmod +x scripts/hooks/*
echo "Git hooks installed. Every commit will now run the compliance scan."
echo "   To uninstall: git config --unset core.hooksPath"
```

Design note: the hook must not launch the dashboard itself. Git hooks are
blocking and non-interactive; `streamlit run` starts a server that never
exits, which would hang every commit. The hook prints the command instead.

---

## 10. Container and Risk Acceptance Files

### 10.1 Dockerfile (complete file)

The application container practices what the scanner preaches: pinned base
image, non-root user.

```dockerfile
# ── Nigerian Fintech DevSecOps - App Dockerfile ────────────────
# Used by the CI/CD pipeline for Trivy container scanning

# Python 3.9 reached end-of-life in October 2025; 3.12 receives security patches
FROM python:3.12-slim

# Security: non-root user
RUN useradd -m -u 1001 appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p reports && chown -R appuser:appuser /app

USER 1001

EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

### 10.2 requirements.txt (complete file)

```
streamlit==1.32.0
pandas==2.2.0
altair==5.5.0
# numpy and pyarrow must be pinned: left unpinned they resolve to numpy 2.x /
# pyarrow 25.x, which are ABI-incompatible with pandas 2.2.0 and crash the
# dashboard's charts (segfault inside Arrow serialization).
numpy==1.26.4
pyarrow==15.0.0
pytest==8.0.0
```

### 10.3 .trivyignore (complete file)

```
# Risk-accepted vulnerabilities for the dashboard container image.
#
# Context: the image runs an internal compliance dashboard. It serves no
# untrusted user content, processes no user-uploaded images, and does not
# parse externally supplied Arrow/protobuf payloads. The fixed versions of
# all packages below are incompatible with the pinned streamlit 1.32 stack
# (streamlit requires pillow<11 and protobuf<5; pyarrow>15 breaks pandas
# 2.2.0), so upgrading requires replatforming the dashboard.
#
# Review date: 2026-07-13. Re-assess when the streamlit stack is upgraded.

# pillow 10.4.0: out-of-bounds write via crafted PSD image. The dashboard
# never opens image files; pillow is only a transitive streamlit dependency.
CVE-2026-25990

# pillow 10.4.0: DoS via decompression bomb in FITS image processing.
# No image processing path exists in this app.
CVE-2026-40192

# pillow 10.4.0: arbitrary code execution via malicious PSD file.
# No PSD (or any) image files are ever opened by this app.
CVE-2026-42311

# protobuf 4.25.9: DoS via recursion depth bypass. Protobuf here only
# serializes streamlit's own UI messages, never external input.
CVE-2026-0994

# pyarrow 15.0.0: DoS via use-after-free. Arrow only carries the app's own
# DataFrames between server and browser, never untrusted data.
CVE-2026-25087
```

---

## 11. The Unit Test Suite (tests/test_scanner.py)

40 tests in four classes. Representative excerpts showing the testing style:
positive detection, negative (false-positive) cases, and regressions for bugs
found during development.

```python
class TestSecretDetection:

    def test_detects_paystack_live_key(self):
        # Paystack live secret: sk_live_ + exactly 40 hex chars
        content = 'SECRET_KEY = "sk_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"'
        findings = scan_content(content, "config.py")
        assert "NG-SEC-001" in [f.rule_id for f in findings]

    def test_phone_number_without_bvn_keyword_not_flagged_as_bvn(self):
        # A Nigerian phone number must NOT trigger the BVN rule (no keyword context)
        content = 'phone_number = "08012345678"'
        findings = scan_content(content, "user.py")
        assert not [f for f in findings if f.rule_id == "NG-SEC-004"]

    def test_twelve_digit_number_not_flagged_as_bvn(self):
        # A BVN is exactly 11 digits; a 12-digit number near a keyword is not one
        content = 'user_bvn = "225226831055"'
        findings = scan_content(content, "user.py")
        assert not [f for f in findings if f.rule_id == "NG-SEC-004"]


class TestNDPACompliance:

    def test_ndpa_rules_not_applied_to_python_files(self):
        # A comment in a .py file mentioning us-east-1 must NOT fail the build.
        content = '# We migrated away from us-east-1 last year, do not use'
        findings = scan_content(content, "README_migration.py")
        assert not [f for f in findings if f.category == "ndpa"]

    def test_ndpa_rules_applied_to_yaml_files(self):
        content = 'AWS_DEFAULT_REGION: us-east-1'
        findings = scan_content(content, "deploy.yml")
        assert "NG-NDPA-001" in [f.rule_id for f in findings]


class TestContainerSecurity:

    def test_container_rules_not_applied_to_python_files(self):
        # "from x import y" in Python must NOT match the Docker FROM regex;
        # container rules only apply to Dockerfiles.
        content = "from dataclasses import dataclass\nfrom os import path\n"
        findings = scan_content(content, "models.py")
        assert not [f for f in findings if f.category == "container"]

    def test_pinned_digest_no_warning(self):
        # An image pinned by sha256 digest is fully reproducible, so no warning
        content = "FROM node@sha256:a1b2...\n"
        findings = scan_content(content, "Dockerfile")
        assert not [f for f in findings if f.category == "container"]


class TestScanResult:

    def test_scanning_relative_dot_path_works(self):
        # Regression: scan_path(".") used to skip EVERYTHING because "." itself
        # starts with a dot, making the CI scan a silent no-op that always passed.
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.tf"), "w") as f:
                f.write('acl = "public-read"\n')
            os.chdir(tmpdir)
            result = scan_path(".")
        assert result.files_scanned >= 1
        assert result.critical > 0

    def test_github_workflows_directory_is_scanned(self):
        # .github/workflows/ must NOT be skipped: pipeline YAML is a supply-chain
        # attack surface. Secrets or unpinned actions there must be caught.
        ...

    def test_finding_line_content_is_redacted(self):
        content = 'KEY = "sk_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"'
        findings = scan_content(content, "config.py")
        assert len(findings) > 0
        for finding in findings:
            assert "sk_live_" not in finding.line_content
```

Beyond pytest, the dashboard is tested headlessly with Streamlit's AppTest
framework (driving inputs, buttons, mode switches, sorting, and filters, then
asserting on rendered metrics, expanders, tables, and chart specifications),
and chart changes are verified by compiling and rendering the actual Vega-Lite
specification to SVG in Node.js, because a specification that validates can
still crash the renderer.

---

## 12. Data Contracts

### 12.1 Scan report (scan_report.json, clean_report.json, vulnerable_report.json)

```json
{
  "scanned_at": "2026-07-13T16:14:02.113937+00:00",
  "files_scanned": 100,
  "total_findings": 320,
  "critical": 140,
  "high": 154,
  "warning": 26,
  "passed": false,
  "findings": [
    {
      "rule_id": "NG-SEC-002",
      "name": "Flutterwave Secret Key",
      "severity": "CRITICAL",
      "category": "secret",
      "filename": "evaluation_data/vulnerable/core_payment_service_2.py",
      "line_number": 13,
      "line_content": "self.flw_key = \"[REDACTED]\"",
      "description": "Flutterwave secret key exposed in source code.",
      "remediation": "Rotate the key immediately and store it in a secrets manager."
    }
  ]
}
```

### 12.2 Scan history (scan_history.json)

A JSON list, one summary entry per scan, keyed by target so the dashboard can
plot independent trends:

```json
[
  {
    "scanned_at": "2026-07-13T15:19:04.523311+00:00",
    "target": "evaluation_data/vulnerable",
    "files_scanned": 100,
    "total_findings": 320,
    "critical": 140,
    "high": 154,
    "warning": 26,
    "passed": false
  }
]
```

### 12.3 Trivy reports (trivy_image.json, trivy_clean.json, trivy_vulnerable.json)

Standard Trivy JSON: a `Results` list where each entry has a `Target` plus
either `Misconfigurations` (config scans: ID, Title, Severity, Resolution) or
`Vulnerabilities` (image scans: VulnerabilityID, PkgName, InstalledVersion,
FixedVersion, Severity, Title). The dashboard's `summarize_trivy` flattens both
shapes into one table.

## 13. Detection Rules Summary

| Rule ID | Severity | Category | Detects | Scope |
|---------|----------|----------|---------|-------|
| NG-SEC-001 | CRITICAL | secret | Paystack live secret key (sk_live_ + 40 hex) | all files |
| NG-SEC-002 | CRITICAL | secret | Flutterwave secret key (FLWSECK[_TEST]- + 32 hex + -X) | all files |
| NG-SEC-003 | WARNING | secret | Paystack public key (pk_test_/pk_live_ + 40 hex) | all files |
| NG-SEC-006 | WARNING | secret | Flutterwave public key (FLWPUBK- + 32 hex + -X) | all files |
| NG-SEC-004 | CRITICAL | pii | Hardcoded BVN (keyword within 40 chars, exactly 11 digits) | all files |
| NG-SEC-005 | WARNING | pii | Nigerian phone assigned to phone/mobile/tel variable | all files |
| NG-NDPA-001 | HIGH | ndpa | Data hosted in us-east-1 | .tf/.yml/.yaml only |
| NG-NDPA-002 | HIGH | ndpa | Data hosted in eu-west regions | .tf/.yml/.yaml only |
| NG-NDPA-003 | HIGH | ndpa | encrypted = false | .tf/.yml/.yaml only |
| NG-NDPA-004 | CRITICAL | ndpa | acl = "public-read" | .tf/.yml/.yaml only |
| NG-NDPA-005 | HIGH | ndpa | protocol = "HTTP" (plaintext listener; "HTTPS" excluded) | .tf/.yml/.yaml only |
| NG-NDPA-006 | HIGH | ndpa | Any AWS region other than af-south-1 (generalises 001/002) | .tf/.yml/.yaml only |
| NG-NDPA-007 | CRITICAL | ndpa | publicly_accessible = true (public database) | .tf/.yml/.yaml only |
| NG-CONT-001 | HIGH | container | USER root | Dockerfiles only |
| NG-CONT-002 | CRITICAL | container | Secret in Dockerfile ENV | Dockerfiles only |
| NG-CONT-003 | WARNING | container | Unpinned image (:latest or no tag) | Dockerfiles only |

## 14. Evaluation Results

- Custom scanner on the vulnerable corpus: 100/100 files detected (finding
  totals vary by generated corpus, roughly 340 to 430, since each file
  receives a random mix of vulnerability templates; the detection rate is the
  stable metric).
- Custom scanner on the clean corpus: 0 findings, even in strict
  fail-on-warning mode (zero false positives).
- Trivy on the same corpus: several hundred CRITICAL/HIGH misconfigurations on
  vulnerable, zero on clean (independent cross-validation with the exact Trivy
  version the pipeline pins, v0.70.0).
- Comparative baseline: a default Gitleaks v8.24.3 scan over the identical
  vulnerable corpus flagged 48/100 files (52 percent file-level miss rate) and
  detected none of the PII, NDPA, or container findings; it matched the custom
  scanner line for line only on conventional secrets (see
  GITLEAKS_COMPARISON.md for method and caveats).
- Comparative baseline (Trivy as competitor rather than cross-validator):
  config scan 65/100 files, secret scan 30/100, combined 95/100, with zero
  coverage of BVNs, data sovereignty, encryption in transit, or Flutterwave
  keys; five extensionless Dockerfiles escaped entirely (see
  TRIVY_COMPARISON.md).
- Unit tests: 40/40 passing; fixtures regenerated deterministically each run.
- Repository self-scan: PASSED (the tool holds itself to its own standard).
- The pipeline re-verifies all of the above on every push via the inverted
  assertions in the evaluation job.

## 15. Technology Stack

| Technology | Use |
|------------|-----|
| Python 3.12 | Scanner engine, generator, tests |
| Regular expressions (compiled once at import) | Detection rules |
| GitHub Actions | CI/CD pipeline |
| Trivy v0.70.0 (action pinned to v0.36.0) | CVE and IaC misconfiguration scanning |
| Docker (python:3.12-slim, non-root) | Dashboard container |
| Streamlit 1.32 | Dashboard UI |
| Altair / Vega-Lite | Charts |
| pandas / pyarrow / numpy (exact pins) | Data handling |
| pytest | Unit tests |
| Streamlit AppTest | Headless dashboard testing |
| git hooks via core.hooksPath | Local commit gate |
| Streamlit Community Cloud | Public dashboard hosting |
