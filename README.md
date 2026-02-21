# 🛡️ Nigerian Fintech DevSecOps Framework

> Automated security & NDPA 2023 compliance scanning for Nigerian Fintech CI/CD pipelines.

**BSc Cybersecurity Project** | Miva Open University | Oluwadurotimi Bajomo (2024/C/CYB/0973)

---

## Project Structure

```
nigerian-devsecops/
├── .github/
│   └── workflows/
│       └── devsecops-pipeline.yml   ← Full CI/CD pipeline (GitHub Actions)
├── compliance_engine/
│   └── scanner.py                   ← Core scanner (12 rules, CLI + importable)
├── dashboard/
│   └── app.py                       ← Streamlit compliance dashboard
├── tests/
│   ├── fixtures/
│   │   ├── bad_code_sample.py       ← Synthetic bad code (for testing)
│   │   └── bad_terraform.tf         ← Synthetic bad Terraform (for testing)
│   └── test_scanner.py              ← Unit tests (pytest)
├── reports/                         ← JSON scan reports (git-ignored)
├── Dockerfile                       ← App container (dashboard)
├── docker/Dockerfile                ← Scanner-only container
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the scanner (CLI)
```bash
# Scan the whole project
python compliance_engine/scanner.py .

# Scan a single file
python compliance_engine/scanner.py path/to/file.py

# Also fail on warnings
python compliance_engine/scanner.py . --fail-on-warning
```

### 3. Run the dashboard
```bash
streamlit run dashboard/app.py
```
Open http://localhost:8501 in your browser.

### 4. Run tests
```bash
pytest tests/ -v
```

### 5. Run with Docker
```bash
# Build
docker build -t nigerian-devsecops .

# Scan CLI
docker run --rm -v $(pwd):/app nigerian-devsecops python compliance_engine/scanner.py /app

# Dashboard
docker run -p 8501:8501 nigerian-devsecops
```

---

## Detection Rules

| Rule ID     | Severity | Category  | Description                                |
|-------------|----------|-----------|--------------------------------------------|
| NG-SEC-001  | CRITICAL | secret    | Paystack Live Secret Key                   |
| NG-SEC-002  | CRITICAL | secret    | Flutterwave Secret Key                     |
| NG-SEC-003  | WARNING  | secret    | Paystack Public Key (test)                 |
| NG-SEC-004  | CRITICAL | pii       | Hardcoded BVN (11-digit)                   |
| NG-SEC-005  | WARNING  | pii       | Nigerian Phone Number                      |
| NG-NDPA-001 | HIGH     | ndpa      | Data Sovereignty (us-east-1)               |
| NG-NDPA-002 | HIGH     | ndpa      | Data Sovereignty (eu-west)                 |
| NG-NDPA-003 | HIGH     | ndpa      | Encryption at rest disabled                |
| NG-NDPA-004 | CRITICAL | ndpa      | Public S3 Bucket                           |
| NG-CONT-001 | HIGH     | container | Dockerfile running as root                 |
| NG-CONT-002 | CRITICAL | container | Secret in Dockerfile ENV                   |
| NG-CONT-003 | WARNING  | container | Unpinned :latest Docker tag                |

**Pass/Fail:** The build fails (exit code 1) on any CRITICAL or HIGH finding.

---

## CI/CD Pipeline Stages

```
git push
    │
    ▼
Stage 1: Compliance Scan   ← Nigerian secrets + NDPA 2023 rules
    │  (blocks on CRITICAL/HIGH)
    ▼
Stage 2: Container Scan    ← Trivy CVE + IaC misconfiguration scan
    │
Stage 3: Unit Tests        ← pytest
    │
    ▼
Stage 4: Summary Report    ← Posted to GitHub Actions summary
```

---

## Tech Stack

- **Python 3.9** — Compliance engine
- **GitHub Actions** — CI/CD orchestration
- **Docker** — Containerisation
- **Trivy** — CVE & IaC scanning
- **Streamlit** — Compliance dashboard
- **pytest** — Unit testing

---

## Ethical Notice

All credentials, BVNs, phone numbers, and API keys in `tests/fixtures/` are **synthetic and non-functional**, generated solely for educational simulation. No real user data is used anywhere in this project.

---

## Supervisor

Dr. Bolaji Abigail Omodunbi — Miva Open University
