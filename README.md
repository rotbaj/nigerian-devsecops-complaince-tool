# Nigerian Fintech DevSecOps Framework

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
│   └── scanner.py                   ← Core scanner (13 rules, CLI + importable)
├── dashboard/
│   └── app.py                       ← Streamlit compliance dashboard
├── scripts/
│   ├── hooks/pre-commit             ← Compliance gate for local commits
│   └── install-hooks.sh             ← One-time hook setup after cloning
├── tests/
│   ├── fixtures/                    ← Generated synthetic bad files (git-ignored)
│   └── test_scanner.py              ← Unit tests (pytest)
├── generate_eval_data.py            ← Generates test fixtures + 200 evaluation files
├── evaluation_data/                 ← Generated evaluation corpus (git-ignored)
├── reports/                         ← JSON scan reports (git-ignored)
├── Dockerfile                       ← App container (dashboard)
├── requirements.txt
└── README.md
```

---

## How It Works

The tool checks source code for security and compliance problems before the code is merged.
It targets issues specific to Nigerian fintech: hardcoded Paystack and Flutterwave API keys,
BVNs and phone numbers left in source files, data hosted outside approved regions contrary
to NDPA 2023, and insecure Docker configuration. Any CRITICAL or HIGH finding fails the
build with exit code 1, which blocks the merge. WARNING findings are reported but do not block.

The system has three components:

1. Scanner (`compliance_engine/scanner.py`) checks every file against 13 rules.
   It runs from the command line and can also be imported as a module.
2. Pipeline (`.github/workflows/devsecops-pipeline.yml`) runs the scanner on every push
   and pull request, followed by a Trivy scan for known CVEs and infrastructure
   misconfigurations, then the unit tests.
3. Dashboard (`dashboard/app.py`) is a Streamlit page for running scans and browsing
   findings with filters and a category chart.

For evaluation, `generate_eval_data.py` produces 200 synthetic files: 100 vulnerable
(hardcoded keys, non-compliant Terraform, insecure Dockerfiles, privileged Kubernetes
manifests) and 100 clean. The scanner is expected to flag every vulnerable file and
none of the clean ones. All planted credentials are fake and non-functional.

A note on the `--exclude` flag: the synthetic vulnerable files live inside this
repository, so scanning the repository root without excludes will always report a
failure caused by the planted test data rather than the actual source code. When
scanning the project itself, pass `--exclude tests,evaluation_data`. When evaluating
detection, scan `evaluation_data/vulnerable` directly; excludes apply only to
subfolders of the scan target, never to the target itself.

---

## Step-by-Step

Run everything from the project root folder.

1. Install dependencies (once):
```bash
pip install -r requirements.txt
```

2. Generate the test data (once, or whenever you want a fresh set):
```bash
python generate_eval_data.py
```
This writes the 200 evaluation files plus the 2 fixture files the unit tests need.

3. Scan the vulnerable set:
```bash
python compliance_engine/scanner.py evaluation_data/vulnerable
```
Expected result: FAILED, roughly 300 findings across all 100 files, exit code 1.

4. Scan the clean set:
```bash
python compliance_engine/scanner.py evaluation_data/clean
```
Expected result: PASSED, 0 findings, exit code 0.

5. Scan the project's own source code:
```bash
python compliance_engine/scanner.py . --exclude tests,evaluation_data
```
Expected result: PASSED. This is the same command the CI pipeline runs on every push.

6. Run the unit tests:
```bash
pytest tests/ -v
```

7. Start the dashboard:
```bash
streamlit run dashboard/app.py
```
Then open http://localhost:8501 in the browser:
- To show detection, enter `evaluation_data/vulnerable` in the path box and click Run Scan.
  The result is a BUILD FAILED banner with findings you can filter and expand.
- To show a clean run, scan `evaluation_data/clean` instead.
- To check the project itself, leave the defaults unchanged and click Run Scan.
- Load Report mode reopens the results of the previous scan without re-scanning.

---

## Extra Commands

```bash
# Scan a single file
python compliance_engine/scanner.py path/to/file.py

# Treat WARNINGs as failures too (stricter mode)
python compliance_engine/scanner.py . --exclude tests,evaluation_data --fail-on-warning

# Write the JSON report somewhere else
python compliance_engine/scanner.py . --exclude tests,evaluation_data --report my_report.json
```

### Run with Docker
```bash
# Build the image
docker build -t nigerian-devsecops .

# Run the scanner inside the container against your mounted code
docker run --rm -v $(pwd):/app nigerian-devsecops python compliance_engine/scanner.py /app --exclude tests,evaluation_data

# Run the dashboard in the container
docker run -p 8501:8501 nigerian-devsecops
```

---

## Detection Rules

| Rule ID     | Severity | Category  | Description                                          |
|-------------|----------|-----------|------------------------------------------------------|
| NG-SEC-001  | CRITICAL | secret    | Paystack Live Secret Key (sk_live_ + 40 hex)         |
| NG-SEC-002  | CRITICAL | secret    | Flutterwave Secret Key (FLWSECK[_TEST]- + 32 hex -X) |
| NG-SEC-003  | WARNING  | secret    | Paystack Public Key (pk_test_/pk_live_ + 40 hex)     |
| NG-SEC-006  | WARNING  | secret    | Flutterwave Public Key (FLWPUBK- + 32 hex -X)        |
| NG-SEC-004  | CRITICAL | pii       | Hardcoded BVN (context-aware: needs bvn keyword)     |
| NG-SEC-005  | WARNING  | pii       | Nigerian Phone (context-aware: phone/mobile/tel var) |
| NG-NDPA-001 | HIGH     | ndpa      | Data Sovereignty (us-east-1)                         |
| NG-NDPA-002 | HIGH     | ndpa      | Data Sovereignty (eu-west)                           |
| NG-NDPA-003 | HIGH     | ndpa      | Encryption at rest disabled                          |
| NG-NDPA-004 | CRITICAL | ndpa      | Public S3 Bucket                                     |
| NG-CONT-001 | HIGH     | container | Dockerfile running as root                           |
| NG-CONT-002 | CRITICAL | container | Secret in Dockerfile ENV                             |
| NG-CONT-003 | WARNING  | container | Unpinned Docker image (:latest or missing tag)       |

**Scoping to prevent false positives:**
- `ndpa` rules apply only to infrastructure files (`.tf`, `.yml`, `.yaml`) — a code comment mentioning `us-east-1` won't fail the build.
- `container` rules apply only to Dockerfiles — a Python `from x import y` won't match the `FROM` rule.
- BVN/phone rules require keyword context, so arbitrary 11-digit numbers aren't flagged.

**Pass/Fail:** The build fails (exit code 1) on any CRITICAL or HIGH finding.

---

## Pre-Commit Hook (developer machines)

The same scanner that gates the pipeline can gate every local commit, so
issues are caught before the code ever leaves the developer's machine.
One-time setup after cloning:

```bash
sh scripts/install-hooks.sh
```

From then on, `git commit` runs the compliance scan first and blocks the
commit if CRITICAL or HIGH findings exist. The hook prints the findings in
the terminal; to inspect them visually, run the dashboard. In an emergency
a commit can bypass the hook with `git commit --no-verify` — the CI
pipeline will still catch it on push.

---

## CI/CD Pipeline Stages

```
git push
    │
    ▼
Stage 1:  Compliance Scan   ← Nigerian secrets + NDPA 2023 rules
    │     (blocks on CRITICAL/HIGH)
    ▼
Stage 1b: Evaluation Scan   ← clean corpus must pass, vulnerable must be caught
    │
Stage 1c: Publish Results   ← reports pushed to the scan-results branch
    │
    ▼
Stage 2:  Container Scan    ← Trivy CVE + IaC misconfiguration scan
    │
Stage 3:  Unit Tests        ← pytest
    │
    ▼
Stage 4:  Summary Report    ← Posted to GitHub Actions summary
```

### Where to see CI results

- **On the run page:** each pipeline run's Summary tab shows result tables
  for the repository scan and both evaluation scans.
- **In the dashboard:** the pipeline pushes every run's reports and the
  accumulated scan history to the `scan-results` branch. In the dashboard,
  open **Load Report → Latest CI results** and click Fetch — no artifact
  downloads needed. The Compliance Trend chart can then plot the pipeline's
  full history.
- **As artifacts:** each run also uploads `compliance-report` and
  `evaluation-reports` artifacts, which can be dropped into
  **Load Report → Upload a file**.

### Hosting the dashboard for stakeholders

The dashboard can run permanently on Streamlit Community Cloud (free), so
non-technical stakeholders open a URL instead of a terminal:

1. Push this repository to GitHub (public).
2. Go to https://share.streamlit.io and sign in with GitHub.
3. Click **Create app**, pick this repository, branch `main`, and set the
   main file path to `dashboard/app.py`. Deploy.
4. Share the app URL. Viewers use **Load Report → Latest CI results**,
   which reads the `scan-results` branch — the page always reflects the
   most recent pipeline run.

---

## Tech Stack

- **Python 3.12** — Compliance engine
- **GitHub Actions** — CI/CD orchestration
- **Docker** — Containerisation
- **Trivy** — CVE & IaC scanning
- **Streamlit** — Compliance dashboard
- **pytest** — Unit testing

---

## Ethical Notice

All credentials, BVNs, phone numbers, and API keys in `tests/fixtures/` and `evaluation_data/` are **synthetic and non-functional**, generated solely for educational simulation by `generate_eval_data.py`. No real user data is used anywhere in this project.

---

## Supervisor

Dr. Bolaji Abigail Omodunbi — Miva Open University
