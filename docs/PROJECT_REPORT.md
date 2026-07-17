# Nigerian Fintech DevSecOps Compliance Framework: Development Report

BSc Cybersecurity Project, Miva Open University
Author: Oluwadurotimi Bajomo (2024/C/CYB/0973)
Supervisor: Dr. Bolaji Abigail Omodunbi

This document is a complete account of how the project was built: what exists in the
repository, why each part exists, every significant problem encountered during
development, how each was diagnosed, and how each was solved or worked around. It is
written as source material for the dissertation.

---

## 1. Problem Statement and Aim

Nigerian fintech companies operate under regulatory obligations that generic security
tools do not address:

- The Nigeria Data Protection Act (NDPA) 2023 imposes duties on how customer data is
  stored, including where it is hosted and whether it is encrypted at rest.
- The dominant local payment providers, Paystack and Flutterwave, issue API keys with
  distinctive formats. A leaked live secret key gives an attacker direct access to
  payment operations.
- Nigerian-specific personally identifiable information (PII), most notably the Bank
  Verification Number (BVN, an 11-digit national banking identifier) and Nigerian
  mobile numbers, is routinely handled by fintech codebases and must never be
  hardcoded in source files.

Generic secret scanners know nothing about BVNs, Paystack key formats, or NDPA data
sovereignty. The aim of this project was to build a DevSecOps toolchain that enforces
these Nigerian-specific compliance requirements automatically at three points in the
software delivery lifecycle: on the developer's machine before code is committed, in
the CI/CD pipeline before code is merged, and on a dashboard where non-technical
stakeholders (CTO, business team leads) can see the compliance position without
reading pipeline logs.

## 2. System Architecture

The delivered system has five components:

1. **Compliance scanner** (`compliance_engine/scanner.py`): a regex-based static
   analysis engine with 16 rules across four categories (secret, pii, ndpa,
   container). It is both a CLI tool and an importable module. Any CRITICAL or HIGH
   finding causes exit code 1, which fails a build.
2. **Evaluation data generator** (`generate_eval_data.py`): produces a 200-file
   synthetic corpus (100 vulnerable, 100 clean) used to measure detection accuracy,
   plus two deterministic fixture files used by the unit tests.
3. **CI/CD pipeline** (`.github/workflows/devsecops-pipeline.yml`): six GitHub
   Actions jobs covering the repository self-scan, the evaluation corpus scan (both
   the custom scanner and Trivy), publication of results, container image scanning,
   unit tests, and a summary.
4. **Streamlit dashboard** (`dashboard/app.py`): runs scans interactively, loads
   reports, fetches the latest CI results over HTTPS, shows a compliance trend over
   time, and presents Trivy results, all with plain-language labels for
   non-technical stakeholders. Deployed publicly on Streamlit Community Cloud.
5. **Pre-commit hook** (`scripts/hooks/pre-commit`, installed by
   `scripts/install-hooks.sh`): runs the scanner before every local commit and blocks
   the commit on CRITICAL or HIGH findings.

The three enforcement layers mirror how commercial DevSecOps products (SonarQube,
Snyk) are deployed: earliest feedback locally, non-bypassable enforcement in CI, and
a persistent reporting surface for management. A sixth supporting element, the
`scan-results` git branch, acts as the data feed between CI and the dashboard.

## 3. The Scanner Engine

### 3.1 Rule set

16 rules, each with an ID, severity, category, regex pattern, description, and
remediation text:

| Rule ID | Severity | Category | Detects |
|---------|----------|----------|---------|
| NG-SEC-001 | CRITICAL | secret | Paystack live secret key (`sk_live_` + 40 hex) |
| NG-SEC-002 | CRITICAL | secret | Flutterwave secret key (`FLWSECK[_TEST]-` + 32 hex + `-X`) |
| NG-SEC-003 | WARNING | secret | Paystack public key (`pk_test_`/`pk_live_` + 40 hex) |
| NG-SEC-006 | WARNING | secret | Flutterwave public key (`FLWPUBK-` + 32 hex + `-X`) |
| NG-SEC-004 | CRITICAL | pii | Hardcoded BVN (context-aware) |
| NG-SEC-005 | WARNING | pii | Nigerian phone number (context-aware) |
| NG-NDPA-001 | HIGH | ndpa | Data hosted in us-east-1 |
| NG-NDPA-002 | HIGH | ndpa | Data hosted in eu-west regions |
| NG-NDPA-003 | HIGH | ndpa | Encryption at rest disabled |
| NG-NDPA-004 | CRITICAL | ndpa | Public S3 bucket |
| NG-NDPA-005 | HIGH | ndpa | Encryption in transit not enforced (plaintext HTTP) |
| NG-NDPA-006 | HIGH | ndpa | Data hosted outside af-south-1 (generalises 001/002) |
| NG-NDPA-007 | CRITICAL | ndpa | Publicly accessible database |
| NG-CONT-001 | HIGH | container | Dockerfile running as root |
| NG-CONT-002 | CRITICAL | container | Secret in Dockerfile ENV |
| NG-CONT-003 | WARNING | container | Unpinned Docker image (`:latest` or missing tag) |

NG-NDPA-006 generalises the narrower region checks NG-NDPA-001 and NG-NDPA-002,
which are retained for their specific remediation text. The overlap never
double-counts in the evaluation metric because detection is measured per file,
not per finding.

Findings redact the matched line content in saved reports so a scan report is never
itself a secrets leak.

### 3.2 Problem: 11-digit false positives on the BVN rule

A naive BVN rule (any 11-digit number) flags order IDs, timestamps, and phone
numbers. Solution: the rule requires a BVN-related keyword (`bvn`,
`bank_verification`, or `biometric`) within 40 characters of the number, in either
direction, and uses lookaround assertions `(?<![0-9])` and `(?![0-9])` so that a
12-digit number is never treated as an 11-digit BVN:

```
(?:bvn|bank_verification|biometric).{0,40}(?<![0-9])[0-9]{11}(?![0-9])
|(?<![0-9])[0-9]{11}(?![0-9]).{0,40}(?:bvn|bank_verification|biometric)
```

The phone rule (NG-SEC-005) similarly requires an assignment context: a variable
name containing `phone`, `mobile`, or `tel` followed by `:` or `=`, then a valid
Nigerian mobile pattern (`+234` or `0`, then `7/8/9`, then `0/1`, then 8 digits, with
a lookahead rejecting longer digit runs). A unit test confirms that a Nigerian phone
number does not trigger the BVN rule and that a 12-digit number near a BVN keyword
is not flagged.

### 3.3 Problem: Python imports flagged as Docker misconfigurations

After broadening the NG-CONT-003 pattern to catch untagged `FROM image` lines, every
Python `from x import y` statement matched it. Solution: rule scoping. Container
rules only run on files whose basename starts or ends with `dockerfile`
(case-insensitive), and NDPA rules only run on infrastructure file types (`.tf`,
`.yml`, `.yaml`). This also fixed a second false-positive class: a code comment
mentioning `us-east-1` in a Python file no longer fails the build. Both scopes are
covered by regression tests.

### 3.4 Problem: the CI self-scan was silently scanning nothing

The original directory walker skipped any path whose components included a dot
directory. The path `"."` itself matched that check, so `scan_path(".")` scanned 0
files and always passed. The CI pipeline's main gate had therefore never actually
scanned anything. Solution: in-place pruning of `os.walk`'s directory list
(`dirs[:] = [...]`), which skips unwanted directories at any depth without
misclassifying the root. A regression test asserts that a dot-path scan finds files.
A related deliberate decision: `.github/` is NOT skipped even though it is a dot
directory, because pipeline YAML is a primary supply-chain attack surface. That is
also tested.

### 3.5 Problem: the scanner kept flagging its own repository

Three separate incidents, three fixes:

1. The evaluation corpus and test fixtures intentionally contain synthetic secrets,
   so a repository self-scan always failed. Fix: an `--exclude` CLI flag
   (comma-separated directory names pruned at any depth). CI, the pre-commit hook,
   and the dashboard default all use `--exclude tests,evaluation_data,reports`.
2. The generator's own source code contained the secret templates it writes, so the
   scanner flagged the generator. Fix: de-fanging. The generator assembles keys from
   concatenated string pieces (for example `"225" + "2268" + "3105"` for a BVN) so
   no complete secret pattern appears in its source. The scanner's own documentation
   comments were de-fanged the same way.
3. Late in the project, the repository self-scan suddenly failed with 16 CRITICAL
   findings. Diagnosis: Trivy's JSON report (`reports/trivy_vulnerable.json`) quotes
   the offending source lines verbatim, including the synthetic Flutterwave keys,
   and the scanner was reading one scanner's report as input to another. Left
   unfixed, the pre-commit hook would have blocked every future commit. Fix:
   `reports/` was added to the standard exclude list everywhere the repository scans
   itself. This incident is a concrete illustration of output-as-input contamination
   between security tools.

### 3.6 Performance

Patterns are compiled once at import time rather than on every line. This was one of
five findings from a mid-project design review (along with the `.github` visibility
decision, NDPA scoping, removal of a redundant Flutterwave pattern, and the untagged
FROM detection).

## 4. The Evaluation Corpus

### 4.1 Design

`generate_eval_data.py` writes 100 vulnerable and 100 clean files with realistic
names (`core_payment_service_12.py`, `aws_infrastructure_38.tf`,
`k8s_deployment_7.yml`, `Dockerfile_api_44`). Vulnerable templates cover every
scanner rule plus misconfigurations that Trivy's IaC scanner detects independently:
hardcoded cloud provider credentials (the synthetic AWS documentation example key),
security groups open to 0.0.0.0/0 including SSH, publicly accessible unencrypted RDS
with a plaintext password, wildcard IAM policies, privileged Kubernetes pods sharing
host namespaces, root containers, curl piped into a shell, world-writable
permissions, and secrets in image layers. All credentials are synthetic and
non-functional.

The generator deletes and recreates its output directories on every run, because
filenames vary between runs and stale files would otherwise skew counts. It also
writes two deterministic fixture files used by pytest, so the unit tests never
depend on the random corpus.

### 4.2 Problem: the corpus cannot be committed

The corpus is 200 files of realistic-looking secrets. Committing it to a public
repository would trip GitHub's own secret scanning and any reviewer's alarm, and the
project's own pipeline would have to exclude it anyway. Solution: `evaluation_data/`
and `tests/fixtures/` are git-ignored, and every consumer regenerates them on
demand: the CI evaluation job runs the generator before scanning, the test job runs
it before pytest, and the dashboard generates the corpus automatically the first
time someone asks to scan it (necessary on Streamlit Cloud, where the deployed app
is a fresh clone that has no corpus). The generator script is the single committed
source of truth.

### 4.3 Problem: Trivy flagged the CLEAN corpus

The CI Trivy scan of the clean corpus reported five HIGH misconfigurations per
Terraform file (four missing public-access-block checks and one missing
customer-managed-key encryption check). Investigation showed two distinct causes:

1. A genuine gap: the clean template's S3 bucket had no customer-managed KMS
   encryption, so check AVD-AWS-0132 failed legitimately. Fix: the clean template
   now creates a KMS key with rotation enabled and an
   `aws_s3_bucket_server_side_encryption_configuration` using it.
2. A scan-context artifact: every clean file declared resources with identical
   names, and Trivy parses a scanned folder as a single Terraform root module.
   Forty duplicate `aws_s3_bucket.user_kyc_documents` addresses collapsed together,
   and only one bucket kept its `aws_s3_bucket_public_access_block` association;
   the other 39 appeared unprotected. The tell-tale evidence was that exactly one
   file in the CI log showed 1 failure while all others showed 5. Fix: the
   generator suffixes each file's resource names with the file number so every
   bucket keeps its own protections.

After the fix, the clean corpus passes Trivy with zero CRITICAL/HIGH
misconfigurations in every file, verified locally with the same Trivy version the
pipeline pins before pushing.

## 5. The CI/CD Pipeline

### 5.1 Stages

```
git push
    |
Stage 1:  Compliance Scan      repository self-scan, blocks on CRITICAL/HIGH
    |
Stage 1b: Evaluation Scan      clean corpus must pass, vulnerable must be caught,
    |                          by both the custom scanner and Trivy
Stage 1c: Publish Results      reports pushed to the scan-results branch
    |
Stage 2:  Container Scan       Docker image CVE scan + repository IaC scan (Trivy)
    |
Stage 3:  Unit Tests           pytest (fixtures regenerated first)
    |
Stage 4:  Summary              tables rendered on the Actions run page
```

Pipeline hardening applied during development: the Trivy action is pinned to a
specific version (v0.36.0) rather than a floating tag, Python is pinned to 3.12
(3.9 reached end of life in October 2025), the push/pull_request triggers were
re-enabled after being found commented out, and all dependencies in
`requirements.txt` are pinned to exact versions.

### 5.2 Inverted assertions: testing that detection works

The evaluation job scans the clean corpus first (with `--fail-on-warning`, so even
one false positive fails the job), then the vulnerable corpus. For the vulnerable
corpus, exit code 1 is the CORRECT outcome, so the step inverts the logic: the job
fails only if the scan PASSES. The same technique is used for Trivy via
`continue-on-error: true` on the scan step and a follow-up step that asserts the
outcome was `failure`. This turns the CI pipeline itself into a continuous
evaluation harness: every push re-proves the 100/100 detection rate and the
zero-false-positive rate.

### 5.3 Problem: how do stakeholders see results if CI is headless?

A CI runner has no browser and is destroyed when the job ends, so the dashboard
cannot "run in CI". The commercial pattern (SonarQube) is that CI pushes results to
a persistent reporting service. Implemented equivalent: a `publish-results` job
force-pushes every run's report JSONs plus an accumulated `scan_history.json` to a
dedicated `scan-results` branch. The job carries the existing history forward by
reading the branch before overwriting it, merging new entries with deduplication on
(timestamp, target). The dashboard then fetches these files over plain HTTPS from
`raw.githubusercontent.com/<repo>/scan-results/<file>`, which works identically
from a laptop or from Streamlit Cloud with no git operations and no authentication
(the repository is public). The publish job runs even when scans fail, because
failed scans are exactly what a dashboard must show, and is skipped on pull
requests because forked PRs have no write access.

### 5.4 Problem: the Trivy image scan failed on real CVEs

Once the container job ran on GitHub, Trivy found 5 HIGH vulnerabilities in the
dashboard image's Python dependencies: three in pillow (PSD out-of-bounds write,
FITS decompression bomb, PSD code execution), one in protobuf (recursion DoS), one
in pyarrow (use-after-free DoS). The pipeline was doing its job: blocking a
vulnerable image. The complication: all three packages are transitively pinned by
Streamlit 1.32 (which requires pillow below 11 and protobuf below 5), and the fixed
versions (pillow 12.x, protobuf 5.29+, pyarrow 23) are incompatible with that
stack. True remediation meant replatforming the dashboard.

Decision: formal risk acceptance. A `.trivyignore` file lists the five CVEs, each
with a written justification (the dashboard processes no user-uploaded images and
no untrusted Arrow/protobuf payloads, so no attack path reaches the vulnerable
code) and a review date. The image scan references the file explicitly. For the
dissertation this demonstrates the full vulnerability management loop: detect,
assess exploitability in context, formally accept or remediate, document, schedule
re-review.

### 5.5 Problem: Trivy could not write its output file

The container job failed with `unable to write results: open
reports/trivy_image.json: no such file or directory`. Cause: `reports/` is
git-ignored so a fresh CI checkout does not contain it, and Trivy does not create
output directories. The evaluation job never hit this because the compliance
scanner runs first there and creates the directory. Fix: a `mkdir -p reports` step
before the image scan.

### 5.6 Problem: pipeline results vanish from logs when exporting JSON

Switching the Trivy steps from table output to JSON (needed for the dashboard)
removed the human-readable tables from the CI logs. Compensation: the run-page
summary step parses the JSON files and renders markdown tables (files scanned,
findings by severity, detection verdicts) directly on the Actions run Summary tab,
so nobody needs to open logs at all.

## 6. The Dashboard

### 6.1 Purpose and audience

The dashboard is explicitly designed for non-technical stakeholders. Design
decisions that followed from this: plain-language status banners ("this code
contains issues that could expose customer data or payment credentials"), headline
metric cards with change-versus-previous-scan deltas (inverse-colored, because for
security issues a decrease is good), friendly category names ("Hardcoded secrets",
"Personal data (PII)", "NDPA / data sovereignty", "Container security") instead of
internal codes, help tooltips on every input, and captions explaining what each
chart means.

### 6.2 Problem: results disappeared when the user touched any control

User-reported bug: clicking "Sort by file name" made all results vanish. Cause:
Streamlit reruns the entire script on every widget interaction, and a button only
reads True on the run immediately after the click, so the scan results ceased to
exist on the next rerun. Fix: scan results are stored in `st.session_state` and
read back on every rerun. Sorting, filtering, and every later feature depend on
this. Five sorting scenarios (including sorting combined with severity filters and
sorting in Load Report mode) are covered by an automated headless test.

### 6.3 Problem: chart looked correct in tests but rendered blank in the browser

The compliance trend chart needed axis titles, which `st.line_chart` in Streamlit
1.32 cannot do, so it was rebuilt in Altair. The user then asked for hour-level
tick marks. The first implementation used Vega-Lite's documented
`tickCount: {interval: "hour", step: 1}` syntax. Automated checks that inspected
the generated chart specification passed, but the browser showed a completely
blank chart.

Diagnosis required reproducing the browser's rendering pipeline outside the
browser: the exact chart spec was extracted from the running app, then compiled
and rendered in Node.js with the same vega-lite/vega libraries the frontend uses.
This reproduced the failure exactly: the interval-object form of `tickCount`
throws a TypeError inside Vega's axis-tick generation at render time, which kills
the whole chart. The spec is valid; the runtime is not able to execute it. A
second issue surfaced during the same investigation: the string form
`tickCount: "hour"` does not snap ticks to hour boundaries either; it relabels
minute-level ticks, producing the same label repeated six times.

Fix: compute the tick positions in Python. The dashboard floors and ceils the
scan-time range to hour boundaries, generates the tick list itself, caps it at
roughly 12 ticks by widening the step for long histories, and passes explicit
tick values to the axis. Verification was upgraded permanently: chart changes are
now validated by actually rendering the spec to SVG in Node and inspecting the
output, not by inspecting the specification alone. The lesson recorded for the
write-up: for declarative visualization stacks, a valid specification does not
guarantee a successful render, and tests must exercise the renderer.

### 6.4 Problem: chart colors and accessibility

Severity colors were chosen as a sequential dark-to-light ramp rather than a
categorical red/amber/gold trio, because the initial categorical palette failed a
computational check for color-vision-deficiency separability. The final steps
(#9f1710, #c05702, #997400) have monotonically increasing lightness and at least
3:1 contrast on white, validated by script rather than by eye.

### 6.5 Problem: absolute filesystem paths leaked into the UI

Scan targets, history entries, and finding locations displayed full local paths
(`/Users/<name>/Desktop/...`). Fix: a `repo_relative()` helper renders every path
relative to the project root; the repository root itself displays as the project
name. Old history entries holding absolute paths are normalized at load time so
they merge with new entries instead of appearing as a duplicate scan target. The
scan input now defaults to `.` and resolves relative paths against the project
root, so the same input works regardless of the working directory streamlit was
launched from.

### 6.6 Problem: pyarrow segfault crashed the dashboard

During headless testing the app process died with exit code 139 (segmentation
fault) inside `st.bar_chart`. Diagnosis with `python3 -X faulthandler` traced the
crash to `pyarrow.pandas_compat`: an unpinned pyarrow had resolved to 25.x, whose
binary interface is incompatible with pandas 2.2.0. Fix: pin `pyarrow==15.0.0`.
The same class of problem was prevented for the cloud deployment by also pinning
`numpy==1.26.4` and `altair==5.5.0`, because Streamlit Cloud resolves dependencies
from scratch and unpinned numpy would land on 2.x, which breaks pandas 2.2.0.

### 6.7 CI results in the dashboard

Load Report mode has three sources: fetch the latest CI results from the
`scan-results` branch (default; the repository slug is auto-detected from the git
remote, with a hardcoded fallback for the cloud deployment where no usable remote
exists), upload a report file downloaded from a CI artifact, or open the local
report. Fetching CI results also pulls the pipeline's accumulated history, and the
trend section then offers a history-source toggle (CI pipeline or this computer).
A dedicated Trivy section renders the pipeline's second-scanner results in three
tabs (Docker image CVEs, vulnerable corpus, clean corpus), each with severity
metric cards and a severity-sorted table with columns Severity, Issue, Where, and
How to fix. Each tab carries a one-line expectation caption so a non-technical
reader knows that findings on the vulnerable corpus are expected proof of
detection, not a live problem.

### 6.8 Deployment to Streamlit Community Cloud

The dashboard is deployed from the `main` branch with main file `dashboard/app.py`
on Python 3.12. Issues found and fixed for the hosted context: the evaluation
corpus does not exist in a fresh clone (solved by on-demand generation with a
spinner), git-remote detection can fail (solved by the fallback repository slug),
and dependency resolution differs from the development machine (solved by the
extra pins). A deployment consideration recorded for the write-up: the app URL is
public and shows scan results by design; the findings are synthetic evaluation
data, but a deployment against a real codebase would use a private app instead.

## 7. The Pre-Commit Hook

The hook runs the repository self-scan before every commit and blocks the commit
on CRITICAL or HIGH findings, printing the findings and the command to open the
dashboard for a visual view. Design points worth writing up:

- The hook must not launch the dashboard itself. Git hooks are blocking and
  non-interactive; `streamlit run` starts a server that never exits, which would
  hang every commit forever. The hook prints instructions instead.
- Git deliberately never activates hooks from a cloned repository (cloning
  malicious code must not execute scripts), so hooks cannot be "committed" in the
  usual sense. Solution: the hook lives in `scripts/hooks/` under version control,
  and a one-time installer sets `git config core.hooksPath scripts/hooks`. Each
  clone runs `sh scripts/install-hooks.sh` once.
- The hook fires on commit, not push, because commits are where bad code enters
  history. The documented emergency bypass (`git commit --no-verify`) is
  acceptable because CI re-scans everything on push and cannot be bypassed. This
  layered arrangement (convenient local gate, authoritative remote gate) is the
  standard shift-left pattern.

## 8. Testing and Verification Methodology

- **Unit tests**: 40 pytest tests covering every rule, both context-aware PII
  rules' negative cases, rule scoping, the dot-path regression, exclude behavior,
  `.github` visibility, report redaction, and fixture-based end-to-end scans.
  Fixtures are regenerated deterministically before every test run, locally and
  in CI.
- **Headless dashboard testing**: Streamlit's `AppTest` framework drives the real
  app without a browser: setting inputs, clicking the scan button, switching
  modes, changing sort order and filters, and asserting on rendered elements
  (metrics, expanders, tables, charts). Suites cover layout order, history and
  trend behavior across multiple scans and targets, all five sorting scenarios,
  and the Trivy section (using real Trivy JSON as input).
  One known limitation: AppTest cannot drive `st.file_uploader`, so the upload
  path is verified by injecting state and by manual use.
- **Renderer-level chart verification**: after the blank-chart incident, chart
  specs are compiled and rendered to SVG with the actual vega-lite/vega libraries
  in Node.js, and the SVG is inspected for tick labels and drawn series.
- **Local Trivy verification**: the exact Trivy version the pipeline pins
  (v0.70.0) was run locally as a standalone binary against the regenerated corpus
  before pushing, confirming zero CRITICAL/HIGH on clean and several hundred on
  vulnerable, so CI outcomes were known in advance rather than discovered from
  failed runs.
- **Comparative baseline (Gitleaks)**: a default-configuration Gitleaks v8.24.3
  scan over the identical vulnerable corpus flagged 48 of 100 files (52 percent
  file-level miss rate) and 0 of the 269 compliance-category findings (PII,
  NDPA, container). Its 78 findings coincide line for line with the custom
  scanner's 78 secret-category findings, and its Paystack detections are an
  accident of format collision with Stripe's key prefix. Full method, results,
  and fairness caveats: docs/GITLEAKS_COMPARISON.md. This measurement converts
  the project's motivating claim (generic scanners miss Nigerian-specific
  compliance issues) from asserted to measured.
- **Comparative baseline (Trivy)**: the same head-to-head was run against
  Trivy v0.70.0 in both its modes. Its misconfiguration scan flagged 65 of
  100 files (no Python file, and only 13 of 18 Dockerfiles due to a filename
  convention); its secret scan flagged 30 (the Paystack keys, again via the
  Stripe format collision). Combined coverage 95/100 at file level, but 0
  coverage of BVNs, data sovereignty (no region-localisation check exists in
  Trivy at any severity), encryption in transit, and Flutterwave keys. Full
  method and tables: docs/TRIVY_COMPARISON.md. Together with the Gitleaks
  study, both dominant classes of generic scanner are measured, not assumed.
- **Evaluation baseline**: 100/100 vulnerable files detected by the custom
  scanner (finding totals vary between generated corpora, roughly 340 to 430,
  because each file receives a random mix of vulnerability templates; the
  detection rate and the zero-false-positive result are the stable metrics).
  0 findings on the 100-file clean corpus even in strict fail-on-warning mode.
  Trivy independently confirms the corpus design: hundreds of CRITICAL/HIGH
  misconfigurations on vulnerable, zero on clean.

## 9. Tool Limitations Encountered and Workarounds

| Tool / platform | Limitation | Workaround |
|---|---|---|
| Streamlit 1.32 | Script reruns on every widget interaction; button state is transient | Persist results in `st.session_state` |
| Streamlit 1.32 | `st.line_chart` has no axis titles | Rebuild charts in Altair |
| Vega/Vega-Lite runtime | Valid `tickCount` interval spec crashes at render time; string interval mislabels minute ticks | Compute explicit hour-boundary tick values in Python; verify by rendering, not spec inspection |
| Streamlit AppTest | Cannot drive file uploads | State injection plus manual verification |
| Streamlit Cloud | Fresh clone lacks git-ignored data and local dependency versions | On-demand corpus generation; full dependency pinning; fallback repo slug |
| pyarrow/pandas/numpy | Unpinned ABI-incompatible versions segfault | Exact pins with explanatory comments in requirements.txt |
| Trivy (config scan) | Parses a folder as one Terraform module; duplicate resource addresses break associations | Unique per-file resource names in generated corpus |
| Trivy (CLI) | Does not create output directories | `mkdir -p reports` step in CI |
| Trivy (image scan) | Fixed CVE versions incompatible with pinned app stack | Documented risk acceptance via `.trivyignore` with review date |
| trivy-action | One output format per step; JSON export removes log tables | Render summary tables from JSON on the run Summary page |
| GitHub Actions | Runners are headless and ephemeral; no dashboard can live there | Publish results to a `scan-results` branch; dashboard fetches over HTTPS |
| GitHub Actions | Forked PRs cannot write to the repository | Publish job skipped on pull_request events |
| git | Hooks are not cloned/activated automatically (by design) | Versioned hooks directory plus `core.hooksPath` installer |
| Regex-based scanning | A scanner's own artifacts (reports quoting findings, test data, its own source) trigger it | Exclude lists, de-fanged construction of test secrets, redacted report output |

## 10. Security Hygiene Issues Found in the Project Itself

Two incidents during development are themselves useful material on secure
development practice:

1. The repository originally had no `.gitignore`; scan reports and generated
   secret-bearing test data could have been committed. Fixed early with a
   comprehensive ignore file (reports, evaluation data, fixtures, caches,
   environments, editor directories).
2. The local git remote URL was found to contain an embedded personal access
   token, stored in plaintext in `.git/config`. The remediation advice recorded:
   strip the token from the URL, authenticate through the OS keychain or the
   GitHub CLI instead, and revoke the exposed token. This mirrors exactly the
   class of leak the project's scanner exists to catch.

## 11. Presentation Standards

Two repository-wide conventions were applied for the academic setting:

- No emojis anywhere in code, workflow, scripts, or documentation, with one
  functional exception: the red, orange, and yellow circle symbols directly
  beside CRITICAL, HIGH, and WARNING labels (dashboard metrics, finding lists,
  CLI summary, CI summary tables), because they encode severity at a glance.
- No em dashes anywhere in the repository; all 76 occurrences across 10 files
  were reworded using colons, semicolons, commas, or restructured sentences,
  including the templates that generate the evaluation corpus.

## 12. Final State and Reproducibility

To reproduce the entire evaluation from a fresh clone:

```bash
pip install -r requirements.txt
python generate_eval_data.py
python compliance_engine/scanner.py evaluation_data/vulnerable   # expect FAILED, exit 1
python compliance_engine/scanner.py evaluation_data/clean        # expect PASSED, exit 0
python compliance_engine/scanner.py . --exclude tests,evaluation_data,reports  # expect PASSED
pytest tests/ -v                                                 # expect 40 passed
streamlit run dashboard/app.py
sh scripts/install-hooks.sh                                      # enable the commit gate
```

Every push to `main` re-runs the full pipeline: self-scan, dual-scanner
evaluation, results publication, image scan, tests, and summary. The hosted
dashboard reflects the newest pipeline run as soon as anyone clicks "Fetch latest
CI results".

## 13. Mapping to Dissertation Themes

- **Detection accuracy and evaluation design**: sections 3.2, 3.3, 4, 8
  (context-aware rules, scoping, synthetic corpus, inverted CI assertions,
  100/100 and 0-false-positive baseline).
- **Shift-left security**: section 7 (pre-commit gate) plus the CI backstop
  argument.
- **Defense in depth / multi-scanner validation**: sections 5.2, 5.4, 6.7 (custom
  scanner plus Trivy over the same corpus, image scanning, cross-confirmation).
- **Risk management practice**: section 5.4 (detect, assess, formally accept,
  document, schedule review).
- **Regulatory specificity**: sections 1, 3.1 (NDPA data sovereignty and
  encryption rules, BVN and Nigerian phone PII, local payment provider key
  formats).
- **Stakeholder communication**: sections 5.3, 6 (headless CI to persistent
  dashboard pattern, plain-language design, trend over time).
- **Engineering rigor and honest failure analysis**: sections 3.4, 3.5, 4.3, 6.3
  (the silent no-op scan, self-flagging incidents, the Trivy module-parsing
  artifact, the spec-valid-but-render-broken chart), each with diagnosis method
  and fix.
