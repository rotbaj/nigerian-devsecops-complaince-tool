# Build Latency Measurement

This document records how the build latency of the compliance scanner was
measured, the results of each method, and how the numbers should be
interpreted. The evaluation criterion is that the compliance stage must
complete within 60 seconds.

All measurements were taken on 2026-07-15 against the 16-rule scanner and the
200-file evaluation corpus (100 vulnerable, 100 clean).

## 1. Why three methods

A single number for "build latency" is misleading because a CI job spends most
of its time on work that is not the tool under evaluation: provisioning the
runner, checking out the repository, setting up Python, and installing
dependencies. Three measurements are therefore reported, from the narrowest
(the scanning engine alone) to the widest (the full CI stage as a stakeholder
sees it on the Actions page). Together they show where the time actually goes.

## 2. Method A: local timed runs of the scanner

The scanner was executed 10 consecutive times on the vulnerable corpus:

```bash
time python compliance_engine/scanner.py evaluation_data/vulnerable
```

Each run scanned 100 files and produced 347 findings. Timing was captured
programmatically with `time.perf_counter()` around a subprocess call, which is
equivalent to the wall-clock `real` value reported by `time`.

| Metric | Value |
|--------|-------|
| Runs | 10 |
| Mean | 0.063 s |
| Range | 0.053 s to 0.089 s |
| Standard deviation | 0.014 s |

Environment: macOS (Apple Silicon), Python 3.12. The first and last runs were
marginally slower (0.089 s), consistent with filesystem cache effects; no run
approached even one second.

This is the latency of the engine itself. The 16 regex rules are compiled once
at import time, so per-file cost is a line-by-line pattern match, and 100 files
complete in tens of milliseconds.

## 3. Method B: CI step durations

GitHub Actions records a duration for every step inside a job. The steps that
actually run the tool were read from the last four successful pipeline runs
(13 to 15 July 2026):

| Step | Duration across 4 runs |
|------|------------------------|
| Run Nigerian Fintech Compliance Engine (repository self-scan) | 0 s in all runs |
| Generate evaluation corpus | 0 s in all runs |
| Scan clean corpus (must pass with zero findings) | 0 s in all runs |
| Scan vulnerable corpus (scanner must catch it) | 0 to 1 s |
| Trivy IaC scan of vulnerable corpus | 5 to 8 s |
| Trivy IaC scan of clean corpus | 3 to 6 s |

GitHub rounds step durations to whole seconds, so "0 s" means under one
second, which agrees with Method A. Note that the two Trivy steps, a
third-party scanner included for cross-validation, take several times longer
than every compliance-engine step combined.

## 4. Method C: CI job (stage) durations

The widest measurement is the wall-clock duration of each job as shown on the
Actions run page. This is what a stakeholder reads as "how long the pipeline
stage took" and includes all environment overhead.

| Run | Trigger | Compliance & Secret Scan | Evaluation Corpus Scan |
|-----|---------|--------------------------|------------------------|
| 13 Jul 2026 | push | 23 s | 56 s |
| 14 Jul 2026 | push | 23 s | 40 s |
| 15 Jul 2026 (#13) | push | 25 s | 44 s |
| 15 Jul 2026 (#14) | manual | 22 s | 35 s |
| Mean | | 23 s | 44 s |
| Range | | 22 to 25 s | 35 to 56 s |

The full six-job pipeline completes in roughly 1 m 24 s to 1 m 35 s of
wall-clock time, but only because independent jobs run in parallel; no single
job exceeded 56 s.

## 5. Where the job time actually goes

Breaking down a representative Compliance & Secret Scan job (25 s total):

| Step | Duration | Nature |
|------|----------|--------|
| Set up job (runner provisioning) | 1 to 3 s | environment overhead |
| Checkout code | 0 to 1 s | environment overhead |
| Set up Python | 0 s | environment overhead |
| Install dependencies (pip install) | 17 to 18 s | environment overhead |
| Run Nigerian Fintech Compliance Engine | 0 s | the tool |
| Upload report artifact | 1 s | reporting |

The single largest cost in every job is `pip install`, at 17 to 18 s, roughly
70 percent of the Compliance & Secret Scan job. The tool under evaluation
contributes under one second.

## 6. Interpretation: overhead versus tool latency

The `pip install` cost is an artifact of how GitHub-hosted runners work: every
job starts on a fresh virtual machine, so dependencies are reinstalled from
scratch on every run. In a real deployment this cost is paid once, not per
build:

- A team running the scanner locally or via the pre-commit hook installs
  dependencies once per machine; every subsequent scan costs only the
  ~0.06 s engine time.
- A self-hosted CI runner keeps its Python environment between builds.
- On GitHub-hosted runners the standard mitigations are `actions/cache` (or
  `actions/setup-python` with `cache: pip`) to restore the pip cache between
  runs, or baking dependencies into a prebuilt Docker image that jobs run in.
- The scanner itself needs only the Python standard library (`re`, `json`,
  `os`, `argparse`, `dataclasses`), so a minimal scan job could skip
  `pip install` entirely; the installed packages serve the dashboard and test
  suite, not the engine.

The overhead was deliberately left unoptimised in this project because even
with it included, every stage meets the threshold, and the unoptimised figure
is the more honest worst case.

## 7. Verdict against the 60-second threshold

| Measurement | Result | Threshold met |
|-------------|--------|---------------|
| Engine alone (local, mean of 10 runs) | 0.063 s | yes |
| Engine as a CI step | 0 to 1 s | yes |
| Compliance & Secret Scan stage, including all overhead | 22 to 25 s | yes |
| Evaluation Corpus Scan stage, including corpus generation, two scanner runs, and two Trivy runs | 35 to 56 s | yes |

The threshold is met on every measurement, at every level of granularity, on
every observed run. The margin at the engine level is roughly three orders of
magnitude; even the widest measurement, a full evaluation stage that runs the
scanner twice and Trivy twice on 200 files, stayed at least 4 s under the
limit with zero caching or optimisation applied.

The local measurement was independently repeated five times and produced the
same results each time, confirming the figures are stable rather than a
one-off observation.

## 8. Reproducing the measurements

```bash
# Method A: local engine timing (run several times, note the "real" value)
time python compliance_engine/scanner.py evaluation_data/vulnerable

# Methods B and C: read durations from the GitHub Actions run page, or via CLI:
gh run list --workflow devsecops-pipeline.yml --limit 5
gh run view <run-id> --json jobs
```

Finding totals vary between generated corpora (roughly 340 to 430), so timing
runs should regenerate the corpus first with `python generate_eval_data.py`
for a like-for-like comparison.
