# Comparative Baseline: Gitleaks Versus the Custom Scanner

The project's central claim is that generic secret scanners miss the
Nigerian-specific compliance issues this tool detects. This document converts
that claim from an assertion into a measurement: a default-configuration
Gitleaks scan was run over the same evaluation corpus the custom scanner is
evaluated on, and the miss rate was recorded.

## 1. Method

- Comparison tool: Gitleaks v8.24.3 (the most widely used open-source secret
  scanner), default configuration, no custom rules.
- Corpus: the same generated evaluation corpus used for the project's own
  baseline, 100 vulnerable and 100 clean files (30 Python, 19 Terraform,
  33 Kubernetes manifests, 18 Dockerfiles in the vulnerable half of the run
  measured here).
- Commands:

```bash
gitleaks dir evaluation_data/vulnerable --report-format json --report-path gitleaks_vulnerable.json
gitleaks dir evaluation_data/clean --report-format json --report-path gitleaks_clean.json
```

- Reference: the custom scanner's results on the identical corpus
  (347 findings, 100/100 files detected, 0 findings on clean).
- Date of measurement: 2026-07-15.

## 2. Headline results

| Metric | Custom scanner | Gitleaks (default) |
|--------|----------------|--------------------|
| Vulnerable files flagged (of 100) | 100 | 48 |
| File-level miss rate | 0 percent | 52 percent |
| Total findings on vulnerable corpus | 347 | 78 |
| False positives on clean corpus | 0 | 0 |

Gitleaks flagged no Terraform file (0 of 19) and no Kubernetes manifest
(0 of 33). Every missed file contains planted violations that the custom
scanner and Trivy both detect.

## 3. What Gitleaks found, by rule

| Gitleaks rule | Findings | What it actually matched |
|---------------|----------|--------------------------|
| stripe-access-token | 30 | Paystack live secret keys in Python files |
| generic-api-key | 48 | Flutterwave secret keys in Python files and Dockerfile ENV lines |

Two observations follow:

1. The 78 Gitleaks findings are exactly the 78 secret-category findings of the
   custom scanner, line for line. On pure secret detection over this corpus,
   the two tools agree completely.
2. The Paystack detections are an accident of format collision: Paystack
   modelled its key format on Stripe's, so Gitleaks matched `sk_live_...`
   with its Stripe rule and reported the wrong provider. The Flutterwave keys
   were caught only by the low-specificity entropy heuristic
   (`generic-api-key`), not by any provider-aware rule. Correct identification
   matters operationally, because remediation (which dashboard to rotate the
   key in, which provider to notify) depends on knowing what leaked.

## 4. What Gitleaks missed

By the custom scanner's categories on the same corpus:

| Category | Custom scanner findings | Gitleaks findings | Coverage |
|----------|------------------------|-------------------|----------|
| secret | 78 | 78 | 100 percent |
| pii (hardcoded BVNs) | 30 | 0 | 0 percent |
| ndpa (regions, encryption, public storage, plaintext HTTP, public database) | 185 | 0 | 0 percent |
| container (root user, ENV secrets, unpinned images) | 54 | 0 (the 18 Dockerfile ENV secret lines were caught, but as generic secrets, not as container misconfigurations) | 0 percent of the configuration issues |

Concretely invisible to Gitleaks: every BVN, every data-sovereignty violation,
every `encrypted = false`, every public S3 ACL, every plaintext HTTP listener,
every publicly accessible database, every plaintext database password in a
Kubernetes env block, every root container, and every unpinned image. Of the
custom scanner's 347 findings, 269 (77.5 percent) belong to categories a
secret scanner does not model at all.

## 5. Fairness caveats

Recorded so the comparison cannot be accused of being rigged:

1. The corpus Terraform files embed the AWS documentation example access key
   (`AKIAIOSFODNN7EXAMPLE`), chosen deliberately so the committed generator is
   de-fanged. Gitleaks allowlists that exact example key. A control experiment
   confirmed this: given one file with the example key and one with a
   realistic-format AKIA key, Gitleaks flagged only the realistic one. With
   realistic keys planted, Gitleaks would additionally flag the 19 Terraform
   files (file-level detection 67 of 100). The 33 Kubernetes manifests would
   remain unflagged, and no compliance category would gain any coverage.
2. Gitleaks is a secret scanner by design; PII, data sovereignty, and
   container configuration are outside its stated scope. That is precisely the
   point being measured: a Nigerian fintech that relies on a generic secret
   scanner for compliance has zero coverage of its NDPA obligations, and the
   measured 52 percent file-level miss rate quantifies the gap this project
   exists to close.
3. Gitleaks also produced zero false positives on the clean corpus, matching
   the custom scanner. The comparison does not claim Gitleaks is a bad secret
   scanner; it claims secret scanning alone is insufficient for this
   regulatory context.

## 6. Conclusion

Measured on an identical corpus, a default Gitleaks scan misses 52 of 100
vulnerable files entirely and detects 0 of the 269 compliance-category
findings (PII, NDPA, container). Where the corpus contains conventional
secrets, the two tools agree line for line, so the custom scanner loses
nothing on the problem Gitleaks solves while adding the categories it does
not. This converts the project's motivating claim from asserted to measured.

## 7. Reproducing

```bash
python generate_eval_data.py
python compliance_engine/scanner.py evaluation_data/vulnerable   # reference results
gitleaks dir evaluation_data/vulnerable --report-format json --report-path gitleaks_vulnerable.json
gitleaks dir evaluation_data/clean --report-format json --report-path gitleaks_clean.json
```

Finding counts vary between generated corpora because each file receives a
random mix of templates; the category coverage result (zero on pii, ndpa, and
container) is stable because it follows from Gitleaks' rule set, not from the
random draw.
