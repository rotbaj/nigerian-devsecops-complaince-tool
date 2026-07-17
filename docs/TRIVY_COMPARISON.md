# Comparative Baseline: Trivy Versus the Custom Scanner

Trivy already runs inside the pipeline, but in the role of a cross-validator:
its agreement on the corpus (findings on vulnerable, none on clean) validates
the corpus design. This document measures Trivy in a different role, as a
baseline competitor, with the same method used for Gitleaks in
GITLEAKS_COMPARISON.md: per-file detection rate and per-category coverage over
the identical evaluation corpus. Gitleaks represents the generic secret
scanner; Trivy represents the generic misconfiguration scanner. Together the
two studies cover both halves of the claim that generic tools miss
Nigerian-specific compliance issues.

## 1. Method

- Comparison tool: Trivy v0.70.0 (the same version and binary the pipeline
  pins), default rules, in both of its relevant modes:
  - IaC misconfiguration scan at the pipeline's severity gate:
    `trivy config evaluation_data/vulnerable --severity CRITICAL,HIGH`
  - Secret scan: `trivy fs evaluation_data/vulnerable --scanners secret`
- Corpus: the same generated corpus as the Gitleaks study and the project
  baseline (this run: 30 Python, 19 Terraform, 33 Kubernetes, 18 Dockerfiles
  in the vulnerable half).
- Reference: the custom scanner's 347 findings, 100/100 files, on the
  identical corpus.
- Date of measurement: 2026-07-15.

## 2. Headline results

| Metric | Custom scanner | Trivy config scan | Trivy secret scan | Trivy combined |
|--------|----------------|-------------------|-------------------|----------------|
| Vulnerable files flagged (of 100) | 100 | 65 | 30 | 95 |
| File-level miss rate | 0 percent | 35 percent | 70 percent | 5 percent |
| Findings | 347 | 413 (400 HIGH, 13 CRITICAL) | 30 | 443 |
| False positives on clean corpus | 0 | 0 | 0 | 0 |

By file type (config scan): Terraform 19/19, Kubernetes 33/33, Dockerfiles
13/18, Python 0/30. The secret scan adds all 30 Python files. The five files
no Trivy mode flags are Dockerfiles.

## 3. Where the two tools overlap

Trivy's strength is real: on infrastructure misconfiguration it fires 18
distinct checks across the corpus, several of which correspond directly to
this project's rules:

| Custom rule | Trivy counterpart that fired |
|-------------|------------------------------|
| NG-NDPA-003 (encryption at rest disabled) | AWS-0026 (EBS encryption), AWS-0080 (RDS encryption) |
| NG-NDPA-004 (public S3 bucket) | AWS-0092 (public ACL) plus four public-access-block checks |
| NG-NDPA-007 (publicly accessible database) | AWS-0180 (RDS publicly accessible) |
| NG-CONT-001 (root container) | DS-0002 (image user should not be root) |
| NG-CONT-002 (secret in Dockerfile ENV) | DS-0031 (secrets passed via envs) |
| NG-SEC-001 (Paystack live key) | stripe-secret-token (format collision, see below) |

Trivy also catches planted issues outside the custom scanner's rule set: open
security groups including SSH from 0.0.0.0/0, host network and PID
namespaces, privileged pods, and writable root filesystems. This is the
defense-in-depth argument in measured form: the two engines together cover
more than either alone.

## 4. What Trivy missed

| Custom scanner category | Custom findings | Trivy findings | Notes |
|------------------------|-----------------|----------------|-------|
| secret | 78 | 30 | All 30 Paystack keys caught, but by the Stripe rule (format collision, same mislabel as Gitleaks). All 48 Flutterwave keys missed: Trivy's secret engine has provider-specific rules only, no generic entropy heuristic. |
| pii (hardcoded BVNs) | 30 | 0 | PII is outside Trivy's scope entirely. |
| ndpa: data sovereignty (NG-NDPA-001/002/006) | 90 | 0 | No Trivy check relates a cloud region to data localisation. This is a regulatory concept, not a security misconfiguration, and no generic tool models it. |
| ndpa: encryption in transit (NG-NDPA-005) | 19 | 0 | Trivy has a plain-HTTP check for ALB listeners, but it did not fire on this corpus (the listener is not attached to a resolvable load balancer in the same file). |
| container: unpinned image (NG-CONT-003) | 18 | 0 | Trivy's unpinned-image check sits below the CRITICAL/HIGH severity gate the pipeline uses. |

Two structural findings beyond the categories:

1. **Filename-convention dependency.** Trivy identified only 13 of the 18
   Dockerfiles: it recognises `*.dockerfile` but not names like
   `Dockerfile_api_28` (no extension). Those five files, each containing a
   root user, an ENV secret, and an unpinned image, are the five files that
   escaped Trivy entirely. The custom scanner treats any basename starting or
   ending with `dockerfile` as a Dockerfile and caught all 18.
2. **The de-fanged AWS example key was not flagged** by Trivy's secret scan,
   consistent with the Gitleaks result (documentation example keys are
   allowlisted by both tools).

## 5. Fairness caveats

1. The config scan was run at the pipeline's `CRITICAL,HIGH` gate for parity
   with how this project actually uses Trivy. Including MEDIUM and LOW
   severities would add findings (for example the unpinned-image check) but
   would not add coverage of PII, data sovereignty, or Flutterwave keys,
   because no rules for those exist at any severity.
2. The combined 95/100 file-level number is generous to Trivy: it counts a
   file as detected if any check fired, even when the file's
   Nigerian-specific violations (a BVN, a region violation) went unseen.
   File-level detection and category coverage answer different questions, and
   the category table is the honest measure of the compliance gap.
3. As with the Gitleaks study, this is not a claim that Trivy is weak. Trivy
   is measurably strong on infrastructure misconfiguration and is part of
   this project's own pipeline for exactly that reason. The claim being
   measured is that even a strong generic scanner has zero coverage of the
   NDPA-specific categories, so the custom rule layer adds coverage no
   generic tool supplies.

## 6. Conclusion

Measured on an identical corpus, Trivy's misconfiguration scan misses 35 of
100 vulnerable files (including every Python file) and its secret scan misses
70 of 100; combined, five Dockerfiles escape entirely due to a filename
convention. At category level, Trivy detects 0 of 30 BVNs, 0 of 90
data-sovereignty findings, 0 of 19 encryption-in-transit findings, and 0 of
48 Flutterwave keys, and it identifies Paystack keys as Stripe keys. Combined
with the Gitleaks study, the two dominant classes of generic scanner have now
both been measured against the corpus, and neither covers the regulatory
categories this project's 16 rules exist to enforce.

## 7. Reproducing

```bash
python generate_eval_data.py
python compliance_engine/scanner.py evaluation_data/vulnerable   # reference results
trivy config evaluation_data/vulnerable --severity CRITICAL,HIGH --format json --output trivy_vulnerable.json
trivy fs evaluation_data/vulnerable --scanners secret --format json --output trivy_secrets.json
trivy config evaluation_data/clean --severity CRITICAL,HIGH   # expect no findings
```

Finding counts vary between generated corpora; the category-coverage result
(zero on pii, data sovereignty, encryption in transit, and Flutterwave keys)
is stable because it follows from Trivy's rule set, not from the random draw.
