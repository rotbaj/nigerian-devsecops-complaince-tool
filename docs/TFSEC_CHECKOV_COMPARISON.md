# Comparative Baseline: tfsec and Checkov Versus the Custom Scanner

Third study in the comparative series (with GITLEAKS_COMPARISON.md and
TRIVY_COMPARISON.md), covering the two remaining widely used
infrastructure-as-code scanners: tfsec (Aqua Security, Terraform-only, now
officially merged into Trivy and in maintenance mode) and Checkov (Palo Alto
Networks, multi-framework). Same method: default configuration, identical
evaluation corpus, per-file detection rate and per-category coverage against
the custom scanner's results.

## 1. Method

- Tools: tfsec v1.28.14 and Checkov 3.3.8 (open-source distribution), default
  rules, no custom policies.
- Corpus: the same generated corpus as the other studies (this run: 30
  Python, 19 Terraform, 33 Kubernetes, 18 Dockerfiles in the vulnerable
  half; the clean half contains 41 Terraform files and 18 Dockerfiles among
  its 100).
- Commands:

```bash
tfsec evaluation_data/vulnerable --format json
tfsec evaluation_data/clean --format json
checkov -d evaluation_data/vulnerable -o json
checkov -d evaluation_data/clean -o json
```

- Reference: the custom scanner's 347 findings, 100/100 files, 0 false
  positives on the identical corpus.
- Date of measurement: 2026-07-15.

## 2. Headline results

| Metric | Custom scanner | tfsec | Checkov |
|--------|----------------|-------|---------|
| Vulnerable files flagged (of 100) | 100 | 19 | 65 |
| File-level miss rate | 0 percent | 81 percent | 35 percent |
| Findings on vulnerable corpus | 347 | 513 (304 CRITICAL/HIGH) | 1,532 failed checks |
| Clean-corpus findings at a CRITICAL/HIGH gate | 0 | 0 (164 LOW/MEDIUM ungated) | not gateable (see 5.1) |

- tfsec scans Terraform only, by design: it flagged all 19 Terraform files
  (every one with CRITICAL/HIGH findings) and cannot see the other 81.
- Checkov flagged all Terraform and Kubernetes files, 13 of 18 Dockerfiles
  (the same extensionless-filename gap Trivy has: `Dockerfile_api_28` is not
  recognised, `*.dockerfile` is), and 0 of 30 Python files. Its secrets
  framework only scans files an IaC framework already recognises unless
  `--enable-secret-scan-all-files` is set, which is off by default.

## 3. Credit where due

The studies must be honest in both directions, and both tools beat Trivy on
specific points:

1. **Both caught the plaintext HTTP listener.** tfsec fired AVD-AWS-0054
   (CRITICAL, 19 findings) and Checkov fired CKV_AWS_2 (19 findings) on the
   Terraform HTTP listener that Trivy's config scan missed on this corpus.
   On encryption in transit in Terraform, both generic tools match
   NG-NDPA-005. (The custom rule also covers .yml/.yaml files, where neither
   fired because the corpus plants that issue only in Terraform.)
2. **Checkov caught the planted AWS credentials.** Its secrets framework
   flagged the hardcoded provider access key in all 19 Terraform files
   (CKV_SECRET_2), the one place it does not honour the documentation-example
   allowlist that exempts this key in Gitleaks and Trivy. It also caught the
   Flutterwave key in 13 Dockerfile ENV lines via a base64-entropy heuristic
   (CKV_SECRET_6).
3. **Checkov flags the unpinned `:latest` image** (CKV_DOCKER_7) and root
   user (CKV_DOCKER_8) on the 13 Dockerfiles it recognises; the unpinned
   image is a check Trivy's CRITICAL/HIGH gate missed.
4. **tfsec's Terraform ruleset fired more broadly than Trivy's.** Although
   tfsec is deprecated in favour of Trivy, it fired 24 distinct AWS checks on
   this corpus (including wildcard IAM, AVD-AWS-0057, which Trivy's config
   scan also missed) against Trivy's 10. Depth on Terraform, at the cost of
   seeing only Terraform.

## 4. What both tools missed

By the custom scanner's categories:

| Category | Custom findings | tfsec | Checkov |
|----------|-----------------|-------|---------|
| secret: Paystack live keys (Python) | 30 | 0 | 0 |
| secret: Flutterwave keys | 48 | 0 | 13 (Dockerfile ENV only, via generic entropy; 0 of 30 in Python) |
| pii: hardcoded BVNs | 30 | 0 | 0 |
| ndpa: data sovereignty (regions) | 90 | 0 | 0 |
| ndpa: encryption in transit | 19 | 19 | 19 |
| ndpa: encryption at rest, public storage, public database | 76 | equivalents fired | equivalents fired |
| container: root user, ENV secret, unpinned image | 54 | 0 (out of scope) | caught on 13 of 18 files |

The consistent result across all four tools measured (Gitleaks, Trivy, tfsec,
Checkov): zero coverage of Nigerian PII and zero coverage of data
sovereignty. No generic scanner has any concept of where Nigerian data is
allowed to live, and none knows a Paystack or Flutterwave key format
(detections happen only via Stripe-format collision or entropy heuristics,
never by provider identity).

## 5. Fairness caveats

1. **Checkov cannot be severity-gated in its open-source form.** Its OSS
   output carries no severity metadata (severities are an enterprise-platform
   feature), so there is no equivalent of the pipeline's CRITICAL/HIGH gate.
   Consequence on the clean corpus: 583 failed checks across all 41 clean
   Terraform files and 9 recognised clean Dockerfiles, all best-practice
   items outside this project's policy (access logging, versioning,
   cross-region replication, lifecycle configuration, and similar). None is a
   planted issue. A CI gate wired to default Checkov would block the fully
   compliant corpus, which is a measured illustration of why a compliance
   gate must encode a deliberate, severity-ranked policy rather than the
   union of every available best practice.
2. **tfsec at the same gate is clean.** Restricted to CRITICAL/HIGH for
   parity with the pipeline, tfsec produces zero findings on the clean corpus
   (its 164 LOW/MEDIUM findings are the same best-practice class as
   Checkov's).
3. tfsec's 81 percent file-level miss rate is by scope, not by defect: it is
   a Terraform-only tool. It is included because a team standardised on tfsec
   for IaC scanning would still have the full measured gap on Python secrets,
   PII, Kubernetes, and Dockerfiles.
4. As with the other studies, none of this claims the tools are weak inside
   their scopes; on Terraform security misconfiguration both are strong. The
   measured claim is that their scopes do not include the regulatory
   categories this project enforces.

## 6. Conclusion

With this study, all four widely deployed generic scanners adjacent to this
project's problem space have been measured on the identical corpus:

| Tool | Files flagged (of 100) | BVN/PII | Data sovereignty | Provider-aware secret detection |
|------|------------------------|---------|------------------|--------------------------------|
| Custom scanner | 100 | yes | yes | yes |
| Gitleaks (default) | 48 | 0 | 0 | no (Stripe collision only) |
| Trivy (config + secret) | 95 | 0 | 0 | no (Stripe collision only) |
| tfsec | 19 | 0 | 0 | no |
| Checkov | 65 | 0 | 0 | no (entropy heuristic only) |

Every generic tool scores zero on the two categories that define the
project's regulatory motivation, PII and data sovereignty, and none
identifies a Nigerian payment-provider key as what it is. The custom
scanner's contribution is measured, not asserted, against four independent
baselines.

## 7. Reproducing

```bash
python generate_eval_data.py
python compliance_engine/scanner.py evaluation_data/vulnerable   # reference results
tfsec evaluation_data/vulnerable --format json --out tfsec_vulnerable.json --soft-fail
tfsec evaluation_data/clean --format json --out tfsec_clean.json --soft-fail
checkov -d evaluation_data/vulnerable -o json --output-file-path checkov_vulnerable
checkov -d evaluation_data/clean -o json --output-file-path checkov_clean
```

Finding counts vary between generated corpora; the category-coverage results
are stable because they follow from each tool's rule set, not from the random
draw.
