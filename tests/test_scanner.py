"""
Unit tests for the Nigerian Fintech Compliance Engine.
Run with: pytest tests/ -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from compliance_engine.scanner import scan_content, scan_path


# ─── Secret Detection Tests ────────────────────────────────────

class TestSecretDetection:

    def test_detects_paystack_live_key(self):
        # Paystack live secret: sk_live_ + exactly 40 hex chars
        content = 'SECRET_KEY = "sk_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-001" in rule_ids

    def test_detects_flutterwave_test_key(self):
        # Flutterwave test secret: FLWSECK_TEST- + 32 hex chars + -X
        content = 'FLW_KEY = "FLWSECK_TEST-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-X"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-002" in rule_ids

    def test_detects_flutterwave_live_key(self):
        # Flutterwave live secret: FLWSECK- + 32 hex chars + -X
        content = 'FLW_KEY = "FLWSECK-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-X"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-002" in rule_ids

    def test_detects_paystack_test_public_key(self):
        # Paystack public key: pk_test_ + exactly 40 hex chars
        content = 'PK = "pk_test_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-003" in rule_ids

    def test_detects_paystack_live_public_key(self):
        # pk_live_ is also flagged (WARNING) even though it's a public key
        content = 'PK = "pk_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-003" in rule_ids

    def test_detects_flutterwave_public_key(self):
        # Flutterwave public key: FLWPUBK- + 32 hex chars + -X
        content = 'FLW_PUB = "FLWPUBK-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-X"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-006" in rule_ids

    def test_detects_bvn_with_keyword_before(self):
        # BVN keyword appears in variable name before the 11-digit value
        content = 'user_bvn = "22522683105"'
        findings = scan_content(content, "user.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-004" in rule_ids

    def test_detects_bvn_with_keyword_after(self):
        # BVN keyword appears in a comment after the value
        content = '  "22522683105"  # bank_verification'
        findings = scan_content(content, "user.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-004" in rule_ids

    def test_phone_number_without_bvn_keyword_not_flagged_as_bvn(self):
        # A Nigerian phone number must NOT trigger the BVN rule — no keyword context
        content = 'phone_number = "08012345678"'
        findings = scan_content(content, "user.py")
        bvn_findings = [f for f in findings if f.rule_id == "NG-SEC-004"]
        assert len(bvn_findings) == 0

    def test_detects_nigerian_phone_number(self):
        # Phone rule triggers when assigned to a phone/mobile/tel variable
        content = 'phone = "+2348012345678"'
        findings = scan_content(content, "user.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-005" in rule_ids

    def test_phone_not_flagged_when_no_phone_keyword(self):
        # Without phone/mobile/tel context, a Nigerian number should not trigger NG-SEC-005
        content = 'contact = "+2348012345678"'
        findings = scan_content(content, "user.py")
        phone_findings = [f for f in findings if f.rule_id == "NG-SEC-005"]
        assert len(phone_findings) == 0

    def test_twelve_digit_number_not_flagged_as_bvn(self):
        # A BVN is exactly 11 digits — a 12-digit number near a keyword is not one
        content = 'user_bvn = "225226831055"'
        findings = scan_content(content, "user.py")
        bvn_findings = [f for f in findings if f.rule_id == "NG-SEC-004"]
        assert len(bvn_findings) == 0

    def test_clean_code_has_no_secret_findings(self):
        content = """
import os
SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY")
FLW_KEY = os.environ.get("FLW_SECRET_KEY")
        """
        findings = scan_content(content, "config.py")
        secret_findings = [f for f in findings if f.category == "secret"]
        assert len(secret_findings) == 0


# ─── NDPA Compliance Tests ─────────────────────────────────────

class TestNDPACompliance:

    def test_detects_us_east_1_region(self):
        content = 'region = "us-east-1"'
        findings = scan_content(content, "main.tf")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-NDPA-001" in rule_ids

    def test_detects_eu_west_region(self):
        content = 'region = "eu-west-1"'
        findings = scan_content(content, "main.tf")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-NDPA-002" in rule_ids

    def test_detects_encryption_disabled(self):
        content = "encrypted = false"
        findings = scan_content(content, "storage.tf")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-NDPA-003" in rule_ids

    def test_detects_public_s3_bucket(self):
        content = 'acl = "public-read"'
        findings = scan_content(content, "s3.tf")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-NDPA-004" in rule_ids

    def test_compliant_region_passes(self):
        content = 'region = "af-south-1"'
        findings = scan_content(content, "main.tf")
        ndpa_findings = [f for f in findings if f.category == "ndpa"]
        assert len(ndpa_findings) == 0

    def test_ndpa_rules_not_applied_to_python_files(self):
        # A comment in a .py file mentioning us-east-1 must NOT fail the build.
        # NDPA sovereignty rules are infrastructure-file-only to prevent false positives.
        content = '# We migrated away from us-east-1 last year — do not use'
        findings = scan_content(content, "README_migration.py")
        ndpa_findings = [f for f in findings if f.category == "ndpa"]
        assert len(ndpa_findings) == 0

    def test_ndpa_rules_applied_to_yaml_files(self):
        # YAML pipeline files that reference non-compliant regions must be flagged.
        content = 'AWS_DEFAULT_REGION: us-east-1'
        findings = scan_content(content, "deploy.yml")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-NDPA-001" in rule_ids


# ─── Container Security Tests ──────────────────────────────────

class TestContainerSecurity:

    def test_detects_docker_root_user(self):
        content = "FROM node:18\nUSER root\nCMD node app.js"
        findings = scan_content(content, "Dockerfile")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-CONT-001" in rule_ids

    def test_detects_secret_in_dockerfile_env(self):
        content = "FROM python:3.9\nENV SECRET_KEY=mysupersecretvalue\n"
        findings = scan_content(content, "Dockerfile")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-CONT-002" in rule_ids

    def test_detects_latest_docker_tag(self):
        content = "FROM node:latest\n"
        findings = scan_content(content, "Dockerfile")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-CONT-003" in rule_ids

    def test_detects_untagged_docker_image(self):
        # "FROM python" with no tag defaults to :latest — must be flagged
        content = "FROM python\n"
        findings = scan_content(content, "Dockerfile")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-CONT-003" in rule_ids

    def test_pinned_tag_no_warning(self):
        content = "FROM node:18.20.0\nUSER 1001\n"
        findings = scan_content(content, "Dockerfile")
        container_findings = [f for f in findings if f.category == "container"]
        assert len(container_findings) == 0

    def test_pinned_digest_no_warning(self):
        # An image pinned by sha256 digest is fully reproducible — no warning
        content = "FROM node@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n"
        findings = scan_content(content, "Dockerfile")
        cont_findings = [f for f in findings if f.category == "container"]
        assert len(cont_findings) == 0

    def test_container_rules_not_applied_to_python_files(self):
        # "from x import y" in Python must NOT match the Docker FROM regex —
        # container rules only apply to Dockerfiles.
        content = "from dataclasses import dataclass\nfrom os import path\n"
        findings = scan_content(content, "models.py")
        cont_findings = [f for f in findings if f.category == "container"]
        assert len(cont_findings) == 0


# ─── Scan Result / Pass-Fail Logic Tests ──────────────────────

class TestScanResult:

    def test_critical_finding_fails_build(self):
        # Scans the whole fixtures/ directory so both bad_code_sample.py
        # and bad_terraform.tf are covered in a single assertion.
        # Run generate_eval_data.py once to create these files before running tests.
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        result = scan_path(fixtures_dir)
        assert result.files_scanned >= 2, (
            "Run `python generate_eval_data.py` from the project root first "
            "to create the test fixture files in tests/fixtures/"
        )
        assert result.passed is False
        assert result.critical > 0

    def test_clean_file_passes_build(self):
        import tempfile, os
        clean_code = """
import os
API_KEY = os.environ.get("PAYSTACK_KEY", "")
region = "af-south-1"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(clean_code)
            tmpfile = f.name
        try:
            result = scan_path(tmpfile)
            assert result.passed is True
        finally:
            os.unlink(tmpfile)

    def test_scanning_relative_dot_path_works(self):
        # Regression: scan_path(".") used to skip EVERYTHING because "." itself
        # starts with a dot — making the CI scan a silent no-op that always passed.
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.tf"), "w") as f:
                f.write('acl = "public-read"\n')
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                result = scan_path(".")
            finally:
                os.chdir(old_cwd)
        assert result.files_scanned >= 1
        assert result.critical > 0

    def test_exclude_directories(self):
        # Directories passed via exclude= must be skipped at any depth
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            fixture_dir = os.path.join(tmpdir, "fixtures")
            os.makedirs(fixture_dir)
            with open(os.path.join(fixture_dir, "bad.tf"), "w") as f:
                f.write('acl = "public-read"\n')
            result = scan_path(tmpdir, exclude=["fixtures"])
        assert result.total_findings == 0
        assert result.passed is True

    def test_github_workflows_directory_is_scanned(self):
        # .github/workflows/ must NOT be skipped — pipeline YAML is a supply-chain
        # attack surface. Secrets or unpinned actions there must be caught.
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            workflow_dir = os.path.join(tmpdir, ".github", "workflows")
            os.makedirs(workflow_dir)
            bad_yml = os.path.join(workflow_dir, "pipeline.yml")
            with open(bad_yml, "w") as f:
                f.write("AWS_DEFAULT_REGION: us-east-1\n")
            result = scan_path(tmpdir)
        assert result.files_scanned >= 1
        ndpa_findings = [f for f in result.findings if f.category == "ndpa"]
        assert len(ndpa_findings) > 0

    def test_finding_line_content_is_redacted(self):
        # Use a valid 40-hex-char Paystack key so the pattern actually matches
        content = 'KEY = "sk_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"'
        findings = scan_content(content, "config.py")
        assert len(findings) > 0, "Pattern did not match — check the test key length"
        for finding in findings:
            assert "sk_live_" not in finding.line_content
