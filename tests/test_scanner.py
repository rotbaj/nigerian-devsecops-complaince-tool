"""
Unit tests for the Nigerian Fintech Compliance Engine.
Run with: pytest tests/ -v
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from compliance_engine.scanner import scan_content, scan_path


# ─── Secret Detection Tests ────────────────────────────────────

class TestSecretDetection:

    def test_detects_paystack_live_key(self):
        content = 'SECRET_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-001" in rule_ids

    def test_detects_flutterwave_test_key(self):
        content = 'FLW_KEY = "FLWSECK_TEST-abcdefghijklmnopqrstuvwxyz1234-X"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-002" in rule_ids

    def test_detects_paystack_public_key(self):
        content = 'PK = "pk_test_abcdefghijklmnopqrstuvwxyz123456"'
        findings = scan_content(content, "config.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-003" in rule_ids

    def test_detects_fake_bvn(self):
        content = "user_bvn = 12345678901"
        findings = scan_content(content, "user.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-004" in rule_ids

    def test_detects_nigerian_phone_number(self):
        content = 'phone = "+2348012345678"'
        findings = scan_content(content, "user.py")
        rule_ids = [f.rule_id for f in findings]
        assert "NG-SEC-005" in rule_ids

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

    def test_pinned_tag_no_warning(self):
        content = "FROM node:18.20.0\nUSER 1001\n"
        findings = scan_content(content, "Dockerfile")
        container_findings = [f for f in findings if f.category == "container"]
        assert len(container_findings) == 0


# ─── Scan Result / Pass-Fail Logic Tests ──────────────────────

class TestScanResult:

    def test_critical_finding_fails_build(self):
        result = scan_path("tests/fixtures/bad_code_sample.py")
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

    def test_finding_line_content_is_redacted(self):
        content = 'KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456"'
        findings = scan_content(content, "config.py")
        for finding in findings:
            assert "sk_live_" not in finding.line_content
