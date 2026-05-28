"""
Nigerian Fintech DevSecOps - Evaluation Data Generator
Generates 100 realistic synthetic files (50 vulnerable, 50 clean) for evaluating
the compliance scanner, and writes deterministic fixture files used by the test suite.

Run from the project root:
    python generate_eval_data.py

Then scan all 100 evaluation files:
    python compliance_engine/scanner.py evaluation_data/

Run the unit tests (which depend on tests/fixtures/):
    pytest tests/ -v
"""

import os
import random

EVAL_DIR = "evaluation_data"
BAD_DIR = os.path.join(EVAL_DIR, "vulnerable")
GOOD_DIR = os.path.join(EVAL_DIR, "clean")
FIXTURES_DIR = os.path.join("tests", "fixtures")

for d in (BAD_DIR, GOOD_DIR, FIXTURES_DIR):
    os.makedirs(d, exist_ok=True)


# ─── Helpers ───────────────────────────────────────────────────

def gen_hex(n_chars):
    """Return n_chars lowercase hex characters."""
    return random.randbytes(n_chars // 2).hex()


def gen_bvn():
    """Synthetic 11-digit BVN. Real BVNs start with 2."""
    return f"2{random.randint(1000000000, 9999999999)}"


def gen_phone():
    """Synthetic Nigerian mobile number (080xxxxxxxx)."""
    return f"080{random.randint(10000000, 99999999)}"


# ─────────────────────────────────────────────────────────
#  VULNERABLE TEMPLATES
# ─────────────────────────────────────────────────────────

# NOTE: {user_bvn} inside the generated f-string must be written as {{user_bvn}}
# so Python's .format() leaves it as a literal {user_bvn} in the output file.
BAD_PYTHON_MULTI = """\
import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


class PaymentGatewayConfig:
    def __init__(self):
        # TODO: DevOps team to move these to AWS Secrets Manager next sprint.
        # Hardcoding temporarily to fix the production outage.
        self.paystack_key = "sk_live_{ps_key}"
        self.flw_key = "FLWSECK-{flw_key}-X"
        self.environment = "production"


def process_kyc(user_payload):
    \"\"\"Process KYC data for new customers.\"\"\"
    user_bvn = "{bvn}"  # Extracted from payload — bank_verification_number
    logger.info(f"Processing KYC for user with BVN: {{user_bvn}}")
    return True
"""

# Terraform templates are NOT passed to .format(), so they use plain HCL braces { }.
BAD_TERRAFORM_MULTI = """\
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# NDPA Violation: Nigerian financial data hosted outside Africa
provider "aws" {
  region  = "us-east-1"
  profile = "fintech-prod"
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

  tags = {
    Name = "CoreBankingDB"
  }
}
"""

BAD_DOCKER_MULTI = """\
# CRITICAL: Unpinned image tag defaults to :latest
FROM node:latest

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install

COPY . .

# SECURITY LEAK: Flutterwave secret embedded in image layer
ENV FLW_SECRET="FLWSECK-{flw_key}-X"
ENV NODE_ENV=production
ENV PORT=8080

# CRITICAL: Container runs as root
USER root

EXPOSE 8080
CMD [ "npm", "start" ]
"""


# ─────────────────────────────────────────────────────────
#  CLEAN TEMPLATES (no CRITICAL/HIGH — build must pass)
# ─────────────────────────────────────────────────────────

# Variable renamed to customer_contact (not phone/mobile/tel) so an 11-digit
# number here does NOT trigger NG-SEC-005. This verifies the no-context
# false-positive fix on BVN rule NG-SEC-004.
CLEAN_PYTHON = """\
import os
from pydantic import BaseSettings


class Settings(BaseSettings):
    # Secrets securely loaded from environment — never hardcoded
    PAYSTACK_SECRET_KEY: str = os.getenv("PAYSTACK_SECRET_KEY", "")
    FLUTTERWAVE_SECRET_KEY: str = os.getenv("FLW_SECRET_KEY", "")

    class Config:
        env_file = ".env"


settings = Settings()


def notify_user(user_id: str):
    # 11-digit number with no BVN keyword context — must NOT trigger NG-SEC-004
    customer_contact = "{contact}"
    print(f"Sending SMS to {{customer_contact}}")
"""

CLEAN_TERRAFORM = """\
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# NDPA Compliant: Cape Town region keeps Nigerian data on the continent
provider "aws" {
  region = "af-south-1"
}

resource "aws_s3_bucket" "user_kyc_documents" {
  bucket = "fintech-kyc-docs-prod"
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
"""

CLEAN_DOCKER = """\
# Pinned to a specific minor version — reproducible and auditable
FROM python:3.9.18-slim-bullseye

RUN groupadd -r fintech_group && useradd -r -g fintech_group fintech_user

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R fintech_user:fintech_group /app

# Secrets injected at runtime via secrets manager — never baked into the image
ARG APP_VERSION
ENV VERSION=$APP_VERSION

USER 1001

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "core.wsgi:application"]
"""


# ─────────────────────────────────────────────────────────
#  FIXTURE FILES (deterministic — used by the test suite)
#
#  These use fixed, non-random keys so pytest results are
#  stable across every run without needing a random seed.
# ─────────────────────────────────────────────────────────

# Paystack: sk_live_ + 40 hex chars
# Flutterwave: FLWSECK- + 32 hex chars + -X
# BVN: 11-digit number with keyword context
FIXTURE_BAD_PYTHON = """\
# Synthetic bad code — all credentials are non-functional.
# DO NOT use any values from this file in a real project.

import os

class InsecurePaymentConfig:
    paystack_secret = "sk_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    flutterwave_secret = "FLWSECK-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-X"
    paystack_public = "pk_live_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    flw_public = "FLWPUBK-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4-X"

def onboard_customer(payload):
    user_bvn = "22522683105"  # bank_verification_number — synthetic, non-real
    mobile_number = "+2348012345678"
    return {"bvn": user_bvn, "mobile": mobile_number}
"""

FIXTURE_BAD_TERRAFORM = """\
# Synthetic bad Terraform — intentionally violates NDPA 2023 and security rules.
# DO NOT apply this to any real infrastructure.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "kyc_store" {
  bucket = "synthetic-kyc-test-bucket"
  acl    = "public-read"
}

resource "aws_ebs_volume" "core_db" {
  availability_zone = "eu-west-1a"
  size              = 100
  encrypted         = false
}
"""


# ─────────────────────────────────────────────────────────
#  GENERATOR
# ─────────────────────────────────────────────────────────

print("Writing test fixture files to tests/fixtures/ ...")

with open(os.path.join(FIXTURES_DIR, "bad_code_sample.py"), "w") as f:
    f.write(FIXTURE_BAD_PYTHON)

with open(os.path.join(FIXTURES_DIR, "bad_terraform.tf"), "w") as f:
    f.write(FIXTURE_BAD_TERRAFORM)

print("Generating 100 realistic evaluation files ...")

for i in range(1, 51):
    file_type = random.choice(["python", "terraform", "docker"])

    if file_type == "python":
        content = BAD_PYTHON_MULTI.format(
            ps_key=gen_hex(40),
            flw_key=gen_hex(32),
            bvn=gen_bvn(),
        )
        filename = os.path.join(BAD_DIR, f"core_payment_service_{i}.py")

    elif file_type == "terraform":
        content = BAD_TERRAFORM_MULTI
        filename = os.path.join(BAD_DIR, f"aws_infrastructure_{i}.tf")

    else:
        content = BAD_DOCKER_MULTI.format(flw_key=gen_hex(32))
        ext = ".dockerfile" if random.choice([True, False]) else ""
        filename = os.path.join(BAD_DIR, f"Dockerfile_api_{i}{ext}")

    with open(filename, "w") as f:
        f.write(content)

for i in range(1, 51):
    file_type = random.choice(["python", "terraform", "docker"])

    if file_type == "python":
        content = CLEAN_PYTHON.format(contact=gen_phone())
        filename = os.path.join(GOOD_DIR, f"config_settings_{i}.py")

    elif file_type == "terraform":
        content = CLEAN_TERRAFORM
        filename = os.path.join(GOOD_DIR, f"aws_infrastructure_{i}.tf")

    else:
        content = CLEAN_DOCKER
        ext = ".dockerfile" if random.choice([True, False]) else ""
        filename = os.path.join(GOOD_DIR, f"Dockerfile_worker_{i}{ext}")

    with open(filename, "w") as f:
        f.write(content)

print(f"Done.")
print(f"  tests/fixtures/  → 2 deterministic fixture files (used by pytest)")
print(f"  {EVAL_DIR}/vulnerable/ → 50 vulnerable files  (random synthetic keys)")
print(f"  {EVAL_DIR}/clean/     → 50 clean files")
print(f"\nScan evaluation data: python compliance_engine/scanner.py {EVAL_DIR}/")
