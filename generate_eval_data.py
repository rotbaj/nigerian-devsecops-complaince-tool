"""
Nigerian Fintech DevSecOps - Evaluation Data Generator
Generates 200 realistic synthetic files (100 vulnerable, 100 clean) for evaluating
the compliance scanner, and writes deterministic fixture files used by the test suite.

Vulnerable files cover both our scanner's rules (secrets, PII, NDPA, container)
and misconfigurations detected by Trivy's IaC scanner (open security groups,
wildcard IAM, public RDS, privileged Kubernetes pods, unsafe Dockerfile practices).

Run from the project root:
    python generate_eval_data.py

Then scan all 200 evaluation files:
    python compliance_engine/scanner.py evaluation_data/

Run the unit tests (which depend on tests/fixtures/):
    pytest tests/ -v
"""

import os
import random
import shutil

EVAL_DIR = "evaluation_data"
BAD_DIR = os.path.join(EVAL_DIR, "vulnerable")
GOOD_DIR = os.path.join(EVAL_DIR, "clean")
FIXTURES_DIR = os.path.join("tests", "fixtures")

# Start from empty output dirs: filenames vary between runs (random extensions),
# so stale files from a previous run would otherwise accumulate and skew counts.
for d in (BAD_DIR, GOOD_DIR):
    shutil.rmtree(d, ignore_errors=True)

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
    user_bvn = "{bvn}"  # Extracted from payload, bank_verification_number
    logger.info(f"Processing KYC for user with BVN: {{user_bvn}}")
    return True
"""

# Terraform templates are NOT passed to .format(), so they use plain HCL braces { }.
# Beyond our own scanner's rules, this includes misconfigurations Trivy's IaC
# scanner detects: open security groups, wildcard IAM, public+unencrypted RDS,
# hardcoded provider credentials (synthetic AWS-docs example key).
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
# Trivy: hardcoded cloud credentials in provider block (synthetic example values)
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
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

# Trivy: security group open to the entire internet, including SSH
resource "aws_security_group" "core_banking_sg" {
  name = "core-banking-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# NDPA Violation: plaintext HTTP listener, so card and KYC data crosses the
# network unencrypted (NG-NDPA-005; Trivy also flags plain HTTP on ALBs)
resource "aws_lb_listener" "api_http" {
  load_balancer_arn = aws_lb.api_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api_tg.arn
  }
}

# Trivy: publicly accessible RDS with plaintext password and no encryption
# (the public-access flag below also fires NG-NDPA-007)
resource "aws_db_instance" "customer_db" {
  identifier          = "fintech-customers"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  username            = "fintech_admin"
  password            = "SuperSecretDbPass123!"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

# Trivy: IAM policy with full wildcard permissions
resource "aws_iam_policy" "app_policy" {
  name = "fintech-app-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
"""

BAD_DOCKER_MULTI = """\
# CRITICAL: Unpinned image tag defaults to :latest
FROM node:latest

WORKDIR /usr/src/app

# Trivy: ADD used where COPY suffices (ADD can fetch remote URLs / auto-extract)
ADD package*.json ./
RUN npm install

# Trivy: curl piped straight into a shell: unverified remote code execution
RUN curl -sSL https://get.example-tool.io/install.sh | sh

# Trivy: world-writable permissions on the app directory
COPY . .
RUN chmod -R 777 /usr/src/app

# Trivy: apt-get without version pinning or cache cleanup
RUN apt-get update && apt-get install -y curl wget netcat

# SECURITY LEAK: Flutterwave secret embedded in image layer
ENV FLW_SECRET="FLWSECK-{flw_key}-X"
ENV NODE_ENV=production
ENV PORT=8080

# CRITICAL: Container runs as root
USER root

# Trivy: no HEALTHCHECK instruction defined
EXPOSE 8080
CMD [ "npm", "start" ]
"""

# Kubernetes manifest with misconfigurations Trivy's config scanner flags:
# privileged container, host network/PID, no resource limits, root user,
# writable root filesystem, and secrets passed as plain env values.
# Also includes us-east-1 so our own NDPA rule fires on .yml files.
BAD_K8S_MULTI = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fintech-core-api
  labels:
    app: fintech-core-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: fintech-core-api
  template:
    metadata:
      labels:
        app: fintech-core-api
    spec:
      # Trivy: pod shares the host's network and PID namespaces
      hostNetwork: true
      hostPID: true
      containers:
        - name: core-api
          # Trivy + NG-CONT: unpinned latest image
          image: fintech/core-api:latest
          securityContext:
            # Trivy: privileged container can escape to the host
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
          env:
            # Trivy: secret material passed as a plain env value
            - name: DB_PASSWORD
              value: "SuperSecretDbPass123!"
            - name: AWS_DEFAULT_REGION
              value: "us-east-1"
          ports:
            - containerPort: 8080
          # Trivy: no resources.limits, so a runaway pod can starve the node
"""


# ─────────────────────────────────────────────────────────
#  CLEAN TEMPLATES (no CRITICAL/HIGH; build must pass)
# ─────────────────────────────────────────────────────────

# Variable renamed to customer_contact (not phone/mobile/tel) so an 11-digit
# number here does NOT trigger NG-SEC-005. This verifies the no-context
# false-positive fix on BVN rule NG-SEC-004.
CLEAN_PYTHON = """\
import os
from pydantic import BaseSettings


class Settings(BaseSettings):
    # Secrets securely loaded from environment, never hardcoded
    PAYSTACK_SECRET_KEY: str = os.getenv("PAYSTACK_SECRET_KEY", "")
    FLUTTERWAVE_SECRET_KEY: str = os.getenv("FLW_SECRET_KEY", "")

    class Config:
        env_file = ".env"


settings = Settings()


def notify_user(user_id: str):
    # 11-digit number with no BVN keyword context; must NOT trigger NG-SEC-004
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

# Customer-managed key: auditable, rotatable encryption for customer data
resource "aws_kms_key" "kyc_docs_key" {
  description         = "CMK for the KYC document bucket"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "user_kyc_documents" {
  bucket = "fintech-kyc-docs-prod"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kyc_docs_sse" {
  bucket = aws_s3_bucket.user_kyc_documents.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.kyc_docs_key.arn
    }
  }
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

# Encryption in transit: HTTPS-only listener with a current TLS policy
# (protocol = "HTTPS" must NOT trigger NG-NDPA-005)
resource "aws_lb_listener" "api_https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:af-south-1:123456789012:loadbalancer/app/fintech-api/0f1e2d3c4b5a6978"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:af-south-1:123456789012:certificate/11aa22bb-33cc-44dd-55ee-66ff77aa88bb"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:af-south-1:123456789012:targetgroup/fintech-api/a1b2c3d4e5f60789"
  }
}

# Private, encrypted database with a managed master password
# (publicly_accessible = false must NOT trigger NG-NDPA-007)
resource "aws_db_instance" "customer_db" {
  identifier                          = "fintech-customers"
  engine                              = "postgres"
  instance_class                      = "db.t3.medium"
  allocated_storage                   = 100
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.kyc_docs_key.arn
  manage_master_user_password         = true
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  backup_retention_period             = 30
  skip_final_snapshot                 = false
}
"""

CLEAN_DOCKER = """\
# Pinned to a specific minor version: reproducible and auditable
FROM python:3.9.18-slim-bullseye

RUN groupadd -r fintech_group && useradd -r -g fintech_group fintech_user

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R fintech_user:fintech_group /app

# Secrets injected at runtime via secrets manager, never baked into the image
ARG APP_VERSION
ENV VERSION=$APP_VERSION

USER 1001

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "core.wsgi:application"]
"""


# ─────────────────────────────────────────────────────────
#  FIXTURE FILES (deterministic; used by the test suite)
#
#  These use fixed, non-random values so pytest results are
#  stable across every run without needing a random seed.
#
#  The values are assembled from pieces so that THIS generator
#  file never contains a scannable secret on a single source
#  line; otherwise the scanner would flag its own tooling.
# ─────────────────────────────────────────────────────────

_HEX40 = "a1b2c3d4e5" * 4          # 40 deterministic hex chars
_HEX32 = "a1b2c3d4e5f6a1b2" * 2    # 32 deterministic hex chars
_BVN = "225" + "2268" + "3105"     # 11 digits, split to avoid self-flagging
_PHONE = "+234" + "80123" + "45678"

FIXTURE_BAD_PYTHON = """\
# Synthetic bad code; all credentials are non-functional.
# DO NOT use any values from this file in a real project.

import os

class InsecurePaymentConfig:
    paystack_secret = "sk_live_{hex40}"
    flutterwave_secret = "FLWSECK-{hex32}-X"
    paystack_public = "pk_live_{hex40}"
    flw_public = "FLWPUBK-{hex32}-X"

def onboard_customer(payload):
    user_bvn = "{bvn}"  # bank_verification_number (synthetic, non-real)
    mobile_number = "{phone}"
    return {{"bvn": user_bvn, "mobile": mobile_number}}
""".format(hex40=_HEX40, hex32=_HEX32, bvn=_BVN, phone=_PHONE)

FIXTURE_BAD_TERRAFORM = """\
# Synthetic bad Terraform; intentionally violates NDPA 2023 and security rules.
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

print("Generating 200 realistic evaluation files ...")

for i in range(1, 101):
    file_type = random.choice(["python", "terraform", "docker", "k8s"])

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

    elif file_type == "k8s":
        content = BAD_K8S_MULTI
        filename = os.path.join(BAD_DIR, f"k8s_deployment_{i}.yml")

    else:
        content = BAD_DOCKER_MULTI.format(flw_key=gen_hex(32))
        ext = ".dockerfile" if random.choice([True, False]) else ""
        filename = os.path.join(BAD_DIR, f"Dockerfile_api_{i}{ext}")

    with open(filename, "w") as f:
        f.write(content)

for i in range(1, 101):
    file_type = random.choice(["python", "terraform", "docker"])

    if file_type == "python":
        content = CLEAN_PYTHON.format(contact=gen_phone())
        filename = os.path.join(GOOD_DIR, f"config_settings_{i}.py")

    elif file_type == "terraform":
        # Resource names must be unique per file: Trivy parses the whole
        # folder as one Terraform module, and duplicate addresses stop it
        # from associating each bucket with its public-access block and
        # encryption config (making clean files look misconfigured).
        content = CLEAN_TERRAFORM
        for name in ("kyc_docs_key", "user_kyc_documents", "kyc_docs_sse",
                     "kyc_docs_block", "database_storage", "api_https",
                     "customer_db"):
            content = content.replace(name, f"{name}_{i}")
        filename = os.path.join(GOOD_DIR, f"aws_infrastructure_{i}.tf")

    else:
        content = CLEAN_DOCKER
        ext = ".dockerfile" if random.choice([True, False]) else ""
        filename = os.path.join(GOOD_DIR, f"Dockerfile_worker_{i}{ext}")

    with open(filename, "w") as f:
        f.write(content)

print("Done.")
print("  tests/fixtures/  → 2 deterministic fixture files (used by pytest)")
print(f"  {EVAL_DIR}/vulnerable/ → 100 vulnerable files (scanner rules + Trivy misconfigs)")
print(f"  {EVAL_DIR}/clean/     → 100 clean files")
print(f"\nScan evaluation data: python compliance_engine/scanner.py {EVAL_DIR}/")
