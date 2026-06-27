# =============================================================================
# DarkWeb Fraud Intelligence Agent — Makefile
# =============================================================================
# Production build, test, lint, Docker, ECR, and CDK deployment automation.
#
# Environment variables (override via env or make VAR=value):
#   AWS_ACCOUNT_ID  — target AWS account (default: from STS caller identity)
#   AWS_REGION      — target region (default: us-east-1)
# =============================================================================

# --- Configuration -----------------------------------------------------------
AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "123456789012")
AWS_REGION     ?= us-east-1
ECR_REPO       := dark-web-fraud/crawling-engine
ECR_URI        := $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com/$(ECR_REPO)
IMAGE_TAG      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "latest")
DOCKER         := docker
CDK            := npx cdk
PYTEST_ARGS    ?=

# CDK stack names (deploy in this order)
STACK_CORE         := DarkWebFraudCore
STACK_INTELLIGENCE := DarkWebFraudIntelligence
STACK_COMPUTE      := DarkWebFraudCompute
STACK_PIPELINE     := DarkWebFraudPipeline

# --- Phony targets -----------------------------------------------------------
.PHONY: install test lint layer-build fargate-build \
        ecr-login ecr-push \
        cdk-synth cdk-diff \
        cdk-deploy-all cdk-deploy-core cdk-deploy-intelligence \
        cdk-deploy-compute cdk-deploy-pipeline \
        destroy-all clean help

# --- Default target ----------------------------------------------------------
.DEFAULT_GOAL := help

# --- Development -------------------------------------------------------------

## Install project in editable mode with dev dependencies
install:
	pip install -e ".[dev]"

## Run test suite with coverage
test:
	python -m pytest tests/ \
		--cov=src/dark_web_fraud_agent \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=80 \
		-v $(PYTEST_ARGS)

## Lint source and tests with ruff
lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

# --- Docker builds -----------------------------------------------------------

## Build Lambda dependency layer image
layer-build:
	$(DOCKER) build \
		--target lambda-layer \
		--platform linux/amd64 \
		-t $(ECR_REPO):layer-$(IMAGE_TAG) \
		-f Dockerfile .

## Build Fargate application image
fargate-build:
	$(DOCKER) build \
		--target fargate-app \
		--platform linux/amd64 \
		-t $(ECR_REPO):$(IMAGE_TAG) \
		-t $(ECR_URI):$(IMAGE_TAG) \
		-t $(ECR_URI):latest \
		-f Dockerfile .

# --- ECR ---------------------------------------------------------------------

## Authenticate Docker to ECR
ecr-login:
	aws ecr get-login-password --region $(AWS_REGION) | \
		$(DOCKER) login --username AWS --password-stdin \
		$(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com

## Tag and push Fargate image to ECR (runs ecr-login + fargate-build first)
ecr-push: ecr-login fargate-build
	$(DOCKER) push $(ECR_URI):$(IMAGE_TAG)
	$(DOCKER) push $(ECR_URI):latest
	@echo "✓ Pushed $(ECR_URI):$(IMAGE_TAG) and $(ECR_URI):latest"

# --- CDK ---------------------------------------------------------------------

## Synthesize all CDK stacks
cdk-synth:
	$(CDK) synth --all --quiet

## Show diff for all stacks against deployed state
cdk-diff:
	$(CDK) diff --all

## Deploy Core stack
cdk-deploy-core:
	$(CDK) deploy $(STACK_CORE) \
		--require-approval never \
		--outputs-file cdk-outputs-core.json

## Deploy Intelligence stack
cdk-deploy-intelligence:
	$(CDK) deploy $(STACK_INTELLIGENCE) \
		--require-approval never \
		--outputs-file cdk-outputs-intelligence.json

## Deploy Compute stack
cdk-deploy-compute:
	$(CDK) deploy $(STACK_COMPUTE) \
		--require-approval never \
		--outputs-file cdk-outputs-compute.json

## Deploy Pipeline stack
cdk-deploy-pipeline:
	$(CDK) deploy $(STACK_PIPELINE) \
		--require-approval never \
		--outputs-file cdk-outputs-pipeline.json

## Deploy all 4 stacks in dependency order
cdk-deploy-all: cdk-deploy-core cdk-deploy-intelligence cdk-deploy-compute cdk-deploy-pipeline
	@echo "✓ All stacks deployed successfully"

## Destroy all stacks (reverse order)
destroy-all:
	$(CDK) destroy $(STACK_PIPELINE) --force
	$(CDK) destroy $(STACK_COMPUTE) --force
	$(CDK) destroy $(STACK_INTELLIGENCE) --force
	$(CDK) destroy $(STACK_CORE) --force
	@echo "✓ All stacks destroyed"

# --- Utilities ---------------------------------------------------------------

## Remove build artifacts
clean:
	rm -rf cdk.out/ htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf src/*.egg-info dist/ build/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; exit 0
	rm -f cdk-outputs-*.json

## Show this help
help:
	@echo ""
	@echo "DarkWeb Fraud Intelligence Agent — Build System"
	@echo "================================================"
	@echo ""
	@echo "Configuration:"
	@echo "  AWS_ACCOUNT_ID = $(AWS_ACCOUNT_ID)"
	@echo "  AWS_REGION     = $(AWS_REGION)"
	@echo "  ECR_URI        = $(ECR_URI)"
	@echo "  IMAGE_TAG      = $(IMAGE_TAG)"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /' | paste - - | \
		awk -F'\t' '{printf "  %-24s %s\n", $$2, $$1}' 2>/dev/null || \
		echo "  install test lint layer-build fargate-build ecr-login ecr-push"
	@echo ""
	@echo "  install                 Install project in editable mode with dev deps"
	@echo "  test                    Run pytest with coverage (min 80%)"
	@echo "  lint                    Lint with ruff (check + format)"
	@echo "  layer-build             Build Lambda layer Docker image"
	@echo "  fargate-build           Build Fargate app Docker image"
	@echo "  ecr-login               Authenticate Docker to ECR"
	@echo "  ecr-push                Build + push Fargate image to ECR"
	@echo "  cdk-synth               Synthesize all CDK stacks"
	@echo "  cdk-diff                Diff all stacks vs deployed"
	@echo "  cdk-deploy-all          Deploy all 4 stacks in order"
	@echo "  cdk-deploy-core         Deploy DarkWebFraudCore"
	@echo "  cdk-deploy-intelligence Deploy DarkWebFraudIntelligence"
	@echo "  cdk-deploy-compute      Deploy DarkWebFraudCompute"
	@echo "  cdk-deploy-pipeline     Deploy DarkWebFraudPipeline"
	@echo "  destroy-all             Destroy all stacks (reverse order)"
	@echo "  clean                   Remove build artifacts"
	@echo ""
