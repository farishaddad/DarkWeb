# =============================================================================
# DarkWeb Fraud Intelligence Agent — Multi-stage Dockerfile
# =============================================================================
# Targets:
#   lambda-layer  — pip-installs all deps into /opt/python (for Lambda layer ZIP)
#   lambda-app    — full Lambda runtime image with handler code
#   fargate-app   — slim Python image for ECS/Fargate crawling engine
#
# Usage:
#   docker build --target lambda-layer  -t dark-web-fraud/lambda-layer .
#   docker build --target lambda-app    -t dark-web-fraud/lambda-app .
#   docker build --target fargate-app   -t dark-web-fraud/fargate-app .
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Lambda dependency layer builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS lambda-layer

ARG PIP_NO_CACHE_DIR=1
ARG PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only requirements first for better Docker layer caching
COPY requirements.txt /build/requirements.txt

# Install all Lambda dependencies into the Lambda layer path
RUN pip install --no-cache-dir \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.12 \
    --only-binary=:all: \
    --upgrade \
    -r requirements.txt \
    -t /opt/python 2>/dev/null || \
    pip install --no-cache-dir \
    -r requirements.txt \
    -t /opt/python

# Also install beautifulsoup4 (not in requirements.txt but needed by Lambda)
RUN pip install --no-cache-dir \
    beautifulsoup4>=4.12.0 \
    -t /opt/python

# Strip bytecache and tests to reduce layer size
RUN find /opt/python -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; \
    find /opt/python -type d -name "tests" -exec rm -rf {} + 2>/dev/null; \
    find /opt/python -type d -name "test" -exec rm -rf {} + 2>/dev/null; \
    find /opt/python -name "*.dist-info" -type d -exec rm -rf {} + 2>/dev/null; \
    exit 0

# ---------------------------------------------------------------------------
# Stage 2: Lambda runtime image
# ---------------------------------------------------------------------------
FROM public.ecr.aws/lambda/python:3.12 AS lambda-app

# Copy the dependency layer
COPY --from=lambda-layer /opt/python /opt/python

# Copy application source
COPY src/ ${LAMBDA_TASK_ROOT}/src/
COPY pyproject.toml ${LAMBDA_TASK_ROOT}/

# Install the project package (editable not supported in Lambda, do a proper install)
RUN pip install --no-cache-dir --no-deps -e . 2>/dev/null || \
    pip install --no-cache-dir --no-deps .

# Ensure /opt/python is on the path (Lambda layer convention)
ENV PYTHONPATH="/opt/python:${LAMBDA_TASK_ROOT}"

# Default handler — override with --env AWS_LAMBDA_FUNCTION_HANDLER at runtime
# or set CMD per function in CDK
CMD ["dark_web_fraud_agent.agents.content_analyst.handler"]

# ---------------------------------------------------------------------------
# Stage 3: Fargate application image (crawling engine)
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS fargate-app

ARG PIP_NO_CACHE_DIR=1
ARG PIP_DISABLE_PIP_VERSION_CHECK=1

# Security: run as non-root
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        tini && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt beautifulsoup4>=4.12.0

# Copy application source and install the package
COPY src/ /app/src/
COPY pyproject.toml /app/

RUN pip install --no-cache-dir --no-deps .

# Strip unnecessary files
RUN find /usr/local/lib/python3.12 -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; exit 0

# Health check — verifies the process is responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import dark_web_fraud_agent; print('ok')" || exit 1

# Switch to non-root user
USER appuser

# Use tini as init to properly handle signals (important for Fargate graceful shutdown)
ENTRYPOINT ["tini", "--"]

# Default: run the crawling engine module
CMD ["python", "-m", "dark_web_fraud_agent.agents.crawling_engine"]
