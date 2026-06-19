# Dark Web Fraud Intelligence Agent

Multi-agent system for autonomous dark web crawling, AI-driven content analysis, STIX 2.1/MISP data structuring, and actionable banking fraud intelligence generation.

## Architecture

Built on AWS with:
- **Amazon Bedrock AgentCore** — Agent runtime (Claude Opus 4.8)
- **AWS Step Functions** — Pipeline orchestration
- **Amazon OpenSearch Serverless** — VECTORSEARCH for threat intel correlation
- **Amazon S3 + Annotations** — Raw artifact storage with queryable metadata
- **Amazon DynamoDB** — Agent state and campaign convergence tracking
- **Amazon SNS/SQS** — Alert distribution

## Agents

| Agent | Role |
|-------|------|
| Crawling Engine | Tor/I2P navigation, proxy rotation, S3 storage |
| Content Analyst | Fraud classification, entity extraction, severity scoring |
| Data Structurer | STIX 2.1 objects, tier classification, OpenSearch indexing |
| Tagging Engine | MITRE ATT&CK, custom taxonomy, Galaxy matching |
| Alert Generator | Campaign convergence, SNS publishing, digests |
| MISP Integration | Bidirectional STIX ↔ MISP conversion |

## Setup

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Deploy infrastructure
pip install aws-cdk-lib constructs
cdk bootstrap
cdk deploy --all
```

## Project Structure

```
src/dark_web_fraud_agent/
├── agents/          # 6 agent implementations
├── config/          # Pydantic configuration models
├── infrastructure/  # CDK stacks + orchestration
├── models/          # Shared data models
├── utils/           # Utilities
└── pipeline.py      # End-to-end pipeline wiring

tests/
├── unit/            # 300+ unit tests
├── property/        # Property-based tests (hypothesis)
└── integration/     # Integration tests
```

## License

Proprietary
