# Project: Dark Web Fraud Intelligence Agent

## Purpose
Autonomous pipeline to extract banking fraud intelligence from dark web sources
and deliver structured, machine-readable alerts to fraud detection systems.

## Agent pipeline (in order)
1. **CrawlingEngine** — Tor/I2P proxy crawl → raw HTML to S3
2. **ContentAnalyst** — Bedrock Guardrails + Claude Opus → classification, NER, severity
3. **DataStructurer** — STIX 2.1 bundle → OpenSearch VECTORSEARCH index
4. **TaggingEngine** — MITRE ATT&CK + custom taxonomy → machine tags
5. **AlertGenerator** — campaign convergence + entity co-occurrence → SNS alerts

## AWS Region
`eu-west-2` (London) — financial services data residency requirement.

## CDK stack dependency order
CoreStack → ComputeStack → IntelligenceStack → PipelineStack

## DynamoDB table reference
| Table | Env var | Primary use |
|-------|---------|-------------|
| `dark-web-fraud-agent-state` | `DYNAMODB_TABLE` | Crawl circuit-breaker state |
| `dark-web-fraud-convergence` | `DYNAMODB_CONVERGENCE_TABLE` | TTP convergence + ENTITY# co-occurrence |

## S3 prefix conventions
| Prefix | Content |
|--------|---------|
| `crawl-artifacts/YYYY/MM/DD/<id>/` | Raw HTML from CrawlingEngine |
| `stix-bundles/YYYY/MM/DD/<id>/` | STIX 2.1 JSON bundles |
| `tag-manifests/YYYY/MM/DD/<id>/` | Tag manifest JSON (parallel to stix-bundles) |
| `alert-artifacts/YYYY/MM/DD/<id>/` | Alert payloads |

## Standalone contract
Each Lambda is independently deployable. No agent imports from another agent's
module — only from `models/` and `config/`. Inter-agent communication is via
S3 key references passed through Step Functions payload.
