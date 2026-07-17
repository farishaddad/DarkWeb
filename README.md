# Dark Web Fraud Intelligence Agent

An autonomous multi-agent system that crawls dark web sources, applies AI-driven analysis to unstructured content, structures findings into threat intelligence standards (STIX 2.1 and MISP), and generates actionable banking fraud alerts — all running on AWS.

---

## Background

### The Problem

Banking fraud is evolving faster than traditional detection systems can adapt. Threat actors operate openly on dark web forums, Telegram channels, and illicit marketplaces — selling stolen credentials ("Fullz"), distributing phishing kits, sharing MFA bypass techniques, and coordinating account takeover campaigns. The intelligence is there, but it's buried in unstructured chatter across hundreds of hidden services.

Fraud teams today face three challenges:

1. **Access** — Dark web sources require specialised infrastructure (Tor/I2P proxies, rotating identities, CAPTCHA handling) that's difficult to maintain at scale.
2. **Signal extraction** — Raw forum posts mix fraud-relevant intelligence with noise. A single thread might contain BIN ranges, SWIFT codes, Bitcoin wallet addresses, and technique descriptions — all embedded in slang and obfuscation.
3. **Operationalisation** — Even when intelligence is found manually, transforming it into structured, machine-readable formats (STIX 2.1, MISP events) for integration with detection systems requires significant analyst effort.

### The Opportunity

The convergence of three technologies makes an automated solution viable:

- **Large Language Models** (Claude Opus 4.8) can understand nuanced fraud language, classify content, and extract structured entities from unstructured dark web text with high accuracy.
- **Agentic AI frameworks** (Amazon Bedrock AgentCore) allow complex multi-step workflows to be orchestrated as autonomous agents with built-in memory, tools, and reasoning.
- **Threat intelligence standards** (STIX 2.1, MISP) provide a universal language for structuring, correlating, and sharing fraud intelligence across organisations.

---

## Approach

This system adopts a **multi-agent pipeline architecture** where each agent specialises in one phase of the intelligence lifecycle. The design mirrors how a human fraud research team operates — but runs 24/7, processes hundreds of sources simultaneously, and structures every finding for immediate machine consumption.

### Intelligence Lifecycle

```
Dark Web Sources → Crawl → Classify → Structure → Tag → Alert → Fraud Detection Systems
```

### Tiered Intelligence Model

Harvested data is classified into three functional tiers, each driving a different response action:

| Tier | Examples | Action |
|------|----------|--------|
| **Observable** | IP addresses, BTC wallets, URLs, email aliases | Immediate blocking and blacklisting |
| **Indicator** | Composite attack patterns (e.g., specific API call sequences in bypass tools) | Real-time detection rule generation |
| **TTP** | Phishing kit deployment methods, MFA bypass guides, synthetic identity creation | Long-term strategic detection logic |

This tiered approach follows the STIX 2.1 framework's graph-based model, where Observables support Indicators, and Indicators implement TTPs — creating a traceable chain from atomic data points to strategic adversarial behaviours.

### Data Standards

- **STIX 2.1** (Structured Threat Information Expression) — Models relationships between threat actors, attack patterns, indicators, and observables in a graph structure.
- **MISP** (Malware Information Sharing Platform) — Handles high-volume indicator management with machine tagging, correlation, and sharing via taxonomies and galaxy clusters.
- **MITRE ATT&CK + F3** (Fight Fraud Framework) — Maps techniques to standardised IDs for cross-organisation correlation.

### Automated Tagging Strategy

Intelligence is automatically classified using:
- **MITRE ATT&CK technique IDs** (e.g., T1566/T1566.001 for phishing, T1078/T1078.001 for account takeover, T1111 for MFA bypass, T1585/T1585.001 for synthetic identity, T1539 for CNP fraud)
- **Custom banking fraud taxonomy** (`fraud:type="mfa-bypass"`, `fraud:target="retail-bank"`)
- **MISP Galaxy clusters** linking events to known threat actor profiles
- **Threat level tags** derived from severity scoring (1-3: low, 4-6: medium, 7-9: high, 10: critical)

Content that doesn't match any taxonomy is automatically flagged with a `requires-review` tag for analyst triage.

---

## Architecture

### AWS-Native Design

The system is built entirely on AWS services, leveraging the latest launches from AWS Summit NY 2026:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AWS Step Functions                             │
│                     (Pipeline Orchestrator)                           │
├──────────┬──────────┬──────────┬──────────┬─────────────────────────┤
│ Crawling │ Content  │  Data    │ Tagging  │   Alert                  │
│ Engine   │ Analyst  │Structurer│ Engine   │  Generator               │
│          │          │          │          │                          │
│ Tor/I2P  │Claude 4.8│ STIX 2.1 │ATT&CK   │ Campaign                │
│ Proxies  │Guardrails│ OpenSearch│Taxonomy  │ Convergence             │
│ S3 Store │   NER    │  MISP    │ Galaxy   │   SNS                   │
└──────────┴──────────┴──────────┴──────────┴─────────────────────────┘
     │           │           │           │            │
     ▼           ▼           ▼           ▼            ▼
┌─────────┐ ┌────────┐ ┌─────────┐ ┌────────┐ ┌──────────┐
│Amazon S3│ │Bedrock │ │OpenSearch│ │AgentCore│ │ SNS/SQS  │
│+Annotate│ │  LLM   │ │Serverles│ │  KB    │ │  Alerts  │
└─────────┘ └────────┘ └─────────┘ └────────┘ └──────────┘
```

### Key AWS Services

| Service | Role | NY Summit 2026 Feature |
|---------|------|------------------------|
| Amazon Bedrock AgentCore | Agent runtime — declarative agent definition | AgentCore Harness (GA) |
| Claude Opus 4.8 | LLM for content analysis and entity extraction | Available on Bedrock |
| AgentCore Managed KB | RAG over historical threat intel | Smart Parsing + Agentic Retriever |
| Bedrock Guardrails | Content safety for dark web material | AgentCore Policy Integrations |
| AgentCore Optimization | Production trace analysis, A/B testing | Failure/intent/trajectory insights |
| AWS Step Functions | Pipeline orchestration with agent reasoning | AgentCore Integration |
| OpenSearch Serverless | Vector search for threat intel correlation | Next Gen for Agentic AI (VECTORSEARCH) |
| Amazon S3 + Annotations | Raw artifacts with queryable metadata | S3 Annotations (up to 1 GB context) |
| AWS Secrets Manager | Tor/MISP credential management | AgentCore BYO Secrets |
| Amazon DynamoDB | Agent state, crawl tracking, campaign convergence | — |
| Amazon EventBridge | Scheduled crawl triggers (every 5 minutes) | — |
| Amazon SNS/SQS | Alert fan-out to downstream consumers | — |
| Amazon VPC | Isolated network for Tor proxy infrastructure | — |
| AWS Continuum | STRIDE threat modeling for the system itself | Gated Preview |

### Pipeline Flow

1. **EventBridge** triggers the Step Functions state machine every 5 minutes
2. **Crawling Engine** connects to Tor via VPC-isolated SOCKS5 proxies, rotates circuits on failure, stores raw HTML in S3 with metadata annotations
3. **Content Analyst** applies Bedrock Guardrails for safety, classifies content via Claude Opus 4.8, extracts entities (BINs, SWIFT codes, wallets, IPs, emails) using LLM + regex fallback
4. **Data Structurer** creates STIX 2.1 objects (SDOs, SCOs, SROs), classifies intelligence tier, generates embeddings, indexes into OpenSearch VECTORSEARCH
5. **Tagging Engine** applies MITRE ATT&CK tags, custom fraud taxonomy, threat-level tags, and links to MISP Galaxy clusters
6. **Alert Generator** tracks convergence — when 3+ items reference the same TTP within 24 hours, generates a consolidated campaign alert and publishes to SNS

---

### Combined Analysis (Cost Optimisation)

The Content Analyst uses a **single Bedrock call** (`classify_and_extract_combined`) that returns fraud classification, entity extraction, and technique categorisation in one JSON response. This replaces the original 3-call pattern (classify → extract → categorise) and delivers:

- **~3× cost reduction** — one prompt instead of three, with shared context
- **~2× latency improvement** — single round-trip to Bedrock instead of three sequential calls
- **Graceful fallback** — if the combined response fails to parse, the system falls back to the 3-call path automatically

### Observability

All Lambda handlers emit **CloudWatch Embedded Metric Format (EMF)** via the `update_health()` method in `AgentBase`. The Lambda runtime auto-converts EMF stdout to CloudWatch custom metrics — zero additional API calls needed.

| Metric | Description |
|--------|-------------|
| `ItemsProcessed` | Items successfully processed per invocation |
| `Errors` | Errors encountered per invocation |
| `ProcessingThroughput` | Items per minute (exponential moving average) |
| `BedrockTokens` | Bedrock tokens consumed |
| `ErrorRate` | Error ratio for health status derivation |

**Namespace:** `dark-web-fraud` · **Dimensions:** `agent_id`

### Cross-Stack Architecture

CDK multi-stack deployments create dependency cycles when constructs reference each other across stacks. This project uses an anti-cycle pattern:

1. **ComputeStack** creates all Lambda functions, ECS resources, and the SNS topic, then **exports ARNs to SSM Parameter Store** (`/dark-web-fraud/lambda/*-arn`, `/dark-web-fraud/cluster-arn`, `/dark-web-fraud/alert-topic-arn`)
2. **PipelineStack** reads SSM strings with `ssm.StringParameter.value_for_string_parameter()` and uses `from_*_arn()` to create non-owned L2 constructs — no `Fn::ImportValue` back-edges
3. Step Functions invokes ECS via **`tasks.CallAwsService`** (raw SDK integration) rather than `tasks.EcsRunTask` (which requires L2 construct references that create cycles)

This eliminates all CDK `DependencyCycle` errors while maintaining full type safety and deployment ordering.

---

## Agents

### Crawling Engine
- Navigates Tor/I2P hidden services using `stem` library for circuit control
- Rotates proxy identity on each retry (max 3 retries per source)
- Circuit breaker pattern: isolates unreachable sources after 5 consecutive failures
- Stores raw artifacts in S3 with queryable annotations (source URL, category, timestamp, content hash)
- Tracks crawl state in DynamoDB for deduplication and scheduling

### Content Analyst
- Invokes Claude Opus 4.8 via Bedrock with structured classification prompts
- Applies Bedrock Guardrails (prompt injection, harmful content, sensitive data detection)
- Extracts entities via LLM + regex fallback (BIN patterns, BTC wallets, IPv4, emails, SWIFT codes)
- Categorises techniques into 5 fraud types: MFA bypass, synthetic identity, phishing kit, CNP fraud, account takeover
- Assigns severity scores (1-10) based on institution count, technique sophistication, confidence, and entity diversity

### Data Structurer
- Creates STIX 2.1 Domain Objects (Threat Actor, Attack Pattern, Indicator, Malware)
- Creates STIX 2.1 Cyber-observable Objects (IPv4Address, URL, EmailAddress, DomainName, Artifact/BTC)
- Establishes STIX Relationship Objects linking actors to techniques
- Classifies intelligence into Observable/Indicator/TTP tiers with referential links
- Serializes/deserializes STIX Bundles (validated round-trip)
- Generates vector embeddings via Bedrock Titan and indexes into OpenSearch Serverless

### MISP Integration
- Bidirectional conversion: STIX 2.1 Bundle ↔ MISP Event
- Maps SCOs to MISP attributes (ip-src, url, email-src, domain, btc)
- Maps SDOs to MISP objects (threat-actor, attack-pattern, malware)
- Creates events via PyMISP REST API with validation error retry

### Tagging Engine
- Loads custom JSON taxonomy definitions (namespace:predicate="value" format)
- Applies fraud tags based on entity keywords (SWIFT → swift-transfer, BIN → bin-attack)
- Maps fraud categories to MITRE ATT&CK technique IDs
- Assigns threat-level tags from severity scores
- Links events to MISP Galaxy clusters for known threat actor profiles
- Applies `requires-review` fallback for unmatched content

### Alert Generator
- Tracks intelligence items by TTP reference with configurable convergence window (default 24h)
- Prunes expired items automatically
- Generates campaign alerts when 3+ items converge around a common TTP
- Publishes alerts to SNS with severity-based message attributes
- Produces periodic summary digests of low/medium findings
- Formats alerts for downstream API integration (JSON-serializable with provenance)

---

## Infrastructure as Code

Three AWS CDK stacks (Python):

### Core Stack (`DarkWebFraudCoreStack`)
- VPC with Public/Private/Isolated subnets (2 AZs, 1 NAT Gateway)
- S3 bucket (encrypted, versioned, 365-day lifecycle)
- 2 DynamoDB tables (Agent State + Campaign Convergence with TTL)
- 2 Secrets Manager secrets (Tor credentials + MISP API key)
- IAM roles with least-privilege per agent

### Intelligence Stack (`DarkWebFraudIntelligenceStack`)
- OpenSearch Serverless VECTORSEARCH collection (GPU-accelerated)
- Encryption, network, and data access security policies

### Pipeline Stack (`DarkWebFraudPipelineStack`)
- Step Functions state machine (5-agent pipeline)
- EventBridge rule (5-minute crawl schedule)
- SNS topic + SQS alert queue with dead-letter queue
- CloudWatch alarms (pipeline failures > 3, DLQ depth > 10)

---

## Getting Started

### Prerequisites
- Python 3.11+
- AWS CLI configured with appropriate credentials
- AWS CDK CLI (`npm install -g aws-cdk`)

### Install
```bash
git clone <repo-url>
cd DarkWeb
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests
```bash
# All unit tests
pytest

# With coverage
pytest --cov=dark_web_fraud_agent --cov-report=html

# Specific test module
pytest tests/unit/test_crawling_engine.py -v
```

### Deploy
```bash
# Install CDK dependencies
pip install aws-cdk-lib constructs

# Bootstrap (one-time per account/region)
cdk bootstrap

# Preview changes
cdk diff

# Deploy all stacks
cdk deploy --all --require-approval broadening
```

### Estimated Costs (Low Volume)
| Resource | Monthly Cost |
|----------|-------------|
| NAT Gateway | ~$32 |
| OpenSearch Serverless (min OCUs) | ~$10-20 |
| DynamoDB (on-demand) | < $1 |
| Step Functions (free tier) | $0 |
| Secrets Manager (2 secrets) | ~$0.80 |
| S3 + SNS/SQS | < $1 |
| **Total** | **~$45-55/month** |

---

## Project Structure

```
dark-web-fraud-agent/
├── app.py                          # CDK entry point
├── cdk.json                        # CDK configuration
├── pyproject.toml                   # Package configuration & dependencies
├── requirements.txt                 # Runtime dependencies
├── requirements-dev.txt             # Development dependencies
├── src/
│   └── dark_web_fraud_agent/
│       ├── agents/                  # 6 agent implementations
│       │   ├── crawling_engine.py   # Tor/I2P crawling + circuit breaker
│       │   ├── content_analyst.py   # Bedrock classification + NER
│       │   ├── data_structurer.py   # STIX 2.1 + OpenSearch indexing
│       │   ├── misp_integration.py  # STIX ↔ MISP bidirectional
│       │   ├── tagging_engine.py    # ATT&CK + taxonomy + Galaxy
│       │   └── alert_generator.py   # Campaign convergence + SNS
│       ├── config/
│       │   └── settings.py          # 6 Pydantic config models
│       ├── infrastructure/
│       │   ├── cdk_core_stack.py    # VPC, S3, DynamoDB, Secrets, IAM
│       │   ├── cdk_intelligence_stack.py  # OpenSearch VECTORSEARCH
│       │   ├── cdk_pipeline_stack.py      # Step Functions, EventBridge, SNS
│       │   ├── pipeline_orchestrator.py   # Step Functions client wrapper
│       │   ├── fault_isolation.py         # Per-agent fault tracking
│       │   └── scheduler.py               # EventBridge + agent initialization
│       ├── models/
│       │   ├── shared.py            # AgentHealth, IntelligenceTier, TierLink
│       │   ├── content_analyst.py   # ClassifiedContent, ExtractedEntity
│       │   ├── crawl_result.py      # CrawlResult with SHA-256 dedup
│       │   └── alerts.py            # FraudAlert, AlertProvenance, DetectionRule
│       └── pipeline.py              # End-to-end orchestration wiring
├── tests/
│   ├── unit/                        # 300+ unit tests (22 test files)
│   ├── property/                    # Property-based tests (hypothesis)
│   └── integration/                 # Integration tests
├── explorer/                        # Fraud Intelligence Explorer UI
│   ├── src/
│   │   ├── views/                   # 5 React views (Dashboard, AlertList, etc.)
│   │   ├── components/              # Shared UI components (Layout, ErrorBoundary)
│   │   ├── store/                   # zustand state management
│   │   ├── data/                    # MockProvider, LiveProvider, mock dataset
│   │   ├── utils/                   # Filters, pagination, graph, validation
│   │   └── types/                   # Full TypeScript type definitions
│   ├── package.json                 # React + Vite + Tailwind dependencies
│   └── vite.config.ts              # Vite build configuration
└── .kiro/
    └── specs/
        ├── dark-web-fraud-agent/    # Backend agent pipeline spec
        └── fraud-intelligence-explorer/  # Explorer UI spec
```

---

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `stix2` | STIX 2.1 object creation and validation |
| `pymisp` | MISP event management via REST API |
| `boto3` | AWS service interactions |
| `pydantic` | Configuration validation |
| `stem` | Tor controller (circuit management) |
| `aiohttp` + `aiohttp-socks` | Async HTTP via SOCKS5 proxy |
| `opensearch-py` | OpenSearch Serverless client |
| `hypothesis` | Property-based testing |
| `moto` | AWS service mocking for tests |
| `aws-cdk-lib` | Infrastructure as Code |

---

## Fraud Intelligence Explorer (UI)

A React single-page application for exploring intelligence produced by the pipeline. Designed for demos and analyst use.

### Features

| View | Route | What it shows |
|------|-------|---------------|
| **Dashboard** | `/` | KPI tiles, severity donut chart, category bar chart, 30-day timeline, recent alerts |
| **Alert List** | `/alerts` | Filterable list with facets (category, severity, tier, date, keyword search), sorting, pagination |
| **Alert Detail** | `/alerts/:id` | Full provenance chain (5-step stepper), detection rules, machine tags, galaxy match |
| **Signal Sources** | `/alerts/:id/sources` | Expandable source cards with confidence bars, entity tables, guardrail status |
| **Relationship Graph** | `/graph` | d3-force visualization of entity/TTP/institution/campaign connections |

### Quick Start

```bash
cd explorer
npm install
npm run dev
# Open http://localhost:5173
```

The app runs in **mock mode** by default — no backend required. It ships with 24 realistic alerts covering all fraud categories.

### Live Mode

To connect to a deployed API Gateway:

```bash
VITE_DATA_MODE=live VITE_API_BASE_URL=https://your-api.execute-api.eu-west-2.amazonaws.com npm run dev
```

### Tech Stack

| Library | Purpose |
|---------|---------|
| React 18 + TypeScript | UI framework |
| Vite | Build tool + dev server |
| Tailwind CSS | Styling |
| zustand | State management |
| recharts | Dashboard charts |
| d3-force | Relationship graph |
| React Router | Client-side routing |

### Testing

```bash
cd explorer
npm run test        # Run all tests (vitest)
npm run build       # Production build
```

---

## Contributing

1. Create a feature branch from `main`
2. Write tests first (unit + property-based where applicable)
3. Implement the feature
4. Run `pytest` — all tests must pass
5. Run `ruff check` — no lint errors
6. Submit a pull request

---

## License

Proprietary — Internal use only.
