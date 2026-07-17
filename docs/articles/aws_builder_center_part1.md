# Dark web fraud signals for banking anti-fraud models (Part 1): Why upstream intelligence changes the game

**Faris Haddad** | July 2026 | AWS Builder Center

---

## Introduction

Amazon Bedrock gives financial institutions the foundation to build automated threat intelligence pipelines that convert unstructured dark web chatter into machine-readable fraud alerts — without maintaining custom ML infrastructure.

Banking fraud does not stand still. Attack patterns evolve on a cycle measured in days, not quarters. A synthetic identity playbook surfaces on a dark web forum on Monday; by Friday, a coordinated wave of fraudulent account openings hits a tier-one bank. The detection system flags it — eventually — but only after losses mount and manual investigators scramble to understand what happened.

The problem is not a lack of detection capability. Banks have invested heavily in transaction monitoring, behavioural analytics, and rules engines. The problem is timing. These systems are fundamentally reactive. They respond to fraud that has already begun executing against the bank's customers and controls.

Dark web forums represent the most upstream source of fraud intelligence available. They are where stolen credentials are sold, where attack toolkits are distributed, where adversaries discuss which institutions have weak controls and which bypass techniques work. This intelligence exists days to weeks before any corresponding fraud attempt reaches a bank's perimeter.

This three-part series walks through an automated pipeline built on AWS that structures dark web signals into machine-readable fraud alerts conforming to industry threat intelligence standards. The pipeline uses a multi-agent architecture powered by Amazon Bedrock to handle the full lifecycle: crawling, classification, structuring, tagging, and alert generation.

**Part 1** (this post) covers the strategic rationale, the intelligence model, and the architecture overview. **Part 2** builds the first three agents with a full code walkthrough. **Part 3** covers detection logic, deployment patterns, and five worked fraud pattern examples.

---

## Why dark web signals matter for fraud detection

Traditional fraud detection operates on a simple premise: observe transactions, identify anomalies, flag or block. This works when the fraud is happening. It does not work when the fraud is being planned, resourced, and staged.

Dark web monitoring shifts the detection window left — sometimes by days, sometimes by weeks. The intelligence appears in predictable categories, and each category provides a distinct lead-time advantage.

### The five signal types

**1. Fullz listings**

A "Fullz" is a complete identity package: name, date of birth, national insurance number, address history, mother's maiden name, and often the answers to common security questions. When a batch of Fullz targeting a specific bank's customer base appears for sale, the bank has a window — typically 24 to 48 hours — before those identities are used for account opening fraud or account takeover.

A concrete example: a threat actor posts 2,300 Fullz records explicitly tagged "UK high-street, Barclays verified" on a prominent carding forum. A bank receiving this signal can pre-emptively flag those identities in its account opening workflow, add step-up verification, or freeze matching applications entirely.

**2. BIN dumps and card data**

Bank Identification Number (BIN) dumps contain partial or complete card data, often from skimming operations or merchant breaches. When a dump surfaces containing BINs belonging to a specific issuer, that issuer gains advance notice that card-not-present fraud attempts are imminent against those card ranges.

**3. MFA bypass tutorials and toolkits**

These are instructional posts or downloadable kits that teach adversaries how to circumvent specific multi-factor authentication implementations. A tutorial titled "Bypassing [Bank X] push notification MFA using SIM swap + SS7 redirect" gives the targeted bank direct intelligence about which control is about to be attacked and the specific technique that will be used.

**4. Account takeover (ATO) kits**

ATO kits are packaged tools — often including credential stuffing scripts, proxy rotation configurations, and browser fingerprint spoofing — tailored to specific banking platforms. Their appearance signals that automated ATO campaigns are being prepared against the targeted institution.

**5. Synthetic identity playbooks**

These are step-by-step guides for creating synthetic identities that pass a specific bank's KYC checks. They often include details about which document verification services the bank uses, what credit file thin-file thresholds trigger manual review, and how to age a synthetic identity to avoid velocity checks.

### The lead-time advantage

The value of these signals is not their existence — security teams have known about dark web activity for years. The value is in the lead time they provide when captured and operationalised at machine speed.

| Signal type | Typical lead time | Defensive action enabled |
|---|---|---|
| Fullz listing | 24–48 hours | Pre-emptive identity flagging |
| BIN dump | 12–36 hours | Card range monitoring, proactive reissue |
| MFA bypass tutorial | 1–2 weeks | Control hardening before exploitation |
| ATO kit | 3–7 days | Bot detection tuning, velocity rule adjustment |
| Synthetic identity playbook | 2–4 weeks | KYC rule update, document verification tuning |

The challenge is that capturing this lead time requires automation. A human analyst reading forum posts cannot scale to the volume of dark web activity relevant to a single major bank. This is where the pipeline architecture becomes necessary.

---

## The signal extraction problem

Three fundamental challenges make dark web intelligence difficult to operationalise at scale.

### Challenge 1: Access

Dark web content lives on Tor hidden services and I2P networks. Forums require registration, reputation building, and sometimes payment. Content moves — sites go offline, migrate to new .onion addresses, or restructure access controls. Building and maintaining access infrastructure is a non-trivial engineering problem that requires specialised crawling agents capable of handling authentication, CAPTCHA challenges, and network-level obfuscation.

### Challenge 2: Signal-to-noise

Even with access, the raw content is noisy. Forum posts use slang, deliberate misspelling, and coded language to evade automated monitoring. A post advertising "fresh UK banks, 50 per head, verified for drops" is selling stolen bank account credentials — but extracting that meaning requires contextual understanding that traditional keyword-based systems miss.

Relevant content is buried among scams, disputes between forum members, outdated listings, and deliberate disinformation. The signal-to-noise ratio on a typical carding forum is roughly 1:15 — for every actionable intelligence item, there are fifteen posts that are noise, duplicates, or stale.

### Challenge 3: Operationalisation

The hardest problem is the last mile. Even when a skilled analyst identifies a relevant dark web post, converting it into a structured format that downstream systems can consume — fraud rules engines, ML feature stores, case management platforms — requires manual effort. An analyst might spend 30 minutes converting a single forum post into a structured indicator with the right taxonomy, confidence level, and context.

At the volume a major bank needs to monitor (hundreds of relevant posts per day across dozens of forums), manual operationalisation is impossible.

This is the gap that automation closes. A multi-agent pipeline powered by large language models can handle all three challenges: maintaining access infrastructure, performing contextual classification at scale, and producing structured output in standard formats.

---

## Threat intelligence standards: STIX 2.1 and MISP

Before building the pipeline, the output format matters. Producing unstructured alerts that require human interpretation defeats the purpose. The pipeline must produce output that is directly consumable by downstream systems — Security Operations Centre (SOC) platforms, fraud detection engines, and threat intelligence sharing communities.

Two standards dominate the threat intelligence ecosystem: STIX 2.1 and MISP.

### STIX 2.1: The language

Structured Threat Information eXpression (STIX) 2.1 is a standardised JSON-based language for expressing cyber threat intelligence. Published by OASIS, it provides a common vocabulary and data model for describing threats, threat actors, attack patterns, and indicators.

STIX organises intelligence into three object categories:

**STIX Domain Objects (SDOs)** represent high-level intelligence concepts:
- **Threat Actor** — an individual or group conducting malicious activity
- **Attack Pattern** — a description of how an adversary exploits a target (maps to MITRE ATT&CK)
- **Indicator** — a pattern that detects suspicious or malicious activity
- **Campaign** — a coordinated set of malicious activities
- **Malware** — malicious software used in attacks
- **Vulnerability** — a weakness that can be exploited

**STIX Cyber-observable Objects (SCOs)** represent concrete technical artefacts:
- IPv4/IPv6 addresses
- URLs and domain names
- Email addresses and messages
- File hashes
- User account identifiers

**STIX Relationship Objects (SROs)** connect SDOs and SCOs into a knowledge graph:
- "Threat Actor X **uses** Attack Pattern Y"
- "Indicator A **indicates** Campaign B"
- "Malware C **targets** Vulnerability D"

The graph-based model is what makes STIX powerful. A single dark web forum post about a new ATO kit can generate a Threat Actor object, an Attack Pattern object, multiple Indicator objects, and the relationships between them — all in a single, machine-parseable JSON bundle.

### MISP: The platform

MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform for storing, correlating, and sharing Indicators of Compromise (IoCs) and threat intelligence. Originally developed by CIRCL (Computer Incident Response Center Luxembourg) for the NATO community, it has become the de facto platform for threat intelligence sharing across financial services.

MISP provides:
- A structured database for storing indicators with rich metadata
- Correlation engines that automatically link related indicators
- Sharing mechanisms (communities, organisations, trust groups)
- Taxonomies and tagging for classification
- Native STIX 2.1 import and export

### How they relate

STIX and MISP are complementary, not competing.

| Dimension | STIX 2.1 | MISP |
|---|---|---|
| Type | Data format / language | Platform / application |
| Purpose | Standardise how intelligence is expressed | Store, correlate, and share intelligence |
| Format | JSON (serialisation format) | Web application with REST API |
| Analogy | PDF (the document format) | Google Docs (the platform for working with documents) |

STIX is how you write the intelligence. MISP is where you store, search, and share it. The pipeline produces STIX 2.1 bundles as its primary output. Those bundles can be ingested directly into a MISP instance, shared with Financial Sector Information Sharing and Analysis Centres (FS-ISACs), or consumed by any SOC tool that supports the STIX standard — which includes virtually all enterprise SIEM and SOAR platforms.

### Why this matters for banks

The practical consequence: a bank deploying this pipeline does not need to build custom adapters for each downstream consumer. The STIX 2.1 output is directly consumable by:
- Splunk Enterprise Security (native STIX ingestion)
- IBM QRadar (STIX/TAXII integration)
- Microsoft Sentinel (STIX-compatible threat intelligence feeds)
- Internal fraud rules engines (via STIX JSON parsing)
- FS-ISAC sharing communities (STIX is the standard exchange format)
- MISP instances (native STIX 2.1 import)

No custom adapters. No proprietary formats. The output speaks the language that SOC tools already understand.

---

## The tiered intelligence model

Not all intelligence is equal, and not all intelligence feeds the same systems. The pipeline organises output into three tiers based on abstraction level and operational use.

### Tier 1: Observables

Observables are raw, atomic data points with no interpretation attached. They are facts extracted from dark web content.

**Examples:** A credit card number, an email address appearing in a breach list, a .onion URL hosting a phishing kit, a cryptocurrency wallet address receiving payments for stolen data.

**Fraud prevention action:** Direct matching against watchlists and blocklists. An observable feeds real-time transaction screening — if a card number from a BIN dump appears in a payment authorisation request, block it immediately.

**Pattern reference:** DC-007 (compromised card data detection), DC-008 (credential exposure monitoring)

### Tier 2: Indicators

Indicators are observables combined with context and a detection pattern. They answer "what should I look for?" rather than just "what exists?"

**Examples:** "If an account login attempt originates from IP range X AND uses credentials matching breach dataset Y AND occurs within 48 hours of the breach listing appearing, flag as high-confidence ATO attempt." A STIX Indicator object with a detection pattern expressed in STIX Patterning language.

**Fraud prevention action:** ML feature engineering and detection rule creation. Indicators feed the feature store — they become signals that fraud models consume alongside transaction-level features. They also generate deterministic rules for scenarios where the confidence is high enough to act without model inference.

**Pattern reference:** CHAPS-026 (payment velocity anomaly with compromised credential context), PS-001 (new payee setup with known synthetic identity markers)

### Tier 3: TTPs (Tactics, Techniques, and Procedures)

TTPs describe how adversaries operate — their methodologies, tools, and procedures. They are the highest-abstraction intelligence and the most durable (TTPs change slowly compared to observables, which change constantly).

**Examples:** "Threat group Z is using synthetic identities aged for 90+ days with thin credit files, applying for current accounts at UK banks that use [specific document verification vendor], exploiting a gap in the vendor's liveness detection for identity documents." A STIX Attack Pattern object linked to a Threat Actor and a Campaign.

**Fraud prevention action:** Strategic control design and detection logic updates. TTPs inform how detection models are structured, what features matter, and where control gaps exist. They feed quarterly model retraining, control framework updates, and red team exercises.

**Pattern reference:** XC-007 (cross-channel synthetic identity orchestration)

### Tier summary

| Tier | What it represents | Examples | Fraud prevention action | Pattern reference |
|---|---|---|---|---|
| Observable | Atomic data point | Card numbers, emails, URLs, wallet addresses | Watchlist matching, real-time blocking | DC-007, DC-008 |
| Indicator | Contextualised detection pattern | Compound conditions with temporal and relational logic | ML features, detection rules | CHAPS-026, PS-001 |
| TTP | Adversary methodology | Attack playbooks, technique descriptions, tool capabilities | Control design, model retraining | XC-007 |

Each tier feeds different bank systems at different operational tempos. Observables feed real-time systems (millisecond decisions). Indicators feed near-real-time detection (seconds to minutes). TTPs feed strategic systems (days to weeks).

---

## Architecture overview

The pipeline uses a five-agent architecture, where each agent handles a distinct stage of the intelligence lifecycle. All agents run on Amazon Bedrock, with supporting AWS services handling infrastructure concerns.

### The five agents

**Agent 1: Crawling Engine**

Manages access to dark web sources. Handles Tor circuit management, forum authentication, pagination, and content retrieval. Outputs raw content with source metadata (forum name, thread context, author reputation, timestamp). Does not perform any classification — its job is reliable, comprehensive content acquisition.

**Agent 2: Content Analyst**

Receives raw content from the Crawling Engine and performs initial classification. Determines relevance (is this about financial fraud?), categorises by signal type (Fullz, BIN dump, ATO kit, tutorial, playbook), and assigns an initial confidence score. Filters noise — the 1:15 signal-to-noise problem is solved here. Only content passing the relevance threshold advances to the next stage.

**Agent 3: Data Structurer**

Takes classified content and produces structured STIX 2.1 objects. Extracts entities (threat actors, targeted institutions, tools mentioned), creates appropriate SDOs and SCOs, establishes relationships, and assigns the intelligence tier (Observable, Indicator, or TTP). This is where unstructured forum posts become graph-structured intelligence.

**Agent 4: Tagging Engine**

Enriches structured intelligence with taxonomic tags. Applies MISP taxonomies (TLP marking, confidence level, source reliability), maps Attack Patterns to MITRE ATT&CK, adds sector-specific tags (payment type, fraud category, targeted geography), and validates consistency. The output is fully tagged, standards-compliant STIX 2.1 ready for distribution.

**Agent 5: Alert Generator**

Produces actionable alerts from tagged intelligence. Determines urgency and routing (which bank systems need this intelligence and how quickly), formats output for each consumer (MISP event, SIEM alert, fraud rules engine update, analyst notification), and manages deduplication against previously generated alerts.

### Pipeline diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Dark Web Intelligence Pipeline                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────┐    ┌────────────────┐    ┌────────────────┐               │
│  │   Crawling   │───▶│    Content     │───▶│     Data       │               │
│  │   Engine     │    │    Analyst     │    │   Structurer   │               │
│  │              │    │                │    │                │               │
│  │  Tor/I2P     │    │  Relevance     │    │  STIX 2.1      │               │
│  │  Access      │    │  Classification│    │  Object Gen    │               │
│  └──────────────┘    └────────────────┘    └───────┬────────┘               │
│                                                     │                        │
│                                                     ▼                        │
│                      ┌────────────────┐    ┌────────────────┐               │
│                      │    Alert       │◀───│    Tagging     │               │
│                      │   Generator   │    │    Engine      │               │
│                      │                │    │                │               │
│                      │  Routing &     │    │  MISP/ATT&CK   │               │
│                      │  Formatting   │    │  Taxonomies    │               │
│                      └───────┬────────┘    └────────────────┘               │
│                              │                                               │
│                              ▼                                               │
│                    ┌──────────────────┐                                      │
│                    │  Output Targets  │                                      │
│                    │  • MISP Instance │                                      │
│                    │  • SIEM / SOAR   │                                      │
│                    │  • Fraud Engine  │                                      │
│                    │  • FS-ISAC Share │                                      │
│                    └──────────────────┘                                      │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### AWS services

| AWS Service | Role in pipeline | Relevant feature |
|---|---|---|
| Amazon Bedrock | Agent reasoning and content analysis | Claude model family for multi-step classification and STIX generation |
| Amazon Bedrock Agents | Orchestration of multi-agent workflow | Agent-to-agent communication, tool use, memory |
| Amazon S3 | Raw content storage and STIX bundle persistence | Lifecycle policies for content retention compliance |
| Amazon DynamoDB | Pipeline state management and deduplication | TTL for automatic expiry of processed items |
| AWS Lambda | Event-driven agent invocation and transformation | Concurrency controls for rate-limited source access |
| Amazon EventBridge | Pipeline scheduling and inter-agent event routing | Cron-based crawl scheduling, event pattern matching |
| AWS Secrets Manager | Credential storage for forum access and API keys | Automatic rotation for operational security |
| Amazon SQS | Buffering between pipeline stages | Dead letter queues for failed processing recovery |
| Amazon CloudWatch | Pipeline observability and alerting | Custom metrics for signal volume, classification accuracy |
| AWS Step Functions | End-to-end workflow orchestration | Error handling, retry logic, parallel execution |

---

## Dark web source classification

Not all dark web content is alike. The pipeline distinguishes between two fundamental source categories, and this distinction drives how each agent processes content.

### Source 1: Compromised data and artefacts

This category includes:
- Fullz listings (complete identity packages)
- Card dumps (BIN data, track data, CVVs)
- Credential lists (email/password combinations, session tokens)
- Account access credentials (online banking logins, crypto exchange accounts)
- Document scans (passports, driving licences, utility bills for KYC bypass)

**Characteristics:** Structured or semi-structured. High volume. Often posted in consistent formats (CSV dumps, standardised listing templates). Amenable to automated ingestion with pattern matching and entity extraction.

**Processing approach:** The Content Analyst applies template-based extraction. Forum posts selling Fullz follow recognisable patterns — price, quantity, geography, verification status, format. The Data Structurer maps extracted entities directly to STIX SCOs (email addresses, card numbers become SCO objects) and generates Indicator SDOs with detection patterns.

**Primary intelligence tier:** Observable and Indicator. A card number is an Observable. A card number combined with the forum post's context (date listed, seller reputation, claimed source of compromise) becomes an Indicator with a confidence score and temporal validity window.

### Source 2: Schemes and tradecraft

This category includes:
- Attack playbooks (step-by-step guides for specific fraud types)
- Automation scripts (credential stuffing tools, account creation bots)
- Bypass tutorials (MFA circumvention, liveness detection spoofing, KYC evasion)
- Social engineering templates (vishing scripts, phishing page source code)
- Operational security guides (money mule recruitment, cash-out procedures)

**Characteristics:** Unstructured natural language. Lower volume but higher intelligence value per item. Requires contextual understanding — a post titled "fresh method for UK banks Dec 2025" could describe anything from a SIM swap technique to a refund fraud playbook. Cannot be processed with template matching alone.

**Processing approach:** The Content Analyst uses the LLM's full reasoning capability to understand intent, extract methodology descriptions, and identify targeted institutions or control types. The Data Structurer generates Attack Pattern SDOs, maps to MITRE ATT&CK where applicable, and creates Threat Actor objects when attribution is possible.

**Primary intelligence tier:** TTP. A tutorial describing how to bypass a specific bank's document verification system is a TTP — it describes adversary methodology at a level of abstraction that informs strategic defence, not real-time blocking.

### Source mapping summary

```
Source 1 (Compromised Data)          Source 2 (Schemes/Tradecraft)
─────────────────────────           ──────────────────────────────
Structured / Semi-structured         Unstructured natural language
High volume, pattern-based           Lower volume, reasoning-required
Template extraction                  LLM contextual classification
        │                                       │
        ▼                                       ▼
┌───────────────────┐               ┌───────────────────┐
│  Observable Tier  │               │     TTP Tier      │
│  Indicator Tier   │               │  (Attack Pattern, │
│  (SCOs + basic    │               │   Campaign, Tool) │
│   Indicators)     │               │                   │
└───────────────────┘               └───────────────────┘
        │                                       │
        ▼                                       ▼
  Real-time systems                    Strategic systems
  (watchlists, blocking)               (model design, control updates)
```

This distinction matters operationally. Source 1 content can be processed at high throughput with relatively simple agent prompts. Source 2 content requires more reasoning tokens, longer context windows, and more expensive model invocations — but produces higher-value intelligence. The pipeline architecture accounts for this asymmetry in its resource allocation and scheduling.

---

## Prerequisites

To follow along with the implementation in Parts 2 and 3, you will need:

**Required:**
- An AWS account with administrator access (or scoped IAM permissions for the services listed in the architecture table)
Amazon Bedrock access with the Anthropic Claude model family enabled in your target region (specifically Claude Sonnet 4 for classification agents and Claude Opus 4 for the Data Structurer agent, which requires stronger reasoning)
- Python 3.11 or later
- AWS CDK CLI v2.x installed and bootstrapped in your target account/region
- Node.js 18+ (required by CDK)
- Docker (required for Lambda container builds)

**Optional but recommended:**
- A MISP instance (self-hosted or community) for bidirectional integration testing — the pipeline can export STIX bundles to MISP and ingest existing MISP events as deduplication context
- A STIX visualisation tool (OASIS STIX Visualiser or similar) for inspecting generated bundles during development
- Familiarity with STIX 2.1 object model (the OASIS specification is freely available)

**Cost considerations:**
The pipeline's primary cost driver is Bedrock model invocation. During development and testing with sample data, expect approximately $15–30 per day in Bedrock costs depending on volume. Production costs scale with the number of sources monitored and the volume of content processed. Part 3 includes a detailed cost model with optimisation strategies.

---

## What comes next

**Part 2** builds the first three agents — Crawling Engine, Content Analyst, and Data Structurer. The post includes complete code for each agent's prompt engineering, tool definitions, and orchestration logic. You will deploy a working pipeline that takes sample dark web content (provided as test fixtures — no actual dark web access required for development) and produces valid STIX 2.1 bundles.

**Part 3** completes the pipeline with the Tagging Engine and Alert Generator, covers deployment patterns for production use, and walks through five worked examples mapping real-world fraud patterns (DC-007, DC-008, CHAPS-026, PS-001, XC-007) from raw source material through to final STIX output and downstream system integration.

---

## Conclusion

In this post, I showed why dark web intelligence represents the most significant untapped signal source for banking fraud detection, and how an automated pipeline built on Amazon Bedrock can close the operationalisation gap that has historically made this intelligence inaccessible at scale.

The key takeaways:

1. Dark web signals provide 24-hour to 4-week lead time over traditional reactive fraud detection — but only if captured and structured at machine speed.
2. Five distinct signal types (Fullz, BIN dumps, MFA bypass tutorials, ATO kits, synthetic identity playbooks) each enable specific defensive actions when operationalised.
3. STIX 2.1 and MISP provide the standards foundation that makes pipeline output immediately consumable by any SOC tool or sharing community.
4. A three-tier intelligence model (Observable, Indicator, TTP) ensures the right intelligence reaches the right system at the right operational tempo.
5. A five-agent architecture on Amazon Bedrock handles the full lifecycle from crawling through alert generation, with clear separation of concerns at each stage.

The complete implementation, including CDK infrastructure, agent definitions, prompt templates, and test fixtures, is available on GitHub:

**[github.com/farishaddad/DarkWeb](https://github.com/farishaddad/DarkWeb)**

If you have questions about adapting this architecture to your institution's specific fraud detection stack, or if you have built similar pipelines and want to share lessons learned, leave a comment on this post.

---

*Faris Haddad is a Solutions Architect on the AWS Alliance Business Group (AABG) Centre of Excellence team, focused on financial services AI and fraud detection with strategic partners.*
