# Implementation Plan: Dark Web Fraud Agent

## Overview

This implementation plan builds the multi-agent dark web fraud intelligence system incrementally, starting with shared infrastructure and data models, then implementing each agent in pipeline order (Crawling Engine → Content Analyst → Data Structurer → Tagging Engine → Alert Generator), and finishing with the Step Functions orchestration layer that wires everything together. Property-based tests validate the 21 correctness properties defined in the design using `hypothesis`.

## Tasks

- [x] 1. Set up project structure, shared models, and testing framework
  - [x] 1.1 Create project directory structure and Python package layout
    - Create `src/dark_web_fraud_agent/` package with `__init__.py`
    - Create sub-packages: `agents/`, `models/`, `infrastructure/`, `config/`, `utils/`
    - Create `tests/` directory with `unit/`, `property/`, `integration/` sub-directories
    - Set up `pyproject.toml` with dependencies: `stix2`, `pymisp`, `hypothesis`, `pytest`, `moto`, `boto3`, `pydantic`
    - Set up `requirements.txt` and `requirements-dev.txt`
    - _Requirements: 8.1_

  - [x] 1.2 Implement shared data models and interfaces
    - Implement `AgentHealth` dataclass with all monitoring fields (status, throughput, error_rate, queue_depth, last_heartbeat, bedrock_token_count)
    - Implement `StepFunctionsPipelineState` dataclass
    - Implement `IntelligenceTier` enum (OBSERVABLE, INDICATOR, TTP)
    - Implement `TierLink` dataclass with source/target tier references
    - Implement base `AgentConfig` and `AgentBase` abstract class with `get_health()` method
    - _Requirements: 8.1, 8.5, 6.1_

  - [x] 1.3 Implement configuration management and validation
    - Implement `CrawlConfig` with Pydantic validation (sources list, ports, retries, S3 bucket, DynamoDB table, Secrets Manager prefix)
    - Implement `SourceDefinition` with validation (url, source_type, category, crawl_interval, requires_auth, secret_arn)
    - Implement `AnalystConfig` (bedrock_model_id, guardrail_id, knowledge_base_id, confidence_threshold)
    - Implement `StructurerConfig` (opensearch_endpoint, collection_name, misp_url, misp_secret_arn, embedding_model_id)
    - Implement `TaggingConfig` (knowledge_base_id, misp_url, taxonomy_s3_prefix, attack_stix_s3_key)
    - Implement `AlertConfig` (convergence_window, digest_period, severity_threshold, opensearch_endpoint, sns_topic_arn, dynamodb_table)
    - _Requirements: 1.6, 8.1_

  - [ ]* 1.4 Write property test for source configuration acceptance (Property 3)
    - **Property 3: Source configuration acceptance**
    - Generate random valid/invalid SourceDefinition lists using hypothesis strategies
    - Valid configs (all required fields present) must be accepted without error
    - Invalid configs (missing required fields) must raise validation error
    - **Validates: Requirements 1.6**

- [ ] 2. Implement Crawling Engine Agent
  - [x] 2.1 Implement CrawlResult model and S3 artifact storage
    - Implement `CrawlResult` dataclass (source_url, source_category, raw_content, crawl_timestamp, proxy_identity, response_status, content_hash, s3_artifact_key, s3_annotation_id)
    - Implement `store_artifact()` method: upload raw content to S3, create S3 Annotation with source metadata
    - Implement SHA-256 content hashing for deduplication
    - _Requirements: 1.3_

  - [ ]* 2.2 Write property test for content extraction metadata preservation (Property 1)
    - **Property 1: Content extraction preserves metadata**
    - Generate random CrawlResult instances with valid URL, timestamp, source_category
    - Assert metadata fields are never null/empty
    - Assert timestamp within 1 second of crawl time
    - Assert S3 Annotation mirrors source metadata fields
    - **Validates: Requirements 1.3**

  - [x] 2.3 Implement Tor proxy connection and circuit rotation
    - Implement `CrawlingEngine.__init__()` with config initialization
    - Implement `rotate_circuit()` using `stem` controller: new exit node, return new IP
    - Implement Tor SOCKS5 proxy connectivity via VPC NAT Gateway
    - Implement Secrets Manager credential retrieval for proxy auth
    - _Requirements: 1.1, 1.4, 1.5_

  - [-] 2.4 Implement crawl_source with retry logic and circuit breaker
    - Implement `crawl_source()`: connect via Tor, extract content, handle failures
    - Implement retry logic: rotate proxy on failure, retry up to max_retries (default 3)
    - Implement `CircuitBreakerState` with DynamoDB-backed state (consecutive_failures, state, recovery_timeout)
    - Implement reconnection logic: new circuit within 60 seconds on connectivity loss
    - _Requirements: 1.2, 1.4, 1.5_

  - [ ]* 2.5 Write property test for retry count bounded by configuration (Property 2)
    - **Property 2: Retry count bounded by configuration maximum**
    - Generate sequences of access failures with random max_retries config
    - Assert retry count never exceeds configured maximum
    - Assert each retry uses a different proxy identity
    - **Validates: Requirements 1.4**

  - [~] 2.6 Implement agent health reporting and DynamoDB state tracking
    - Implement `get_health()` returning AgentHealth with throughput, error_rate, queue_depth
    - Implement DynamoDB state writes for crawl tracking (last_crawl_timestamp, last_content_hash, next_crawl_due)
    - Implement `start()` and `stop()` lifecycle methods
    - _Requirements: 8.5, 1.2_

- [~] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement Content Analyst Agent
  - [x] 4.1 Implement ClassifiedContent and ExtractedEntity models
    - Implement `ClassifiedContent` dataclass (source_ref, is_fraud_relevant, confidence, requires_manual_review, severity_score, fraud_category, entities, raw_text_snippet, bedrock_guardrail_result)
    - Implement `ExtractedEntity` dataclass (entity_type, value, context, confidence)
    - Define entity_type enum: bank_name, bin_range, swift_code, btc_wallet, email, url, ip_address
    - _Requirements: 2.1, 2.2_

  - [x] 4.2 Implement fraud relevance classification with Bedrock Guardrails
    - Implement `classify_relevance()`: invoke Claude Opus 4.8 via Bedrock with content safety guardrails
    - Apply Bedrock Guardrails before processing (prompt injection, harmful content, sensitive data detection)
    - Return (is_fraud_relevant: bool, confidence: float) tuple
    - Set `requires_manual_review = True` when confidence < 0.7
    - _Requirements: 2.1, 2.5_

  - [ ]* 4.3 Write property test for classification output validity (Property 4)
    - **Property 4: Classification output validity**
    - Generate random raw text inputs
    - Assert output always contains valid boolean fraud-relevance and confidence in [0.0, 1.0]
    - Assert confidence < 0.7 implies requires_manual_review is True
    - **Validates: Requirements 2.1, 2.5**

  - [x] 4.4 Implement entity extraction and technique categorization
    - Implement `extract_entities()`: NER + LLM extraction for BINs, SWIFT codes, wallets, bank names, URLs, IPs, emails
    - Implement `categorize_technique()`: classify bypass techniques into exactly one of 5 categories
    - Extract affected institution identifiers and estimated record counts from Fullz/credential dumps
    - _Requirements: 2.2, 2.3, 2.4_

  - [ ]* 4.5 Write property test for entity extraction validity (Property 5)
    - **Property 5: Entity extraction produces valid typed results**
    - Generate random fraud-relevant text with entities
    - Assert all extracted entities have entity_type in defined set
    - Assert all entity values are non-empty strings
    - **Validates: Requirements 2.2**

  - [ ]* 4.6 Write property test for fraud technique categorization (Property 6)
    - **Property 6: Fraud technique categorization validity**
    - Generate random security bypass technique descriptions
    - Assert assigned category is exactly one of: MFA bypass, synthetic identity creation, phishing kit, card-not-present fraud, account takeover
    - **Validates: Requirements 2.3**

  - [x] 4.7 Implement severity scoring
    - Implement `assign_severity()`: calculate severity 1-10 based on threat immediacy and scale
    - Map severity based on: target institution count, technique sophistication, data freshness, volume of affected records
    - _Requirements: 2.6_

  - [ ]* 4.8 Write property test for severity score bounded (Property 7)
    - **Property 7: Severity score bounded**
    - Generate random ClassifiedContent instances
    - Assert severity_score is always an integer in [1, 10]
    - **Validates: Requirements 2.6**

- [ ] 5. Implement Data Structurer Agent - STIX 2.1
  - [x] 5.1 Implement STIX 2.1 object creation (SDOs, SCOs, SROs)
    - Implement `create_stix_sdo()`: create Threat Actor, Attack Pattern, Indicator, Malware objects from entities
    - Implement `create_stix_sco()`: create IPv4Address, URL, EmailAddress, DomainName, Artifact (BTC) objects
    - Implement `create_stix_relationship()`: link Threat Actors to Attack Patterns and Indicators
    - Implement `build_bundle()`: assemble STIX 2.1 Bundle from collected objects
    - Use `stix2` library for proper schema-validated object construction
    - _Requirements: 3.1, 3.2, 3.3_

  - [ ]* 5.2 Write property test for STIX Bundle schema validity (Property 8)
    - **Property 8: STIX Bundle schema validity**
    - Generate random combinations of SDOs, SROs, and SCOs using hypothesis strategies
    - Assert resulting Bundle passes stix2 library schema validation
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4**

  - [x] 5.3 Implement STIX serialization and deserialization
    - Implement `serialize_bundle()`: convert Bundle to JSON string conforming to STIX 2.1 spec
    - Implement `deserialize_bundle()`: reconstruct Bundle from JSON with all relationships intact
    - _Requirements: 3.5, 3.6_

  - [ ]* 5.4 Write property test for STIX serialization round-trip (Property 9)
    - **Property 9: STIX serialization round-trip**
    - Generate random valid STIX 2.1 Bundles
    - Assert serialize then deserialize produces equivalent Bundle (all objects, properties, relationships intact)
    - **Validates: Requirements 3.5, 3.6**

  - [x] 5.5 Implement intelligence tier classification
    - Implement `classify_tier()`: assign Observable, Indicator, or TTP based on content type
    - Observable: single atomic value (IP, URL, hash, wallet, email) — mark for blocking
    - Indicator: composite pattern with temporal/logical operators — mark for detection-rule-generation
    - TTP: adversarial behavior methodology — mark for strategic-logic
    - Maintain referential links between tiers using TierLink dataclass
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ]* 5.6 Write property test for tier classification completeness (Property 16)
    - **Property 16: Intelligence tier classification completeness**
    - Generate random data items
    - Assert each item classified into exactly one tier
    - Assert corresponding action marker is present
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4**

  - [ ]* 5.7 Write property test for tier referential link integrity (Property 17)
    - **Property 17: Tier referential link integrity**
    - Generate random intelligence stores with Observable → Indicator → TTP chains
    - Assert link chain is traversable with valid references at each step
    - **Validates: Requirements 6.5**

  - [~] 5.8 Implement OpenSearch Serverless vector indexing
    - Implement `index_to_opensearch()`: generate embeddings via Bedrock, index into VECTORSEARCH collection
    - Create index mapping with knn_vector field (dimension 1024, HNSW, cosine similarity)
    - Index STIX objects with metadata (stix_id, tier, severity, fraud_category, entities, tags)
    - _Requirements: 3.1, 6.5_

- [~] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement Data Structurer Agent - MISP Integration
  - [~] 7.1 Implement STIX-to-MISP conversion
    - Implement `stix_to_misp()`: convert STIX Bundle to MISP event with attributes and object references
    - Map STIX SCOs to MISP attribute types (ipv4-addr→ip-src, url→url, email-addr→email-src, domain-name→domain, artifact/btc→btc)
    - Assign organization context and distribution level based on sensitivity
    - _Requirements: 4.1, 4.2, 4.3_

  - [ ]* 7.2 Write property test for SCO-to-MISP attribute mapping (Property 11)
    - **Property 11: SCO-to-MISP attribute type mapping correctness**
    - Generate random STIX SCOs of supported types
    - Assert mapped MISP attribute type matches defined mapping
    - **Validates: Requirements 4.2**

  - [~] 7.3 Implement MISP-to-STIX export and round-trip
    - Implement `misp_to_stix()`: export MISP event back to STIX 2.1 Bundle
    - Implement `create_misp_event()`: create event via PyMISP REST API with validation error handling and retry
    - _Requirements: 4.4, 4.5_

  - [ ]* 7.4 Write property test for STIX-MISP round-trip (Property 10)
    - **Property 10: STIX-MISP conversion round-trip**
    - Generate random valid STIX Bundles
    - Convert to MISP event, then export back to STIX
    - Assert observable values and relationship structures are preserved (semantic equivalence)
    - **Validates: Requirements 4.1, 4.4**

- [ ] 8. Implement Tagging Engine Agent
  - [~] 8.1 Implement taxonomy loading and validation
    - Implement `load_taxonomy()`: parse JSON taxonomy definitions with namespace, predicates, entries
    - Implement custom banking fraud taxonomy schema (fraud:type, fraud:target predicates)
    - Load MITRE ATT&CK STIX data from S3 for technique matching
    - Validate taxonomy JSON structure on load; reject invalid with parse error
    - _Requirements: 5.6, 5.1_

  - [ ]* 8.2 Write property test for custom taxonomy loading (Property 15)
    - **Property 15: Custom taxonomy loading**
    - Generate random valid/invalid JSON taxonomy definitions
    - Assert valid definitions load successfully with predicates available for tagging
    - Assert invalid JSON rejected with parse error
    - **Validates: Requirements 5.6**

  - [~] 8.3 Implement severity-to-threat-level mapping and tag application
    - Implement `map_severity_to_threat_level()`: 1-3→low, 4-6→medium, 7-9→high, 10→critical
    - Implement `apply_attack_tags()`: match content to MITRE ATT&CK techniques
    - Implement `apply_fraud_tags()`: apply `fraud:type="<category>"` tags for banking keywords
    - _Requirements: 5.3, 5.1, 5.2_

  - [ ]* 8.4 Write property test for severity-to-threat-level mapping (Property 12)
    - **Property 12: Severity-to-threat-level mapping**
    - Generate random severity scores in [1, 10]
    - Assert correct threat-level: 1-3→low, 4-6→medium, 7-9→high, 10→critical
    - **Validates: Requirements 5.3**

  - [ ]* 8.5 Write property test for fraud keyword tagging format (Property 13)
    - **Property 13: Fraud keyword tagging format**
    - Generate random MISP events containing banking keywords (SWIFT, Fullz, BIN, bank names)
    - Assert at least one tag in format `fraud:type="<category>"` where category is valid taxonomy value
    - **Validates: Requirements 5.2**

  - [~] 8.6 Implement Galaxy cluster matching and unmatched content handling
    - Implement `match_galaxy_cluster()`: query AgentCore Knowledge Base (Agentic Retriever) for threat actor matching
    - Link events to corresponding MISP Galaxy clusters when actors match known profiles
    - Apply `requires-review` tag when event doesn't match any taxonomy predicate
    - Implement `tag()` orchestration method combining all tagging steps
    - _Requirements: 5.4, 5.5_

  - [ ]* 8.7 Write property test for unmatched content fallback tag (Property 14)
    - **Property 14: Unmatched content fallback tag**
    - Generate random MISP events with content not matching any taxonomy predicate
    - Assert `requires-review` tag is applied
    - **Validates: Requirements 5.5**

- [~] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Implement Alert Generator Agent
  - [x] 10.1 Implement FraudAlert, AlertProvenance, and DetectionRule models
    - Implement `FraudAlert` dataclass (alert_id, alert_type, severity, ttp_description, affected_institutions, recommended_detection_rules, related_intelligence, provenance, created_at, sns_message_id)
    - Implement `AlertProvenance` dataclass (original_source_url, crawl_timestamp, s3_artifact_key, processing_chain)
    - Implement `DetectionRule` dataclass (rule_type: yara/sigma/custom, rule_content, confidence)
    - _Requirements: 7.1, 7.2, 7.4_

  - [ ]* 10.2 Write property test for alert structure completeness (Property 18)
    - **Property 18: Alert structure completeness**
    - Generate random TTP alerts
    - Assert all required fields present: TTP description, affected institutions list, severity, at least one detection rule
    - Assert conforms to documented API schema
    - **Validates: Requirements 7.1, 7.2**

  - [ ]* 10.3 Write property test for alert provenance traceability (Property 20)
    - **Property 20: Alert provenance traceability**
    - Generate random alerts with provenance objects
    - Assert non-empty original_source_url, valid crawl_timestamp preceding alert creation, valid S3 artifact key
    - **Validates: Requirements 7.4**

  - [~] 10.4 Implement campaign convergence detection
    - Implement `check_campaign_convergence()`: query OpenSearch vector similarity for related items
    - Track convergence in DynamoDB with TTL-based time window expiry
    - Generate consolidated campaign alert when 3+ related items converge around common TTP
    - _Requirements: 7.3_

  - [ ]* 10.5 Write property test for campaign alert consolidation (Property 19)
    - **Property 19: Campaign alert consolidation**
    - Generate sets of 3+ related Observables/Indicators referencing common TTP within convergence window
    - Assert consolidated campaign alert produced linking all related intelligence item IDs
    - **Validates: Requirements 7.3**

  - [~] 10.6 Implement alert publishing and summary digest generation
    - Implement `publish_alert()`: publish to SNS topic, return message ID
    - Implement `format_for_api()`: format alert for downstream fraud detection system integration
    - Implement `generate_summary_digest()`: produce periodic digest of low/medium findings when no high-severity intel found
    - Implement `process()` orchestration method combining correlation, generation, and publishing
    - _Requirements: 7.2, 7.5_

- [ ] 11. Implement Step Functions Pipeline Orchestration
  - [~] 11.1 Implement PipelineOrchestrator and inter-agent message passing
    - Implement `PipelineOrchestrator` class with Step Functions state machine integration
    - Implement `start_execution()`: invoke state machine with input payload, return execution ARN
    - Implement `get_execution_status()`: query execution history and current state
    - Implement `signal_human_approval()`: handle task token callbacks for manual review gates
    - Define inter-agent message interface with correlation_id preservation
    - _Requirements: 8.2, 8.4_

  - [ ]* 11.2 Write property test for pipeline message integrity (Property 21)
    - **Property 21: Step Functions pipeline message integrity**
    - Generate random agent output payloads with correlation_id
    - Assert subsequent agent step receives equivalent payload with identical correlation_id
    - Assert all fields preserved through orchestration layer
    - **Validates: Requirements 8.2**

  - [~] 11.3 Implement agent fault isolation and health monitoring
    - Implement per-agent error handling: isolate failures, continue processing with remaining agents
    - Implement Step Functions retry configuration (exponential backoff per state)
    - Implement dead-letter queue routing for failed items (SQS DLQ)
    - Implement health aggregation: collect per-agent AgentHealth, expose pipeline-level status
    - _Requirements: 8.3, 8.5_

  - [~] 11.4 Implement EventBridge scheduling and initialization
    - Implement EventBridge rule for cron-based crawl cycle triggering
    - Implement agent initialization in dependency order (Crawling Engine first, then downstream)
    - Verify inter-agent connectivity before beginning crawl operations
    - Implement Step Functions Map state for parallel crawl result processing (MaxConcurrency: 10)
    - _Requirements: 8.4, 1.2_

- [ ] 12. Implement AWS Infrastructure (CDK)
  - [~] 12.1 Create CDK stack for core infrastructure
    - Define VPC with isolated subnet for Tor proxy (NAT Gateway → Tor SOCKS5)
    - Define S3 bucket with Annotations enabled for raw artifact storage
    - Define DynamoDB tables (Agent State, Crawl State, Campaign Convergence) with TTL
    - Define Secrets Manager secrets for Tor proxy credentials and MISP API keys
    - Define IAM roles with least-privilege policies per agent
    - _Requirements: 1.1, 8.1_

  - [~] 12.2 Create CDK stack for intelligence infrastructure
    - Define OpenSearch Serverless VECTORSEARCH collection with GPU acceleration
    - Define OpenSearch index template with knn_vector mapping (dimension 1024, HNSW, cosine)
    - Define AgentCore Managed Knowledge Base with Smart Parsing
    - Define Bedrock Guardrails configuration (prompt injection, harmful content, sensitive data)
    - _Requirements: 3.1, 5.4_

  - [~] 12.3 Create CDK stack for pipeline orchestration
    - Define Step Functions state machine with agent invocation steps
    - Define EventBridge rule for scheduled crawl triggers
    - Define SNS topic and SQS queues for alert distribution
    - Define SQS dead-letter queues for failed processing items
    - Define CloudWatch dashboards and alarms (error rate > 5%, failures > 3/hour, latency > 500ms)
    - _Requirements: 8.1, 8.2, 7.2_

- [ ] 13. Wire all components together and validate end-to-end flow
  - [~] 13.1 Implement full pipeline integration
    - Wire CrawlingEngine output → ContentAnalyst input
    - Wire ContentAnalyst output → DataStructurer input
    - Wire DataStructurer output → TaggingEngine input
    - Wire TaggingEngine output → AlertGenerator input
    - Implement correlation_id propagation through entire pipeline
    - Validate Step Functions state machine definition against implemented agents
    - _Requirements: 8.1, 8.2_

  - [ ]* 13.2 Write integration tests for end-to-end pipeline
    - Test full pipeline execution with mocked Tor and Bedrock calls
    - Test fault isolation: single agent failure doesn't block pipeline
    - Test campaign convergence detection across multiple crawl cycles
    - Test SNS alert delivery to downstream consumers
    - _Requirements: 8.1, 8.2, 8.3, 7.3_

- [~] 14. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation between major components
- Property tests validate the 21 universal correctness properties from the design document
- Unit tests validate specific edge cases and error handling paths
- The implementation uses Python exclusively: `stix2`, `pymisp`, `hypothesis`, `pytest`, `boto3`, `moto`, `stem`
- AWS infrastructure is defined via CDK (Python) in task group 12
- Bedrock calls are mocked in unit/property tests; real calls in integration tests with cost controls
- OpenSearch Serverless VECTORSEARCH collection scales from 0 automatically
- Step Functions provides native retry, catch, and parallel processing without custom orchestration code

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["1.4", "2.1", "4.1", "10.1"] },
    { "id": 3, "tasks": ["2.2", "2.3", "4.2", "5.1"] },
    { "id": 4, "tasks": ["2.4", "2.5", "4.3", "4.4", "5.2", "5.3"] },
    { "id": 5, "tasks": ["2.6", "4.5", "4.6", "4.7", "5.4", "5.5"] },
    { "id": 6, "tasks": ["4.8", "5.6", "5.7", "5.8", "7.1"] },
    { "id": 7, "tasks": ["7.2", "7.3", "8.1"] },
    { "id": 8, "tasks": ["7.4", "8.2", "8.3"] },
    { "id": 9, "tasks": ["8.4", "8.5", "8.6"] },
    { "id": 10, "tasks": ["8.7", "10.2", "10.3", "10.4"] },
    { "id": 11, "tasks": ["10.5", "10.6", "11.1"] },
    { "id": 12, "tasks": ["11.2", "11.3", "11.4"] },
    { "id": 13, "tasks": ["12.1", "12.2", "12.3"] },
    { "id": 14, "tasks": ["13.1"] },
    { "id": 15, "tasks": ["13.2"] }
  ]
}
```
