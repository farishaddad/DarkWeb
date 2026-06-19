# Requirements Document

## Introduction

This document defines the requirements for an agentic dark web research agent designed to crawl the dark web and discover banking fraud-relevant intelligence. The system autonomously navigates Tor-based forums and marketplaces, applies AI-driven analysis to unstructured content, structures findings using industry standards (STIX 2.1 and MISP), and generates actionable alerts for integration into a fraud detection pipeline.

## Glossary

- **Crawling_Engine**: The autonomous component responsible for navigating hidden networks (Tor/I2P) and collecting raw content from dark web sources.
- **Content_Analyst**: The AI-driven component that applies natural language processing to classify and extract fraud-relevant intelligence from raw text.
- **Data_Structurer**: The component responsible for parsing raw harvested data into standardized formats (STIX 2.1 objects and MISP events).
- **Tagging_Engine**: The automated classification component that applies machine tags, taxonomies, and galaxy clusters to structured events.
- **Alert_Generator**: The component that synthesizes structured intelligence into actionable reports and alerts for downstream fraud detection systems.
- **Observable**: A simple, atomic cyber-relevant data point such as an IP address, BTC wallet address, URL, or email alias (STIX Cyber-observable Object).
- **Indicator**: A pattern of activity that signals a potential attack, such as a specific sequence of API calls used in a bypass tool.
- **TTP**: Tactics, Techniques, and Procedures describing adversarial behavior at a strategic level (e.g., phishing kit deployment methods, MFA bypass guides).
- **STIX_2.1**: Structured Threat Information Expression version 2.1, a graph-based standard for modelling and linking threat information.
- **MISP**: Malware Information Sharing Platform, an open-source platform for ingesting, correlating, and sharing threat indicators.
- **Fullz**: A complete set of stolen personal and financial data for a single identity, typically sold on dark web marketplaces.
- **BIN**: Bank Identification Number, the first six digits of a payment card number identifying the issuing institution.
- **SWIFT_Code**: A standardized code used to identify banks and financial institutions globally in wire transfers.

## Requirements

### Requirement 1: Dark Web Crawling

**User Story:** As a fraud analyst, I want the system to autonomously crawl dark web sources, so that I can discover banking fraud intelligence without manual investigation.

#### Acceptance Criteria

1. WHEN the Crawling_Engine is started, THE Crawling_Engine SHALL connect to the Tor network using rotating proxy configurations to avoid detection.
2. WHILE the Crawling_Engine is active, THE Crawling_Engine SHALL monitor configured dark web sources including onion sites, forums, and marketplaces on a continuous 24/7 basis.
3. WHEN the Crawling_Engine discovers a new page on a configured source, THE Crawling_Engine SHALL extract the raw textual content and store it with source metadata including URL, timestamp, and source category.
4. WHEN the Crawling_Engine encounters access restrictions or CAPTCHAs, THE Crawling_Engine SHALL rotate its proxy identity and retry the request up to three times before logging a failure.
5. IF the Crawling_Engine loses connectivity to the Tor network, THEN THE Crawling_Engine SHALL attempt reconnection with a new circuit within 60 seconds and log the connectivity disruption.
6. WHEN configuring crawl targets, THE Crawling_Engine SHALL accept a list of source definitions including Telegram channels, dark web forums, and illicit marketplaces.

### Requirement 2: AI-Driven Content Analysis

**User Story:** As a fraud analyst, I want the system to automatically analyze crawled content for banking fraud relevance, so that I can focus on actionable intelligence rather than raw data.

#### Acceptance Criteria

1. WHEN the Content_Analyst receives raw text from the Crawling_Engine, THE Content_Analyst SHALL classify the content as fraud-relevant or irrelevant using natural language processing.
2. WHEN the Content_Analyst identifies fraud-relevant content, THE Content_Analyst SHALL extract structured entities including bank names, BIN ranges, SWIFT codes, cryptocurrency wallet addresses, and fraud technique descriptions.
3. WHEN the Content_Analyst encounters a discussion about bypassing bank security controls, THE Content_Analyst SHALL categorize the technique (MFA bypass, synthetic identity creation, phishing kit, card-not-present fraud, or account takeover).
4. WHEN the Content_Analyst processes content referencing stolen credential dumps or Fullz listings, THE Content_Analyst SHALL extract affected institution identifiers and estimated record counts.
5. IF the Content_Analyst cannot determine the fraud relevance of content with confidence above 0.7, THEN THE Content_Analyst SHALL flag the content for manual review and assign a preliminary category.
6. WHEN the Content_Analyst processes content, THE Content_Analyst SHALL assign a severity score between 1 and 10 based on the immediacy and scale of the identified threat.

### Requirement 3: Data Structuring with STIX 2.1

**User Story:** As a threat intelligence engineer, I want harvested data structured according to STIX 2.1 standards, so that intelligence can be shared and correlated with external threat feeds.

#### Acceptance Criteria

1. WHEN the Data_Structurer receives classified entities from the Content_Analyst, THE Data_Structurer SHALL create valid STIX 2.1 Domain Objects (SDOs) with correct type assignments (Threat Actor, Attack Pattern, Indicator, or Malware).
2. WHEN the Data_Structurer creates STIX objects, THE Data_Structurer SHALL establish relationship objects linking Threat Actors to their Attack Patterns and Indicators.
3. WHEN the Data_Structurer processes observables such as IP addresses, BTC wallets, and URLs, THE Data_Structurer SHALL represent them as STIX Cyber-observable Objects (SCOs) with valid property values.
4. THE Data_Structurer SHALL produce STIX 2.1 Bundles that pass schema validation against the official STIX 2.1 specification.
5. WHEN the Data_Structurer serializes STIX objects to storage, THE Data_Structurer SHALL encode them as JSON conforming to the STIX 2.1 JSON serialization format.
6. WHEN the Data_Structurer deserializes STIX objects from storage, THE Data_Structurer SHALL reconstruct equivalent in-memory representations with all relationships intact.

### Requirement 4: MISP Integration and Event Management

**User Story:** As a threat intelligence engineer, I want harvested data ingested into MISP as structured events, so that I can correlate dark web intelligence with other threat feeds.

#### Acceptance Criteria

1. WHEN the Data_Structurer produces a STIX Bundle, THE Data_Structurer SHALL convert it into a MISP event with appropriate attributes and object references.
2. WHEN creating MISP events, THE Data_Structurer SHALL map STIX SCOs to MISP attribute types (ip-src, url, btc, email-src) preserving semantic meaning.
3. WHEN a MISP event is created, THE Data_Structurer SHALL assign it to the correct organization context and set distribution level based on sensitivity classification.
4. THE Data_Structurer SHALL export MISP events as STIX 2.1 Bundles for downstream consumers that require STIX-native input.
5. IF a MISP event creation fails due to validation errors, THEN THE Data_Structurer SHALL log the validation failure with the offending attributes and retry after correction.

### Requirement 5: Automated Tagging and Classification

**User Story:** As a fraud analyst, I want dark web intelligence automatically tagged and classified, so that I can filter and prioritize intelligence by fraud type, severity, and affected institution.

#### Acceptance Criteria

1. WHEN a MISP event is created, THE Tagging_Engine SHALL apply machine tags from enabled taxonomies including MITRE ATT&CK and a custom banking fraud taxonomy.
2. WHEN the Tagging_Engine processes an event containing banking-specific keywords (SWIFT, Fullz, BIN, or specific bank names), THE Tagging_Engine SHALL apply corresponding fraud-category tags using the format fraud:type="category".
3. WHEN the Tagging_Engine processes an event, THE Tagging_Engine SHALL assign a threat-level tag based on the Content_Analyst severity score mapping (1-3: low, 4-6: medium, 7-9: high, 10: critical).
4. WHEN the Tagging_Engine identifies content matching a known threat actor profile, THE Tagging_Engine SHALL link the event to the corresponding MISP Galaxy cluster.
5. WHEN the Tagging_Engine encounters an event that does not match any configured taxonomy predicate, THE Tagging_Engine SHALL apply a "requires-review" tag and log the unmatched content for taxonomy expansion.
6. THE Tagging_Engine SHALL support custom taxonomy definitions provided as JSON configuration files with namespace, predicate, and value fields.

### Requirement 6: Tiered Intelligence Classification

**User Story:** As a fraud detection engineer, I want intelligence classified into functional tiers (Observables, Indicators, TTPs), so that I can apply the appropriate response action for each tier.

#### Acceptance Criteria

1. WHEN the Data_Structurer processes raw data, THE Data_Structurer SHALL classify each item into one of three tiers: Observable, Indicator, or TTP.
2. WHEN an item is classified as an Observable, THE Data_Structurer SHALL mark it for immediate blocking and blacklisting use cases.
3. WHEN an item is classified as an Indicator, THE Data_Structurer SHALL mark it for real-time detection rule generation.
4. WHEN an item is classified as a TTP, THE Data_Structurer SHALL mark it for long-term strategic detection logic development.
5. THE Data_Structurer SHALL maintain referential links between items across tiers so that an Observable can trace back to its parent Indicator and the TTP it supports.

### Requirement 7: Actionable Reporting and Alerting

**User Story:** As a fraud operations manager, I want the system to generate structured alerts about emerging attack vectors, so that my team can proactively update detection rules.

#### Acceptance Criteria

1. WHEN the Alert_Generator identifies a new or escalating TTP, THE Alert_Generator SHALL produce a structured alert containing the TTP description, affected institutions, severity, and recommended detection rules.
2. WHEN the Alert_Generator produces an alert, THE Alert_Generator SHALL format the alert for integration with downstream fraud detection systems via a documented API.
3. WHEN multiple related Observables and Indicators converge around a common TTP within a configurable time window, THE Alert_Generator SHALL generate a consolidated campaign alert linking all related intelligence items.
4. WHEN the Alert_Generator produces an alert, THE Alert_Generator SHALL include provenance information tracing back to the original dark web source and crawl timestamp.
5. IF no new high-severity intelligence is discovered within a configurable reporting period, THEN THE Alert_Generator SHALL produce a summary digest of low-and-medium severity findings for the period.

### Requirement 8: Agent Orchestration

**User Story:** As a system architect, I want the system implemented as a multi-agent architecture, so that each agent can be developed, scaled, and maintained independently.

#### Acceptance Criteria

1. THE system SHALL implement a multi-agent architecture where the Crawling_Engine, Content_Analyst, Data_Structurer, Tagging_Engine, and Alert_Generator operate as independent agents.
2. WHEN one agent produces output, THE system SHALL pass that output to the next agent in the pipeline via a defined message interface.
3. IF an individual agent fails, THEN THE system SHALL isolate the failure and continue processing with remaining agents while logging the failure for recovery.
4. WHEN the system starts, THE system SHALL initialize all agents in the correct dependency order and verify inter-agent connectivity before beginning crawl operations.
5. WHILE the system is operational, THE system SHALL provide health status for each agent including processing throughput, error rate, and queue depth.
