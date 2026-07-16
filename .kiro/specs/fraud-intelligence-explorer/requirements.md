# Requirements Document

## Introduction

The Fraud Intelligence Explorer is a React single-page application that provides a demo-quality interface for exploring intelligence produced by the Dark Web Fraud Agent pipeline. It visualizes fraud alerts, intelligence classifications, entity relationships, and full provenance chains — enabling stakeholders to understand what the pipeline has discovered, how items are categorized, and the evidence chain from raw dark web source to actionable alert.

The application supports two operating modes: a live mode backed by API Gateway + Lambda querying DynamoDB/OpenSearch, and a mock mode using bundled static JSON for offline demonstrations.

## Glossary

- **Explorer**: The Fraud Intelligence Explorer React single-page application
- **Dashboard**: The top-level overview view showing aggregate intelligence metrics
- **AlertList**: The filterable, sortable list view of all intelligence alerts
- **AlertDetail**: The full detail view for a single alert including provenance chain
- **RelationshipGraph**: The force-directed graph visualization of entity connections
- **SignalSources**: The view displaying raw signal sources that contributed to an insight
- **DataProvider**: The adapter interface that abstracts data fetching from either mock or live backends
- **MockProvider**: The DataProvider implementation that returns data from bundled static JSON
- **LiveProvider**: The DataProvider implementation that fetches data from API Gateway endpoints
- **ProvenanceChain**: The ordered sequence of processing steps an alert passed through in the pipeline
- **AlertSummary**: A compact representation of an alert used in list views
- **AlertDetail**: The full representation of an alert including provenance, tags, and detection rules
- **FraudCategory**: One of the ten defined fraud classification types (mfa_bypass, synthetic_identity, phishing_kit, cnp_fraud, account_takeover, new_account_fraud, recurring_billing_fraud, money_mule, investment_fraud, social_engineering)
- **Severity**: One of the four alert severity levels (low, medium, high, critical)
- **IntelligenceTier**: One of the three intelligence classification levels (observable, indicator, ttp)
- **GraphNode**: A node in the relationship graph representing an alert, institution, TTP, entity, or campaign
- **GraphEdge**: A directed edge in the relationship graph connecting two GraphNodes
- **MachineTag**: A structured tag in namespace:predicate=value format applied by the TaggingEngine
- **GalaxyMatch**: A match against the MISP galaxy cluster taxonomy

## Requirements

### Requirement 1: Dashboard Summary Display

**User Story:** As a fraud analyst, I want to see an aggregate overview of all intelligence on a dashboard, so that I can quickly assess the current threat landscape.

#### Acceptance Criteria

1. WHEN a user navigates to the dashboard, THE Explorer SHALL display the total number of alerts, the number of active campaigns, and the number of active sources as KPI tiles.
2. WHEN a user navigates to the dashboard, THE Explorer SHALL render a severity donut chart showing the distribution of alerts across the four Severity levels.
3. WHEN a user navigates to the dashboard, THE Explorer SHALL render a category bar chart showing the distribution of alerts across all FraudCategory values.
4. WHEN a user navigates to the dashboard, THE Explorer SHALL render a 30-day activity timeline showing alert counts per day.
5. WHEN a user navigates to the dashboard, THE Explorer SHALL display the five most recent alerts as summary cards.
6. THE Explorer SHALL compute the sum of all severity distribution values equal to the total alert count.

### Requirement 2: Alert List Filtering and Sorting

**User Story:** As a fraud analyst, I want to filter and sort intelligence alerts by category, severity, tier, time range, and keyword, so that I can find specific threats relevant to my investigation.

#### Acceptance Criteria

1. WHEN a user selects one or more FraudCategory values in the filter sidebar, THE AlertList SHALL display only alerts matching at least one of the selected categories.
2. WHEN a user selects one or more Severity values in the filter sidebar, THE AlertList SHALL display only alerts matching at least one of the selected severities.
3. WHEN a user selects one or more IntelligenceTier values in the filter sidebar, THE AlertList SHALL display only alerts matching at least one of the selected tiers.
4. WHEN a user specifies a time range, THE AlertList SHALL display only alerts with a creation timestamp within the specified range (inclusive).
5. WHEN a user enters search text, THE AlertList SHALL display only alerts whose TTP description or affected institution names contain the search text (case-insensitive).
6. WHEN multiple filter criteria are active simultaneously, THE AlertList SHALL display only alerts satisfying ALL active criteria (logical AND).
7. WHEN no filter criteria are active, THE AlertList SHALL display all alerts.
8. WHEN a user selects a sort field and order, THE AlertList SHALL order results by the selected field in the specified direction.
9. THE AlertList SHALL paginate results with a configurable page size between 10 and 100 alerts per page.
10. WHEN paginating results, THE AlertList SHALL ensure no alert appears on more than one page and no alert is omitted from all pages.

### Requirement 3: Alert Detail and Provenance Display

**User Story:** As a fraud analyst, I want to view full details of an alert including its provenance chain, so that I can understand the complete evidence trail from raw source to actionable intelligence.

#### Acceptance Criteria

1. WHEN a user clicks an alert card in the AlertList, THE Explorer SHALL navigate to the AlertDetail view for that alert.
2. WHEN the AlertDetail view loads, THE Explorer SHALL display the alert severity, TTP description, affected institutions, creation timestamp, and alert type.
3. WHEN the AlertDetail view loads, THE Explorer SHALL render the ProvenanceChain as a vertical stepper showing each processing step with agent name, timestamp, and summary.
4. WHEN the AlertDetail view loads, THE Explorer SHALL display detection rules with syntax-highlighted code blocks.
5. WHEN the AlertDetail view loads, THE Explorer SHALL display MachineTag values as colored badges grouped by namespace.
6. WHEN the alert has a GalaxyMatch, THE AlertDetail SHALL display the galaxy cluster information with a link to the MITRE reference.
7. IF a user navigates to an alert ID that does not exist, THEN THE Explorer SHALL display an "Alert not found" message with a link back to the AlertList.

### Requirement 4: Relationship Graph Visualization

**User Story:** As a fraud analyst, I want to see a visual graph of relationships between alerts, institutions, TTPs, and campaigns, so that I can identify patterns and connections across threats.

#### Acceptance Criteria

1. WHEN the RelationshipGraph view loads, THE Explorer SHALL render a force-directed graph using d3-force with nodes representing alerts, institutions, TTPs, entities, and campaigns.
2. THE Explorer SHALL color-code GraphNodes by their type (alert, institution, ttp, entity, campaign).
3. THE Explorer SHALL size GraphNodes proportionally to their connection count.
4. WHEN a user hovers over a GraphEdge, THE Explorer SHALL display the relationship label.
5. THE Explorer SHALL support zoom and pan navigation on the graph.
6. WHEN a user selects a GraphNode, THE Explorer SHALL highlight that node and all its directly connected edges and nodes.
7. IF the graph exceeds 100 nodes, THEN THE Explorer SHALL prune to the top 100 most-connected nodes and display a "Showing top 100 connections" indicator.
8. THE Explorer SHALL ensure every GraphEdge references a valid source GraphNode and a valid target GraphNode present in the rendered graph.

### Requirement 5: Signal Sources Display

**User Story:** As a fraud analyst, I want to see the raw signal sources that contributed to an alert, so that I can evaluate source reliability and confidence.

#### Acceptance Criteria

1. WHEN the SignalSources view loads for an alert, THE Explorer SHALL display each signal source as an expandable card showing source type, crawl timestamp, and confidence level.
2. THE Explorer SHALL render confidence levels as a color-coded progress bar with values in the range 0.0 to 1.0.
3. WHEN a user expands a signal source card, THE Explorer SHALL display extracted entities with their type, value, and confidence.
4. THE Explorer SHALL display a guardrail status badge (PASSED, FILTERED, or FLAGGED) for each signal source.
5. THE Explorer SHALL redact dark web source URLs to show only the domain portion, not the full path.

### Requirement 6: Data Provider Adapter Pattern

**User Story:** As a developer, I want the application to support both mock and live data providers interchangeably, so that the app works for offline demos and connected environments.

#### Acceptance Criteria

1. THE DataProvider interface SHALL expose methods for fetching dashboard summary, alert list, alert detail, relationships, and signal sources.
2. WHEN the Explorer is configured with a MockProvider, THE Explorer SHALL return data from the bundled static JSON dataset without making network requests.
3. WHEN the Explorer is configured with a LiveProvider, THE Explorer SHALL fetch data from the configured API Gateway endpoint.
4. THE MockProvider SHALL apply filter and pagination logic to the mock dataset identically to how the LiveProvider returns filtered results.
5. THE Explorer SHALL indicate the active data source (mock or live) in the API response metadata.

### Requirement 7: Error Handling and Resilience

**User Story:** As a user, I want the application to handle errors gracefully, so that I can continue using the application even when issues occur.

#### Acceptance Criteria

1. IF the LiveProvider receives a 5xx response or network timeout, THEN THE Explorer SHALL display cached data with a "Data may be stale" banner and retry with exponential backoff (1s, 2s, 4s, max 30s).
2. IF the mock JSON dataset is malformed or missing required fields, THEN THE Explorer SHALL display an error boundary with a "Demo data unavailable" message and fall back to minimal hardcoded sample data.
3. IF a data fetch is in progress, THEN THE Explorer SHALL display a loading indicator in the affected view area.
4. THE Explorer SHALL wrap all API responses in a typed ApiResponse envelope containing data, metadata (requestId, timestamp, dataSource), and an optional error object.

### Requirement 8: Dashboard Aggregation Computation

**User Story:** As a fraud analyst, I want dashboard metrics to be accurately computed from the underlying alert data, so that I can trust the displayed statistics.

#### Acceptance Criteria

1. WHEN computing the dashboard summary, THE Explorer SHALL count the total alerts equal to the length of the input alert array.
2. WHEN computing severity distribution, THE Explorer SHALL produce counts for each Severity level that sum to the total alert count.
3. WHEN computing the timeline, THE Explorer SHALL group alerts by calendar date and sort timeline points chronologically.
4. WHEN computing the campaign count, THE Explorer SHALL count only alerts with alertType equal to "campaign_alert".
5. WHEN computing active source count, THE Explorer SHALL count the number of distinct originalSourceUrl values across all alert provenance records.

### Requirement 9: Filter Algorithm Correctness

**User Story:** As a fraud analyst, I want filter logic to be precise and consistent, so that I see exactly the alerts matching my criteria without false positives or omissions.

#### Acceptance Criteria

1. THE Explorer SHALL apply category filters using set membership — an alert passes if its category is contained in the selected categories set.
2. THE Explorer SHALL apply severity filters using set membership — an alert passes if its severity is contained in the selected severities set.
3. THE Explorer SHALL apply time range filters as inclusive bounds — an alert passes if its createdAt is greater than or equal to the from value AND less than or equal to the to value.
4. THE Explorer SHALL apply text search as case-insensitive substring matching against TTP description and each affected institution name.
5. WHEN multiple filter types are active, THE Explorer SHALL combine them with logical AND — an alert must pass every active filter to appear in results.
6. THE Explorer SHALL produce a filter result that is always a subset of the input alert list (no fabricated results).
7. THE Explorer SHALL produce identical results when the same filters are applied to the same input data (deterministic output).

### Requirement 10: Graph Construction Correctness

**User Story:** As a fraud analyst, I want the relationship graph to accurately represent connections in the data, so that I can trust the visualized patterns.

#### Acceptance Criteria

1. THE Explorer SHALL create one GraphNode for each unique alert, institution, TTP, and campaign encountered in the input data.
2. THE Explorer SHALL deduplicate institution nodes by lowercase name — "HSBC" and "hsbc" produce a single node.
3. THE Explorer SHALL create TTP nodes only from tags with namespace "mitre-attack" and predicate "technique".
4. THE Explorer SHALL create campaign nodes only from alerts with alertType "campaign_alert" that have a non-null GalaxyMatch.
5. WHEN the node count exceeds the maxNodes threshold, THE Explorer SHALL retain the nodes with the highest connection counts.
6. WHEN pruning the graph, THE Explorer SHALL remove any edges whose source or target node was pruned.
7. THE Explorer SHALL produce a graph where every edge references a source node and target node that exist in the final node list.

### Requirement 11: Input Validation

**User Story:** As a developer, I want all inputs to be validated before processing, so that the application handles invalid data predictably.

#### Acceptance Criteria

1. THE Explorer SHALL validate that severity values are one of: "low", "medium", "high", "critical".
2. THE Explorer SHALL validate that confidence values are in the range [0.0, 1.0].
3. THE Explorer SHALL validate that createdAt values are valid ISO 8601 timestamps.
4. THE Explorer SHALL validate that alertId values are non-empty strings.
5. THE Explorer SHALL validate that page values are greater than or equal to 1 and pageSize values are in the range [10, 100].
6. IF any input fails validation, THEN THE Explorer SHALL reject the operation and return a descriptive error message indicating which field failed and why.
