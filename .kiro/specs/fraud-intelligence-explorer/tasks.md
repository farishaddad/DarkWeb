# Implementation Plan: Fraud Intelligence Explorer

## Overview

Build a React + TypeScript SPA using Vite, zustand, recharts, d3-force, and Tailwind CSS. The app provides a demo-quality interface for exploring intelligence from the Dark Web Fraud Agent pipeline. It supports two data modes: MockProvider (bundled JSON) and LiveProvider (API Gateway). Implementation follows an incremental approach — data layer first, then views, then integration.

## Tasks

- [x] 1. Project scaffolding and core type definitions
  - [x] 1.1 Initialize Vite + React + TypeScript project with Tailwind CSS
    - Run `npm create vite@latest explorer -- --template react-ts` in the DarkWeb project root
    - Install dependencies: zustand, recharts, d3-force, @types/d3-force, tailwindcss, postcss, autoprefixer, react-router-dom
    - Configure tailwind.config.ts, postcss.config.ts, and base styles
    - Set up path aliases in tsconfig.json (e.g., `@/` → `src/`)
    - Create directory structure: `src/types/`, `src/store/`, `src/data/`, `src/components/`, `src/views/`, `src/utils/`
    - _Requirements: 6.1_

  - [x] 1.2 Define core TypeScript type definitions
    - Create `src/types/models.ts` with all core types: Severity, AlertType, IntelligenceTier, FraudCategory, SourceType
    - Create `src/types/api.ts` with ApiResponse<T>, AlertSummary, AlertDetail, ProvenanceChain, ProcessingStep, DetectionRule, MachineTag, GalaxyMatch
    - Create `src/types/dashboard.ts` with DashboardSummary, TimelinePoint
    - Create `src/types/filters.ts` with AlertFilters, PaginatedAlerts
    - Create `src/types/graph.ts` with GraphNode, GraphEdge, RelationshipGraph
    - Create `src/types/signals.ts` with SignalSource, ExtractedEntity
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

  - [x] 1.3 Create DataProvider interface and provider factory
    - Create `src/data/provider.ts` with the DataProvider interface (fetchDashboardSummary, fetchAlerts, fetchAlertDetail, fetchRelationships, fetchSignalSources)
    - Create `src/data/providerFactory.ts` with factory function to instantiate MockProvider or LiveProvider based on config
    - Create `src/data/errors.ts` with ApiError class
    - _Requirements: 6.1, 6.5, 7.4_

  - [x] 1.4 Set up Vitest testing framework
    - Install vitest, @testing-library/react, @testing-library/jest-dom, jsdom, fast-check
    - Configure vitest.config.ts with jsdom environment
    - Create `src/test/setup.ts` with testing-library matchers
    - _Requirements: N/A (testing infrastructure)_

- [x] 2. Data transformation and validation logic
  - [x] 2.1 Implement input validation utilities
    - Create `src/utils/validation.ts` with validators for severity, confidence, ISO 8601 timestamps, alertId, page/pageSize
    - Each validator returns a descriptive error message on failure
    - Export `validateSeverity`, `validateConfidence`, `validateTimestamp`, `validateAlertId`, `validatePagination`
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_

  - [ ]* 2.2 Write property tests for input validation
    - **Property 21: Validation rejects invalid severity**
    - **Property 22: Validation rejects out-of-range confidence**
    - **Property 23: Validation rejects invalid pagination parameters**
    - **Validates: Requirements 11.1, 11.2, 11.5, 11.6**

  - [x] 2.3 Implement dashboard aggregation algorithm
    - Create `src/utils/dashboard.ts` with `computeDashboardSummary(alerts: AlertDetail[]): DashboardSummary`
    - Compute severity distribution, category breakdown, tier breakdown
    - Compute timeline data grouped by calendar date and sorted chronologically
    - Compute campaignCount (alertType === 'campaign_alert') and activeSourceCount (distinct originalSourceUrl)
    - Compute recentAlerts as the 5 most recent
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 1.6_

  - [ ]* 2.4 Write property tests for dashboard aggregation
    - **Property 1: Severity distribution sums to total**
    - **Property 18: Timeline chronological ordering**
    - **Property 19: Campaign count accuracy**
    - **Property 20: Active source count accuracy**
    - **Validates: Requirements 1.6, 8.1, 8.2, 8.3, 8.4, 8.5**

  - [x] 2.5 Implement filter algorithm
    - Create `src/utils/filters.ts` with `applyFilters(alerts: AlertSummary[], filters: AlertFilters): AlertSummary[]`
    - Implement category, severity, tier, timeRange, searchText filters
    - Implement sorting by field and direction
    - Filters combine with logical AND
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_

  - [ ]* 2.6 Write property tests for filter algorithm
    - **Property 2: Filter result is always a subset of input**
    - **Property 3: Filter determinism (idempotency)**
    - **Property 4: Category filter correctness**
    - **Property 5: Severity filter correctness**
    - **Property 6: Time range filter correctness**
    - **Property 7: Text search filter correctness**
    - **Property 8: Filter AND-composition**
    - **Property 9: Empty filter returns all**
    - **Property 10: Sort ordering correctness**
    - **Validates: Requirements 2.1, 2.2, 2.4, 2.5, 2.6, 2.7, 2.8, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7**

  - [x] 2.7 Implement pagination utility
    - Create `src/utils/pagination.ts` with `paginate(alerts: AlertSummary[], page: number, pageSize: number): PaginatedAlerts`
    - Validate page >= 1 and pageSize in [10, 100]
    - Compute totalCount, hasMore, and slice the array correctly
    - _Requirements: 2.9, 2.10, 11.5_

  - [ ]* 2.8 Write property test for pagination
    - **Property 11: Pagination disjointness and completeness**
    - **Validates: Requirements 2.9, 2.10**

  - [x] 2.9 Implement relationship graph construction algorithm
    - Create `src/utils/graph.ts` with `buildRelationshipGraph(alerts: AlertDetail[], maxNodes?: number): RelationshipGraph`
    - Build nodes for alerts, institutions (deduped by lowercase), TTPs (from mitre-attack tags), campaigns (from campaign_alert + GalaxyMatch)
    - Build edges with relationship types: affects, uses_ttp, part_of_campaign
    - Implement pruning to maxNodes by highest connection count
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

  - [ ]* 2.10 Write property tests for graph construction
    - **Property 12: Graph edge integrity**
    - **Property 13: Graph node deduplication**
    - **Property 14: TTP node source constraint**
    - **Property 15: Campaign node prerequisite**
    - **Property 16: Graph pruning retains most-connected nodes**
    - **Validates: Requirements 4.7, 4.8, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7**

  - [x] 2.11 Implement URL redaction and tag grouping utilities
    - Create `src/utils/redaction.ts` with `redactUrl(url: string): string` that returns only the domain portion
    - Create `src/utils/tags.ts` with `groupTagsByNamespace(tags: MachineTag[]): Record<string, MachineTag[]>`
    - _Requirements: 5.5, 3.5_

  - [ ]* 2.12 Write property tests for URL redaction and tag grouping
    - **Property 17: URL redaction removes path**
    - **Property 24: Tag grouping by namespace**
    - **Validates: Requirements 5.5, 3.5**

- [x] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Data providers and state management
  - [x] 4.1 Create mock dataset JSON
    - Create `src/data/mockDataset.json` with at least 20 alerts spanning all 10 FraudCategory values, all 4 Severity levels, and all 3 IntelligenceTier values
    - Include varied provenance chains, machine tags (with mitre-attack namespace), galaxy matches, detection rules
    - Include signal sources with different source types, confidence levels, and guardrail results
    - _Requirements: 6.2, 6.4_

  - [x] 4.2 Implement MockProvider
    - Create `src/data/mockProvider.ts` implementing DataProvider interface
    - `fetchDashboardSummary` computes summary from mock data using `computeDashboardSummary`
    - `fetchAlerts` applies filters and pagination to mock data
    - `fetchAlertDetail` returns full alert by ID or throws ApiError
    - `fetchRelationships` builds graph from alerts related to the given alertId
    - `fetchSignalSources` returns signal sources for a given alert
    - Wrap all responses in ApiResponse envelope with `dataSource: 'mock'`
    - _Requirements: 6.2, 6.4, 6.5, 7.4_

  - [ ]* 4.3 Write property test for API response envelope
    - **Property 25: API response envelope structure**
    - **Validates: Requirements 6.5, 7.4**

  - [x] 4.4 Implement LiveProvider
    - Create `src/data/liveProvider.ts` implementing DataProvider interface
    - Use fetch API to call configured API Gateway endpoint
    - Implement exponential backoff retry for 5xx errors and timeouts (1s, 2s, 4s, max 30s)
    - Enforce 30s request timeout
    - Wrap responses in ApiResponse envelope with `dataSource: 'live'`
    - _Requirements: 6.3, 7.1, 7.4_

  - [x] 4.5 Implement zustand store
    - Create `src/store/appStore.ts` with zustand store managing:
      - `dashboardSummary`, `alertList`, `currentAlert`, `relationships`, `signalSources`
      - `filters`, `pagination`
      - `loading` states per view
      - `error` state
      - `dataProvider` reference
    - Implement actions: `loadDashboard`, `loadAlerts`, `loadAlertDetail`, `loadRelationships`, `loadSignalSources`, `setFilters`, `setPage`
    - _Requirements: 7.3, 2.1–2.10_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. UI views — Dashboard and AlertList
  - [x] 6.1 Implement app shell with React Router
    - Create `src/App.tsx` with React Router setup for routes: `/`, `/alerts`, `/alerts/:alertId`, `/graph`, `/sources/:alertId`
    - Create `src/components/Layout.tsx` with navigation sidebar/header linking to Dashboard, Alerts, Graph
    - Create `src/components/LoadingSpinner.tsx` and `src/components/ErrorBoundary.tsx`
    - _Requirements: 3.1, 7.2, 7.3_

  - [x] 6.2 Implement DashboardView
    - Create `src/views/DashboardView.tsx`
    - Render KPI tiles (total alerts, campaigns, active sources) using TailwindCSS cards
    - Render severity donut chart using recharts PieChart
    - Render category bar chart using recharts BarChart
    - Render 30-day activity timeline using recharts LineChart
    - Render top-5 recent alert cards with severity badge and category label
    - Load data via store `loadDashboard` action on mount
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [x] 6.3 Implement AlertListView
    - Create `src/views/AlertListView.tsx`
    - Create `src/components/FilterSidebar.tsx` with multi-select facets for category, severity, tier, time range picker, and search input
    - Create `src/components/AlertCard.tsx` for rendering individual alert summaries
    - Create `src/components/Pagination.tsx` for page navigation
    - Implement sort toggling by field and direction
    - Navigate to AlertDetail on card click
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 3.1_

- [x] 7. UI views — AlertDetail and SignalSources
  - [x] 7.1 Implement AlertDetailView
    - Create `src/views/AlertDetailView.tsx`
    - Display alert severity badge, TTP description, affected institutions as chips, creation timestamp, alert type
    - Render ProvenanceChain as vertical stepper (CrawlingEngine → ContentAnalyst → DataStructurer → TaggingEngine → AlertGenerator)
    - Render detection rules with syntax-highlighted code blocks (using a simple `<pre>` with CSS or a lightweight highlighter)
    - Render MachineTag values as colored badges grouped by namespace using `groupTagsByNamespace`
    - Display GalaxyMatch info with MITRE reference link when present
    - Handle non-existent alertId with "Alert not found" message and link back to AlertList
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

  - [x] 7.2 Implement SignalSourcesView
    - Create `src/views/SignalSourcesView.tsx`
    - Create `src/components/SignalSourceCard.tsx` as expandable card showing source type, crawl timestamp, confidence
    - Render confidence as color-coded progress bar (0.0–1.0)
    - Display extracted entities on expand with type, value, and confidence
    - Show guardrail status badge (PASSED/FILTERED/FLAGGED) with appropriate colors
    - Redact source URLs using `redactUrl` utility
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [x] 8. UI views — Relationship Graph
  - [x] 8.1 Implement RelationshipGraphView
    - Create `src/views/RelationshipGraphView.tsx`
    - Implement force-directed graph using d3-force simulation (forceLink, forceCharge, forceCenter)
    - Color-code nodes by type (alert=red, institution=blue, ttp=orange, entity=green, campaign=purple)
    - Size nodes proportionally to their connection count
    - Show edge relationship labels on hover (tooltip)
    - Implement zoom/pan using d3-zoom or SVG viewBox manipulation
    - Implement node selection that highlights the selected node and its direct connections
    - Display "Showing top 100 connections" indicator when graph is pruned
    - Add entity type filter controls to narrow graph scope
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_

- [x] 9. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Integration, error handling, and final wiring
  - [x] 10.1 Wire data provider initialization and mode switching
    - Create `src/config.ts` with app configuration (dataMode: 'mock' | 'live', apiBaseUrl, apiKey)
    - Initialize the appropriate provider in `src/main.tsx` based on config
    - Add a visual indicator showing current data source mode (mock vs live) in the app header
    - _Requirements: 6.2, 6.3, 6.5_

  - [x] 10.2 Implement error boundaries and resilience UI
    - Implement React error boundary wrapping each view for graceful fallback
    - Add "Data may be stale" banner when live API retry is in progress
    - Implement minimal hardcoded fallback data (3 alerts) for mock data corruption scenario
    - Add loading indicators per view area during data fetches
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 10.3 Final integration and route wiring
    - Ensure all views are connected via React Router and navigation works end-to-end
    - Verify filter state persists when navigating between views
    - Verify AlertList → AlertDetail → SignalSources navigation flow
    - Verify graph view loads from relationship data
    - Add code splitting with React.lazy for each view component
    - _Requirements: 3.1, 4.1_

  - [ ]* 10.4 Write integration tests
    - Test dashboard loads and displays charts with mock data
    - Test filter application reduces visible alerts
    - Test alert detail shows provenance chain
    - Test graph visualization renders nodes and edges
    - Test navigation between views preserves filter state
    - _Requirements: 1.1–1.5, 2.1–2.10, 3.1–3.7, 4.1–4.8_

- [x] 11. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The app uses TypeScript throughout with strict mode enabled
- All data transformation logic is pure functions (easily testable independent of React)
- The mock dataset should be comprehensive enough to demo all features without a backend

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["1.3", "1.4"] },
    { "id": 2, "tasks": ["2.1", "2.3", "2.5", "2.7", "2.9", "2.11"] },
    { "id": 3, "tasks": ["2.2", "2.4", "2.6", "2.8", "2.10", "2.12", "4.1"] },
    { "id": 4, "tasks": ["4.2", "4.4"] },
    { "id": 5, "tasks": ["4.3", "4.5"] },
    { "id": 6, "tasks": ["6.1"] },
    { "id": 7, "tasks": ["6.2", "6.3"] },
    { "id": 8, "tasks": ["7.1", "7.2", "8.1"] },
    { "id": 9, "tasks": ["10.1", "10.2"] },
    { "id": 10, "tasks": ["10.3", "10.4"] }
  ]
}
```
