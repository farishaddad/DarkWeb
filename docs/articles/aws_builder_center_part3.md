# Dark web fraud signals for banking anti-fraud models (Part 3): Detection rules, composite alerts, and deployment

## Introduction

In [Part 1](/posts/dark-web-fraud-signals-part-1) of this series, I introduced the intelligence model and multi-agent architecture for converting raw dark web content into structured, actionable fraud signals. In [Part 2](/posts/dark-web-fraud-signals-part-2), I walked through building the first three agents: the Crawling Engine (Tor-proxied collection with circuit breaker), the Content Analyst (Claude-powered classification and entity extraction), and the Data Structurer (STIX 2.1 graph creation and OpenSearch vectorization).

This post completes the pipeline. I walk through the final two agents — the Tagging Engine and the Alert Generator — then deploy the full system via AWS CDK, and trace five real fraud patterns end-to-end through the pipeline. By the end, you will have a production-ready system that generates Sigma detection rules and composite alerts from dark web intelligence, with a median lead time of 24 to 48 hours before fraud materializes in your transaction stream.

## Solution walkthrough

### Agent 4: Tagging Engine

The Tagging Engine sits between the Data Structurer and the Alert Generator. It receives a STIX 2.1 bundle with a fraud category and severity score, then applies three layers of machine-readable tags: MITRE ATT&CK technique identifiers, a custom banking fraud taxonomy, and MISP Galaxy cluster associations. These tags are the semantic glue that enables downstream correlation — the Alert Generator uses them to group disparate intelligence items into campaigns.

#### Machine tag format

Every tag follows the namespace:predicate="value" convention from MISP taxonomies. This format is machine-parseable, human-readable, and directly importable into threat intelligence platforms:

```python
@dataclass
class MachineTag:
    """A machine-readable tag in namespace:predicate="value" format."""

    namespace: str
    predicate: str
    value: str

    def __str__(self) -> str:
        return f'{self.namespace}:{self.predicate}="{self.value}"'
```

A tag like `mitre-attack:technique="T1136"` tells the Alert Generator, a SIEM rule, or a MISP instance exactly which technique was observed, without ambiguity.

#### MITRE ATT&CK technique mapping

The `attack_map` dictionary maps each of the ten fraud categories to a primary MITRE ATT&CK technique identifier. I chose technique IDs that represent the closest behavioral analogue in ATT&CK v14 to each banking fraud pattern:

```python
attack_map: dict[str, str] = {
    "mfa_bypass":              "T1111",    # Multi-Factor Authentication Interception
    "phishing_kit":            "T1566",    # Phishing (T1566.001 for attachment delivery)
    "account_takeover":        "T1078",    # Valid Accounts (T1078.001 default creds)
    "synthetic_identity":      "T1585",    # Establish Accounts (T1585.001 social media)
    "cnp_fraud":               "T1539",    # Steal Web Session Cookie (approximation — ATT&CK lacks a native CNP fraud technique)
    "new_account_fraud":       "T1136",    # Create Account (Fullz → new account opening)
    "recurring_billing_fraud": "T1565",    # Data Manipulation (fraudulent recurring charges)
    "money_mule":              "T1537",    # Transfer Data (mule funds) (funds transfer via mules)
    "investment_fraud":        "T1583",    # Acquire Infrastructure (fake exchange setup)
    "social_engineering":      "T1598",    # Phishing for Information (romance / scripted SE)
}
```

These primary technique IDs anchor correlation at a tactic level. For SIEMs that correlate at sub-technique granularity, a second dictionary emits more specific identifiers:

#### Sub-technique precision

```python
sub_technique_map: dict[str, str] = {
    "phishing_kit":            "T1566.001",  # Spearphishing Attachment
    "account_takeover":        "T1078.001",  # Default Accounts
    "synthetic_identity":      "T1585.001",  # Social Media Accounts
    "investment_fraud":        "T1583.006",  # Web Services (fake exchange hosting)
    "social_engineering":      "T1598.003",  # Spearphishing via Service (romance contact)
}
```

When a phishing kit is detected, the Tagging Engine emits both `mitre-attack:technique="T1566"` and `mitre-attack:technique="T1566.001"`. This dual-emission strategy means that a SIEM rule targeting either the parent technique or the specific sub-technique will fire correctly.

The `apply_attack_tags()` method applies both layers:

```python
def apply_attack_tags(self, fraud_category: Optional[str]) -> list[MachineTag]:
    if fraud_category is None or fraud_category not in attack_map:
        return []

    technique_id = attack_map[fraud_category]
    tags = [MachineTag("mitre-attack", "technique", technique_id)]
    if fraud_category in sub_technique_map:
        tags.append(MachineTag("mitre-attack", "technique", sub_technique_map[fraud_category]))
    return tags
```

#### Custom banking fraud taxonomy

The MITRE ATT&CK layer handles the "how" of an attack. The custom fraud taxonomy handles the "what" and "who" — which financial instrument is being abused, which institution is being targeted, and what kind of fraud is occurring.

The `apply_fraud_tags()` method inspects each extracted entity and emits tags based on entity type:

```python
def apply_fraud_tags(self, entities: list[ExtractedEntity]) -> list[MachineTag]:
    tags: list[MachineTag] = []

    for entity in entities:
        if "SWIFT" in entity.value.upper():
            tags.append(MachineTag("fraud", "type", "swift-transfer"))
        if entity.entity_type == "bin_range":
            tags.append(MachineTag("fraud", "type", "bin-attack"))
        if entity.entity_type == "btc_wallet":
            tags.append(MachineTag("fraud", "type", "crypto-fraud"))
        if entity.entity_type == "bank_name":
            tags.append(MachineTag("fraud", "target", entity.value.lower()))
        if entity.entity_type == "monero_wallet":
            tags.append(MachineTag("fraud", "type", "crypto-laundering"))
        if entity.entity_type == "merchant_id":
            tags.append(MachineTag("fraud", "type", "merchant-account-fraud"))
        if entity.entity_type == "acquiring_bin":
            tags.append(MachineTag("fraud", "type", "acquiring-bin-abuse"))
        if entity.entity_type == "iban":
            tags.append(MachineTag("fraud", "type", "cross-border-transfer"))
        if entity.entity_type == "national_id":
            tags.append(MachineTag("fraud", "type", "identity-document-fraud"))

    return tags
```

When the Content Analyst extracts a `bank_name` entity with value "Barclays", the Tagging Engine produces `fraud:target="barclays"`. When it finds a `bin_range` entity, it emits `fraud:type="bin-attack"`. This lets the Alert Generator correlate all intelligence targeting the same institution, regardless of whether the underlying technique is phishing, account takeover, or card fraud.

#### MISP Galaxy cluster matching

The third tagging layer links fraud intelligence to MISP Galaxy clusters. Galaxies provide community-maintained threat actor profiles and attack pattern taxonomies. The Tagging Engine first queries a Bedrock Knowledge Base for a galaxy cluster match. If the Knowledge Base is unavailable or returns low-confidence results, it falls back to a static mapping covering the `financial-fraud`, `social-engineering`, and `mitre-attack-pattern` galaxies:

```python
galaxy_map: dict[str, dict] = {
    "mfa_bypass": {
        "galaxy": "mitre-attack-pattern",
        "cluster_uuid": "mfa-bypass-001",
        "cluster_value": "MFA Bypass",
    },
    "new_account_fraud": {
        "galaxy": "financial-fraud",
        "cluster_uuid": "new-account-fraud-001",
        "cluster_value": "New Account Fraud via Identity Theft",
    },
    "money_mule": {
        "galaxy": "financial-fraud",
        "cluster_uuid": "money-mule-001",
        "cluster_value": "Money Mule Network",
    },
    "social_engineering": {
        "galaxy": "social-engineering",
        "cluster_uuid": "romance-script-001",
        "cluster_value": "Romance Scam / Social Engineering Script",
    },
    # ... entries for all 10 categories
}
```

When a match is found, the engine emits a tag like `misp-galaxy:financial-fraud="Money Mule Network"`. This links the intelligence item to the broader MISP ecosystem — analysts who import your STIX feed into their own MISP instance can immediately see which galaxy cluster the content maps to.

#### Threat-level tag derivation

The severity score (1–10) from the Content Analyst maps to a threat-level tag:

```python
def map_severity_to_threat_level(self, severity: int) -> str:
    if severity <= 3:
        return "low"
    elif severity <= 6:
        return "medium"
    elif severity <= 9:
        return "high"
    else:
        return "critical"
```

This produces tags like `threat-level:level="high"` which SIEM systems can use for priority routing.

#### The requires-review fallback

When content passes through the pipeline but matches neither the attack taxonomy nor the fraud taxonomy, the Tagging Engine applies a workflow tag:

```python
if not attack_tags and not fraud_tags and galaxy_match is None:
    all_tags.append(
        MachineTag(
            namespace="workflow",
            predicate="status",
            value="requires-review",
        )
    )
```

This prevents intelligence from silently disappearing. The `workflow:status="requires-review"` tag routes the item to an analyst queue where a human can evaluate whether the content represents a novel fraud pattern not yet captured in the taxonomies.

### Agent 5: Alert Generator

The Alert Generator is the final agent in the pipeline. It receives tagged intelligence from the Tagging Engine and makes a determination: is this signal strong enough to warrant an alert, or should it be tracked and correlated with future signals?

The agent implements three alert paths:

1. **Immediate alert**: severity score 7 or above bypasses all convergence logic and fires immediately.
2. **TTP convergence alert**: three or more intelligence items reference the same MITRE ATT&CK technique within a 24-hour window.
3. **Entity co-occurrence composite alert**: the same institution name appears in signals from different intelligence tiers.

#### Campaign convergence logic

The convergence check is the primary correlation mechanism. When a new intelligence item arrives, the Alert Generator writes it to DynamoDB with a partition key derived from the TTP reference. It then queries DynamoDB for all items sharing that partition key within the convergence window:

```python
def check_campaign_convergence(
    self,
    ttp_reference: str,
    embedding_vector: list[float] | None = None,
) -> list[str] | None:
    table = self._get_convergence_table()
    resp = table.query(
        KeyConditionExpression=Key("PK").eq(f"CONV#{ttp_reference}"),
    )
    dynamo_items = resp.get("Items", [])
    converged_ids: list[str] = [item["stix_id"] for item in dynamo_items]

    # Phase 2: OpenSearch vector similarity for semantic matches
    os_similar_ids = self.query_opensearch_similar_items(
        ttp_reference=ttp_reference,
        embedding_vector=embedding_vector,
    )

    # Merge and deduplicate
    seen = set(converged_ids)
    for stix_id in os_similar_ids:
        if stix_id not in seen:
            converged_ids.append(stix_id)
            seen.add(stix_id)

    if len(converged_ids) >= _CONVERGENCE_THRESHOLD:
        return converged_ids
    return None
```

The convergence threshold is 3 items. This balances sensitivity with specificity. Items expire via DynamoDB TTL after the 24-hour convergence window closes.

#### Entity co-occurrence composite alerting (CHAPS-026 pattern)

The CHAPS-026 pattern illustrates why simple TTP convergence is not sufficient. Consider two independent crawls:

- Crawl A finds a credential listing containing HSBC sort codes (observable tier, tagged T1078).
- Crawl B finds a mule recruitment script offering "UK account holders needed" with HSBC mentioned specifically (TTP tier, tagged T1537).

Neither alone crosses the TTP convergence threshold — they reference different techniques. But the entity co-occurrence check detects that the same institution appears in signals from different tiers:

```python
def check_entity_cooccurrence(self, entity_type: str, entity_value: str) -> Optional[list[str]]:
    table = self._get_convergence_table()
    resp = table.query(
        KeyConditionExpression=Key("PK").eq(
            f"ENTITY#{entity_type}#{entity_value.lower()}"
        ),
    )
    items = resp.get("Items", [])
    if len(items) < 2:
        return None
    # Require items from at least 2 distinct intelligence tiers
    tiers = {item.get("tier") for item in items}
    if len(tiers) >= 2:
        return [item["stix_id"] for item in items]
    return None
```

The requirement for two distinct tiers prevents a single credential dump with many entries from triggering a false composite alert. Only cross-tier signals — where the attacker is active at multiple operational layers simultaneously — generate an alert.

#### DynamoDB key schema

The ConvergenceTable uses a composite primary key that supports both convergence patterns:

- **TTP convergence**: `PK = CONV#{ttp_reference}`, `SK = ITEM#{stix_id}`
- **Entity co-occurrence**: `PK = ENTITY#bank_name#{institution}`, `SK = ITEM#{stix_id}`

Both patterns coexist in the same table. Entity co-occurrence items are queryable directly on the base table using the `ENTITY#` PK prefix — no GSI needed because the partition key supports both query patterns natively.

#### Tracking items for convergence

The `track_item()` method writes to both key namespaces in a single operation:

```python
def track_item(
    self,
    stix_id: str,
    ttp_reference: str,
    tier: str,
    entity_values: list[dict] | None = None,
) -> None:
    table = self._get_convergence_table()
    ttl = int((datetime.now(UTC) + self._convergence_window).timestamp())
    try:
        table.put_item(
            Item={
                "PK": f"CONV#{ttp_reference}",
                "SK": f"ITEM#{stix_id}",
                "stix_id": stix_id,
                "ttp_reference": ttp_reference,
                "tier": tier,
                "timestamp": datetime.now(UTC).isoformat(),
                "TTL": ttl,
            },
            ConditionExpression=Attr("SK").not_exists(),
        )
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        pass  # Item already tracked — idempotent

    # Cross-entity co-occurrence: index each bank_name entity independently.
    # When the same institution appears in both a credential listing and a
    # mule-recruitment post within the convergence window, a composite alert
    # is generated linking both signals (CHAPS-026).
    if entity_values:
        for entity in entity_values:
            if entity.get("entity_type") == "bank_name":
                bank_key = f"ENTITY#bank_name#{entity['value'].lower()}"
                try:
                    table.put_item(
                        Item={
                            "PK": bank_key,
                            "SK": f"ITEM#{stix_id}",
                            "stix_id": stix_id,
                            "ttp_reference": ttp_reference,
                            "tier": tier,
                            "entity_type": "bank_name",
                            "entity_value": entity["value"].lower(),
                            "timestamp": datetime.now(UTC).isoformat(),
                            "TTL": ttl,
                        },
                        ConditionExpression=Attr("SK").not_exists(),
                    )
                except table.meta.client.exceptions.ConditionalCheckFailedException:
                    pass  # Entity already tracked — idempotent
```

The `ConditionExpression` ensures idempotency — duplicate writes from at-least-once delivery are silently skipped.

#### Sigma YAML rule generation

When convergence is detected, the Alert Generator produces a Sigma detection rule alongside the alert. Sigma is vendor-neutral (translates to Splunk SPL, Elastic KQL, Sentinel KQL):

```python
_SIGMA_LOGSOURCE_MAP = {
    "T1111": {"category": "authentication", "product": "windows"},
    "T1566": {"category": "webserver"},
    "T1078": {"category": "authentication"},
    "T1585": {"category": "network"},
    "T1539": {"category": "proxy"},
    "T1136": {"category": "network", "service": "newaccountmonitoring"},
    "T1565": {"category": "application", "product": "payment-gateway"},
    "T1537": {"category": "network", "service": "transaction-monitoring"},
    "T1583": {"category": "network"},
    "T1598": {"category": "application"},
}

_SIGMA_TITLE_MAP = {
    "T1111": "MFA Interception Detected",
    "T1566": "Phishing Kit Deployment Detected",
    "T1078": "Account Takeover via Valid Credentials",
    "T1585": "Synthetic Identity Account Creation",
    "T1539": "Card-Not-Present Session Cookie Theft",
    "T1136": "New Account Fraud via Stolen Identity (Fullz)",
    "T1565": "Recurring Billing Aggregation Fraud Detected",
    "T1537": "Money Mule Network Activity Detected",
    "T1583": "Investment Fraud / Fake Exchange Infrastructure",
    "T1598": "Social Engineering — Romance Script / Pig Butchering",
}
```

The generation function assembles a complete, syntactically valid Sigma rule:

```python
def _generate_sigma_rule(ttp_reference: str, ttp_description: str) -> str:
    import uuid as _uuid
    import datetime as _dt

    technique_id = None
    if "=" in ttp_reference:
        technique_id = ttp_reference.split("=")[-1].strip()
    elif len(ttp_reference) >= 5 and ttp_reference.startswith("T"):
        technique_id = ttp_reference

    logsource = _SIGMA_LOGSOURCE_MAP.get(technique_id, {"category": "security"})
    title = _SIGMA_TITLE_MAP.get(technique_id, f"Dark Web Campaign: {ttp_reference[:60]}")
    logsource_lines = "\n    ".join(f"{k}: {v}" for k, v in logsource.items())
    attack_tag = (
        f"attack.{technique_id.lower().replace('.', '_')}"
        if technique_id else "attack.t0000"
    )

    # Technique-specific detection logic per logsource category.
    detection_map = {
        "T1111": (  # MFA Interception
            "    selection:\n"
            "        EventType: AuthenticationFailure\n"
            "        FailureReason|contains:\n"
            "            - 'MFA_CHALLENGE_FAILED'\n"
            "            - 'OTP_EXPIRED'\n"
        ),
        "T1078": (  # Account Takeover via Valid Credentials
            "    selection:\n"
            "        EventID:\n"
            "            - 4625\n"
            "            - 4648\n"
            "    filter:\n"
            "        SourceIP|cidr:\n"
            "            - '10.0.0.0/8'\n"
        ),
        "T1566": (  # Phishing Kit
            "    selection:\n"
            "        cs-uri-stem|contains:\n"
            "            - '/login'\n"
            "            - '/signin'\n"
            "        cs-referer|endswith: '.onion'\n"
        ),
        "T1136": (  # New Account Fraud
            "    selection:\n"
            "        EventType: AccountCreated\n"
            "        ChannelType: 'DIGITAL'\n"
            "    timeframe: 24h\n"
        ),
        "T1537": (  # Money Mule — flag large transfers from young accounts
            "    selection:\n"
            "        EventType: FundsTransfer\n"
            "        Amount|gte: 5000\n"
        ),
    }
    detection_block = detection_map.get(
        technique_id,
        "    selection:\n"
        "        EventType|contains: 'suspicious'\n"
    )

    return (
        f"title: {title}\n"
        f"id: {_uuid.uuid4()}\n"
        f"status: experimental\n"
        f"description: |\n"
        f"    Auto-generated from dark web campaign convergence.\n"
        f"    TTP: {ttp_reference}\n"
        f"    Context: {ttp_description[:200]}\n"
        f"references:\n"
        f"    - https://attack.mitre.org/techniques/{technique_id or 'T0000'}/\n"
        f"author: dark-web-fraud-agent\n"
        f"date: {_dt.date.today().isoformat()}\n"
        f"tags:\n"
        f"    - {attack_tag}\n"
        f"logsource:\n"
        f"    {logsource_lines}\n"
        f"detection:\n"
        f"{detection_block}"
        f"    condition: selection\n"
        f"falsepositives:\n"
        f"    - Legitimate activity matching the selection criteria\n"
        f"    - Security testing\n"
        f"level: high\n"
    )
```

Each rule targets technique-specific log fields — authentication events for T1078, HTTP logs for T1566, account creation for T1136, transaction events for T1537. Other techniques receive a generic placeholder for customisation.

Sigma rules are included in the SNS alert payload for SIEM deployment.

#### Two invocation paths

The Alert Generator Lambda handles two distinct trigger sources:

1. **Step Functions (scheduled)**: The normal pipeline path. Every 5 minutes, EventBridge triggers the full pipeline. The Alert Generator receives tagged intelligence from the Tagging Engine and evaluates convergence.

2. **DynamoDB Streams (reactive)**: When a new item is written to the ConvergenceTable, the DynamoDB Stream triggers the Alert Generator immediately. This path handles the case where a third item converges around a TTP — the alert fires within seconds of the convergence threshold being crossed, rather than waiting up to 5 minutes for the next scheduled pipeline run.

#### Immediate alert threshold

High-severity items bypass convergence entirely:

```python
high_severity_threshold = int(os.environ.get("HIGH_SEVERITY_THRESHOLD", "7"))
immediate_alert = severity_score >= high_severity_threshold

if convergence_ids or immediate_alert:
    alert = generator.generate_campaign_alert(
        ttp_reference=ttp_ref,
        ttp_description=f"[{fraud_category}] Campaign or high-severity intelligence detected",
        affected_institutions=[],
        related_ids=convergence_ids or [stix_bundle_key],
        source_url=s3_key,
        crawl_timestamp=datetime.now(timezone.utc),
    )
    alert_published = generator.publish_alert(alert, sns_topic_arn, _sns_client)
```

A Fullz listing with a severity of 8 (boosted by the record-count adjustment from Part 2) fires an alert immediately. The SOC team does not wait for two additional signals to confirm what a single high-confidence, high-volume dump already tells them.

### Infrastructure as code: AWS CDK deployment

The system deploys as three dependent CDK stacks: `CoreStack → ComputeStack → PipelineStack`.

#### CoreStack resources

The CoreStack provisions foundational infrastructure with no dependencies on other stacks:

- **VPC**: Multi-AZ, 2 NAT Gateways, three subnet tiers (Public, Private with Egress for Fargate/Tor, Isolated for Lambda). VPC Endpoints: Bedrock Runtime, Secrets Manager, SNS, SQS, CloudWatch Logs, OpenSearch (aoss) Interface Endpoints + S3/DynamoDB Gateways.
- **KMS CMK**: A single customer-managed key with automatic annual rotation encrypts all data at rest across S3, DynamoDB, and Secrets Manager.
- **S3 artifacts bucket**: CMK-encrypted with Object Lock enabled (WORM compliance for forensic integrity), versioning, and Intelligent-Tiering lifecycle rules.
- **DynamoDB ConvergenceTable**: Pay-per-request billing, CMK encryption, TTL attribute for automatic item expiration, and DynamoDB Streams enabled for the reactive alert path.
- **Secrets Manager**: Tor control port password (auto-generated, 32 characters) and MISP API key.

The ConvergenceTable includes a Global Secondary Index for entity co-occurrence queries:

The ConvergenceTable uses a single-table design with PK namespace prefixes — no GSI required:

```python
self.convergence_table = dynamodb.Table(
    self, "ConvergenceTable",
    table_name="dark-web-fraud-convergence",
    partition_key=dynamodb.Attribute(name="PK", type=dynamodb.AttributeType.STRING),
    sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
    billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
    time_to_live_attribute="TTL",
    stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
)
```

Two query patterns work directly on the base table PK:
- **TTP convergence**: `PK = "CONV#mitre-attack:technique=T1078"` → all items referencing that TTP within the TTL window
- **Entity co-occurrence**: `PK = "ENTITY#bank_name#hsbc"` → all items mentioning HSBC, with tier diversity indicating a composite signal

No GSI needed — DynamoDB resolves PK queries in single-digit milliseconds.

#### PipelineStack resources

The PipelineStack orchestrates the five-agent pipeline:

- **Step Functions Standard Workflow**: Five sequential states (CrawlSources → AnalyzeContent → StructureData → TagIntelligence → GenerateAlerts). At 288 daily executions (5-minute cadence), Standard Workflow costs approximately $0.04/day — cost-effective for this volume and avoids the 5-minute maximum execution duration limit that Express Workflow imposes. Standard Workflow also provides built-in execution history in the Step Functions console without requiring separate CloudWatch Logs configuration.
- **EventBridge Scheduler**: Rate-based schedule (every 5 minutes) with a dead-letter queue for missed invocations. Uses `FlexibleTimeWindow: { Mode: OFF }` for precise scheduling.
- **SNS + SQS FIFO**: The alert topic fans out to a FIFO queue (ordered delivery by TTP group) with a separate DLQ for failed deliveries. FIFO guarantees chronological ordering per campaign. Deduplication uses explicit `MessageDeduplicationId` (the `alert_id` UUID) to prevent collision between similar convergence alerts.
- **CloudWatch Dashboard**: Three rows of widgets showing pipeline execution metrics, alert queue depth, and alert-type breakdown.

The Alert Generator state payload demonstrates how entity information threads through the entire pipeline:

```python
alert_state = tasks.LambdaInvoke(
    self,
    "GenerateAlerts",
    comment="Alert Generator — campaign convergence + SNS fan-out + entity co-occurrence",
    lambda_function=alert_generator_fn,
    payload=sfn.TaskInput.from_object({
        "tagging_output": sfn.JsonPath.object_at("$.tagging_result.tagging_output"),
        "execution_id": sfn.JsonPath.string_at("$$.Execution.Id"),
        # Pass extracted entities so track_item() can index bank_name values
        # for cross-entity co-occurrence detection (CHAPS-026 composite alert).
        "entities": sfn.JsonPath.object_at(
            "$.analyst_result.analyst_output.entities"
        ),
    }),
    result_selector={"alert_output.$": "$.Payload"},
    result_path="$.alert_result",
    retry_on_service_exceptions=True,
)
```

The `entities` field is sourced from the Content Analyst output (state 2) and forwarded directly to state 5 — bypassing the Data Structurer and Tagging Engine states. This ensures that the raw extracted entity list (including bank_name values) reaches the Alert Generator for co-occurrence indexing.

#### Deployment commands

Deploy all three stacks in dependency order:

```bash
cd infrastructure/
cdk bootstrap aws://ACCOUNT_ID/eu-west-2
cdk deploy --all --require-approval broadening
```

The stacks deploy in the correct order automatically based on their construct dependencies.

### Five fraud patterns in practice

The following examples trace real fraud patterns end-to-end through the pipeline.

#### Pattern DC-007: Fullz identity fraud

**Source material**: A dark web marketplace listing titled "Fresh UK Fullz — NI verified, all with sort codes."

**Pipeline trace**:

1. **Crawling Engine**: Retrieves the listing via Tor proxy. Stores raw content in S3 with annotation metadata.
2. **Content Analyst**: Classifies as fraud-relevant (confidence 0.93). Extracts entities: national_id (NI format AA999999A), sort_code (20-45-67), bank_name (Barclays), bin_range (476134). Categorizes as `new_account_fraud`. Base severity 5, boosted to 8 by the record-count adjustment (listing advertises 500+ records, crossing the high-volume threshold).
3. **Data Structurer**: Creates STIX Identity SDO for Barclays (victim institution), AttackPattern SDO for new account fraud, and SCOs for each extracted entity. Classifies tier as TTP. Indexes to OpenSearch with 1024-dimension Titan embedding.
4. **Tagging Engine**: Emits `mitre-attack:technique="T1136"` (Create Account), `fraud:type="identity-document-fraud"`, `fraud:target="barclays"`, `threat-level:level="high"`. Galaxy match: `financial-fraud` cluster "New Account Fraud via Identity Theft".
5. **Alert Generator**: Severity 8 exceeds the immediate alert threshold (7). Fires immediately without waiting for convergence. Publishes campaign alert to SNS with a Sigma rule targeting authentication EventID 4625 (failed logon attempts — the signal that appears when stolen Fullz are used to open accounts online).

**Lead time**: 24–48 hours. The listing typically appears on dark web markets one to two days before the identities are used for account opening applications.

#### Pattern DC-008: Card aggregation dump

**Source material**: A paste site dump containing 10,000 card numbers with BINs, expiry dates, and CVVs.

**Pipeline trace**:

1. **Crawling Engine**: Captures the paste content. Content hash deduplication prevents re-processing if the same dump appears on multiple paste sites.
2. **Content Analyst**: Extracts bin_range entities (multiple BIN prefixes identified). Categorizes as `cnp_fraud`. Base severity 6. The `adjust_severity_for_record_count()` method detects 10,000 records (above the 5,000-record high threshold) and boosts severity by 2, yielding severity 8.
3. **Data Structurer**: Creates STIX Indicator SDOs with pattern expressions for each extracted BIN. Tier classification: Indicator (cnp_fraud is in the indicator category set, and multiple entity types are present).
4. **Tagging Engine**: Emits `mitre-attack:technique="T1539"` (Steal Web Session Cookie — the CNP mapping), `fraud:type="bin-attack"`, `threat-level:level="high"`.
5. **Alert Generator**: Severity 8 triggers immediate alert. The Sigma rule targets proxy log category events. Downstream action: card-level blocking on all affected BINs via the issuer's real-time decisioning engine.

**Lead time**: 1–7 days. Card dumps typically surface on markets before large-scale CNP fraud campaigns begin.

#### Pattern CHAPS-026: Reverse money mule (composite alert)

**Source material**: Two independent crawls from different sources, processed in separate pipeline executions.

- **Crawl A** (forum post): Credential listing with HSBC account numbers, sort codes, and online banking passwords. Observable tier. Tagged T1078 (Valid Accounts).
- **Crawl B** (Telegram channel): Mule recruitment script — "UK account holders needed for receiving transfers, 20% commission, HSBC preferred." TTP tier. Tagged T1537 (Transfer Data (mule funds)).

**Pipeline trace**:

1. **Crawl A processing**: Content Analyst extracts bank_name "HSBC". Data Structurer classifies as observable tier. Tagging Engine emits `fraud:target="hsbc"`. Alert Generator calls `track_item()` with entity_values including `{"entity_type": "bank_name", "value": "hsbc"}`. Writes to both `CONV#mitre-attack:technique="T1078"` and `ENTITY#bank_name#hsbc` in DynamoDB. No convergence detected. No alert.

2. **Crawl B processing** (separate execution): Content Analyst extracts bank_name "HSBC". Data Structurer classifies as TTP tier. Alert Generator calls `track_item()` — writes to `CONV#mitre-attack:technique="T1537"` and `ENTITY#bank_name#hsbc`. No TTP convergence (only 1 item for T1537). But: `check_entity_cooccurrence("bank_name", "hsbc")` finds 2 items across 2 distinct tiers (observable + ttp). Fires composite alert linking both STIX bundles.

**Why this matters**: Neither signal alone is actionable. The combination — credentials for HSBC accounts appearing alongside mule recruitment specifically requesting HSBC account holders — indicates an imminent funds transfer attack against HSBC customers.

#### Pattern PS-001: Purchase scam merchant

**Source material**: A dark web guide titled "Storefront setup — how to build a card-harvesting Shopify clone."

**Pipeline trace**:

1. **Content Analyst**: Classifies as `phishing_kit` (confidence 0.91). Extracts entities: acquiring_bin (6-digit acquiring processor BIN mentioned in the guide), url (phishing domain template). Severity 5.
2. **Data Structurer**: Creates AttackPattern SDO. Tier: TTP (phishing_kit is in the TTP category set).
3. **Tagging Engine**: Emits `mitre-attack:technique="T1566"`, `mitre-attack:technique="T1566.001"`, `fraud:type="acquiring-bin-abuse"`, `threat-level:level="medium"`.
4. **Alert Generator**: Severity 5 does not trigger immediate alert. Tracks item with TTP reference `mitre-attack:technique="T1566.001"`. Uses the acquiring BIN as a secondary convergence key.
5. **Subsequent crawls**: Over the next 48 hours, two more storefront guides surface — all referencing the same acquiring BIN. The third item triggers TTP convergence. Campaign alert fires with a Sigma rule targeting webserver log events. The converged acquiring BIN is added to the merchant watchlist.

**Lead time**: 3–7 days. Purchase scam storefronts typically go live 3 to 7 days after setup guides circulate.

#### Pattern XC-007: Pig butchering

**Source material**: A Telegram message containing a romance scam script with the phrase "don't tell your bank — they'll freeze your funds if you mention crypto."

**Pipeline trace**:

1. **Content Analyst**: The coached-secrecy keyword override fires before returning the combined analysis result. The override exists because LLMs sometimes classify romance scripts as "not fraud-relevant" without coached-secrecy context:

```python
_COACHED_SECRECY_KEYWORDS = (
    "don't tell your bank",
    "they'll freeze your funds",
    "investment protection scheme",
    "authorized push payment",
    "romance script",
    "pig butcher",
    # ... additional markers
)

raw_snippet = text.lower()
if any(kw in raw_snippet for kw in _COACHED_SECRECY_KEYWORDS):
    result["fraud_category"] = "social_engineering"
    result["is_fraud_relevant"] = True
    if result.get("confidence", 0.0) < 0.85:
        result["confidence"] = 0.85
```

This forces the correct classification regardless of LLM output.

2. **Data Structurer**: Tier classification: TTP. Creates AttackPattern SDO.
3. **Tagging Engine**: Emits `mitre-attack:technique="T1598"`, `mitre-attack:technique="T1598.003"` (Spearphishing via Service), `threat-level:level="medium"`. Galaxy match: `social-engineering` cluster "Romance Scam / Social Engineering Script".
4. **Alert Generator**: Severity 5, no immediate alert. Item tracked for convergence. No artefact-level blocking is appropriate — you cannot block a romance script. The intelligence routes to the analyst dashboard where fraud prevention teams use it to inform authorized push payment (APP) intervention strategies.

**Lead time**: Weeks. Pig-butchering scripts circulate for weeks before victims are coached into making the large transfers that constitute the actual fraud event.

### CloudWatch observability

The Alert Generator publishes three custom metrics to the `dark-web-fraud` CloudWatch namespace. Each metric represents a distinct alert pathway:

**EntityCooccurrenceAlerts** (dimension: AlertType=composite): Incremented when `check_entity_cooccurrence()` finds the same entity across multiple intelligence tiers. This metric tells the SOC team how often cross-signal correlation is detecting threats that individual TTP tracking missed. A sustained increase indicates that attackers are coordinating across multiple operational layers.

**TTPConvergenceAlerts**: Incremented when three or more intelligence items converge around a common ATT&CK technique within 24 hours. This metric reflects campaign-scale activity. A spike suggests that a specific attack type is trending across dark web sources.

**ImmediateSeverityAlerts**: Incremented when a single high-severity item (score 7 or above) bypasses convergence and fires immediately. This metric tracks the most urgent signals: large-volume data dumps, high-confidence Fullz listings, and active phishing kit deployments. A sustained high rate may indicate that severity scoring needs recalibration.

The CloudWatch Dashboard groups these metrics in a single row alongside pipeline execution metrics and alert queue depth, giving SOC analysts a unified view of both system health and threat activity.

## Prerequisites

To deploy this solution, you need:

- An AWS account with permissions to create VPC, Lambda, DynamoDB, S3, Step Functions, SNS, SQS, KMS, Secrets Manager, OpenSearch Serverless, EventBridge, and CloudWatch resources.
- AWS CDK v2 installed (`npm install -g aws-cdk`).
- Python 3.11 or later with the project dependencies installed (`pip install -r requirements.txt`).
- A bootstrapped CDK environment in your target region (`cdk bootstrap aws://ACCOUNT_ID/eu-west-2`).
- An Amazon Bedrock model access grant for Claude (Anthropic) in your target region.
- An OpenSearch Serverless VECTORSEARCH collection (created separately or via the companion CDK construct in the repository).

## Clean up

To remove all deployed resources:

```bash
cdk destroy --all
```

This removes the PipelineStack, ComputeStack, and CoreStack in reverse dependency order. Note that Secrets Manager secrets created with `RemovalPolicy.RETAIN` enter a 7-day recovery window rather than being deleted immediately. To force deletion:

```bash
aws secretsmanager delete-secret \
    --secret-id dark-web-fraud/tor-control-password \
    --force-delete-without-recovery

aws secretsmanager delete-secret \
    --secret-id dark-web-fraud/misp-api-key \
    --force-delete-without-recovery
```

The S3 artifacts bucket and DynamoDB tables also use `RemovalPolicy.RETAIN` to prevent accidental data loss. Empty these resources manually before re-running `cdk destroy` if you want complete removal.

## Conclusion

In this post, I showed how to build the final two agents of a five-agent dark web fraud intelligence pipeline: the Tagging Engine (MITRE ATT&CK mapping, custom banking fraud taxonomy, MISP Galaxy cluster matching) and the Alert Generator (TTP convergence, entity co-occurrence composite alerts, Sigma rule generation). I then deployed the full system via AWS CDK and traced five distinct fraud patterns — Fullz identity fraud, card aggregation dumps, reverse money mule coordination, purchase scam merchants, and pig butchering scripts — end-to-end through the pipeline.

Across all three posts in this series, the architecture demonstrates a core principle: dark web intelligence is most valuable when it is structured, classified, and correlated before it reaches a fraud analyst. Raw crawled content has minimal operational value. But that same content, processed through a pipeline that assigns STIX types, ATT&CK technique tags, severity scores, and intelligence tiers, becomes a detection rule that your SIEM can execute automatically — days before the fraud materializes in your transaction stream.

The complete source code, CDK templates, and test suite for this solution are available on the [companion GitHub repository](https://github.com/farishaddad/DarkWeb). Clone the repository, deploy in a sandbox account, and experiment with convergence thresholds and severity scoring to match your institution's risk appetite.

If you have questions or feedback about this implementation, leave a comment on this post.

---

**About the author**

**Faris Haddad** is a Solutions Architect in the AWS AABG Centre of Excellence. He works with financial services customers to design machine learning and generative AI solutions for fraud detection, anti-money laundering, and financial crime prevention.
