# Dark web fraud signals (Part 2): Building the intelligence pipeline

In [Part 1](link-to-part-1) of this series, I explained why dark web signals provide upstream lead time for banking fraud detection and introduced the five-agent pipeline architecture. I showed how threat intelligence from underground forums, marketplaces, and paste sites can reach your anti-fraud models hours or days before traditional detection methods fire.

This post walks you through building the first three agents in the pipeline: the **Crawling Engine**, the **Content Analyst**, and the **Data Structurer**. Together, these agents handle collection, analysis, and intelligence structuring, transforming raw dark web content into STIX 2.1 objects indexed for semantic correlation.

By the end of this post, you will have working implementations of all three agents with Tor proxy connectivity, single-call Bedrock analysis, regex-augmented entity extraction, STIX 2.1 bundle creation, and OpenSearch Serverless vector indexing.

## Solution walkthrough

The pipeline flows linearly through five agents. This post covers Agents 1 through 3:

1. **Crawling Engine** — Retrieves raw content from dark web sources via Tor, deduplicates using SHA-256 hashing, and stores artifacts in Amazon S3 with queryable annotations.
2. **Content Analyst** — Classifies content for fraud relevance, extracts structured entities, categorizes fraud techniques, and scores severity using Amazon Bedrock with Guardrails.
3. **Data Structurer** — Converts classified intelligence into STIX 2.1 objects, classifies intelligence tiers, generates vector embeddings via Amazon Titan, and indexes into OpenSearch Serverless.

Agents 4 (Tagging Engine) and 5 (Alert Generator) are covered in Part 3 alongside the full AWS CDK deployment.

## Agent 1: Crawling Engine

The Crawling Engine is the pipeline's entry point. It connects to dark web sources through Tor, retrieves content, deduplicates it, and stores raw artifacts in S3 with rich metadata annotations.

### Tor proxy connectivity

The agent uses the `stem` library to manage Tor circuit rotation through the SOCKS5 proxy. Each crawl request routes through Tor's onion network, and the agent rotates circuits between retries to avoid source-level blocking.

The Crawling Engine connects to the Tor control port to issue `NEWNYM` signals, which request a fresh circuit with a different exit node. This gives each retry attempt a different network identity.

```python
from stem import Signal
from stem.control import Controller

async def rotate_circuit(self) -> str:
    """Rotate the Tor circuit to obtain a new exit node IP."""
    if not self._is_running or self._tor_controller is None:
        raise RuntimeError("CrawlingEngine is not running. Call start() first.")

    # Send NEWNYM signal to request a new circuit
    self._tor_controller.signal(Signal.NEWNYM)

    # Get the new exit node IP from the Tor circuit info
    new_ip = self._get_exit_ip()
    self._current_ip = new_ip
    return new_ip

def get_proxy_url(self) -> str:
    """Get the SOCKS5 proxy URL for HTTP requests through Tor."""
    return f"socks5://127.0.0.1:{self._crawl_config.tor_socks_port}"
```

The SOCKS5 proxy URL is passed to `aiohttp` for all outbound requests. The Tor control port password is retrieved from AWS Secrets Manager at startup.

### Circuit breaker pattern

When a dark web source becomes unreachable, the agent should not keep hammering it. The circuit breaker tracks consecutive failures per source URL and isolates failing sources with exponential backoff recovery (60s → 120s → 240s → max 3600s). This prevents permanently unreachable sources from being probed every 60 seconds indefinitely.

The circuit breaker has three states:
- **Closed** — Normal operation, requests flow through.
- **Open** — Five consecutive failures reached; requests are blocked until recovery timeout elapses.
- **Half-open** — Recovery timeout has elapsed; one probe request is allowed to test availability.

```python
@dataclass
class CircuitBreakerState:
    """DynamoDB-backed circuit breaker state for a crawl source."""

    source_url_hash: str
    consecutive_failures: int = 0
    state: str = "closed"  # "closed" | "open" | "half-open"
    last_failure_time: Optional[datetime] = None
    recovery_timeout: int = 60

    @property
    def is_open(self) -> bool:
        """Return True when the circuit breaker is open (consecutive_failures >= 5)."""
        return self.consecutive_failures >= 5

    @property
    def should_attempt_recovery(self) -> bool:
        """Return True when elapsed time since last failure exceeds recovery_timeout."""
        if self.last_failure_time is None:
            return True
        elapsed = (datetime.now(UTC) - self.last_failure_time).total_seconds()
        return elapsed > self.recovery_timeout

    def record_failure(self) -> None:
        """Record a failure, incrementing the counter and updating state."""
        self.consecutive_failures += 1
        self.last_failure_time = datetime.now(UTC)
        if self.is_open:
            self.state = "open"

    def record_success(self) -> None:
        """Record a success, resetting the circuit breaker to closed state."""
        self.consecutive_failures = 0
        self.state = "closed"
        self.last_failure_time = None
```

The `source_url_hash` serves as the DynamoDB partition key, so circuit breaker state persists across Lambda cold starts and ECS task restarts.

### S3 artifact storage with S3 Annotations (GA)

Raw crawl content lands in S3 with date-partitioned keys: `crawl-artifacts/{YYYY}/{MM}/{DD}/{content_hash_prefix}/{uuid}.txt`. Each artifact receives an S3 Annotation containing the full source metadata (URL, category, timestamp, proxy identity, response status, content hash). S3 Annotations (GA) support up to 1 GB of queryable metadata per object, which means you can query artifacts by metadata fields without downloading the raw content.

The bucket uses CMK encryption, Object Lock (WORM) for forensic integrity, versioning, and Intelligent-Tiering lifecycle rules to archive cold artifacts automatically.

### Content deduplication

Before storing any artifact, the agent computes a SHA-256 hash of the extracted plain text. This hash serves dual purposes:

1. **Deduplication** — If the hash already exists in the DynamoDB state table, the content is unchanged since the last crawl, and the agent skips storage.
2. **Change detection** — When the hash differs from the stored value, the agent stores the new content and updates the state record.

```python
def compute_content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for deduplication."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
```

### The CrawlResult dataclass

Every successful crawl produces a `CrawlResult` containing everything downstream agents need:

```python
@dataclass
class CrawlResult:
    """Result of a single crawl operation against a dark web source."""

    source_url: str
    source_category: str  # "forum" | "marketplace" | "telegram" | "paste"
    raw_content: str
    crawl_timestamp: datetime
    proxy_identity: str
    response_status: int
    content_hash: str  # SHA-256 for deduplication
    s3_artifact_key: str  # S3 key for raw artifact
    s3_annotation_id: str  # S3 Annotation ID with metadata
```

The `source_category` field tells the Content Analyst what type of source produced the content, which influences classification confidence thresholds. The `proxy_identity` field records which Tor exit node was used, enabling correlation analysis if a source blocks specific exit nodes.

### The crawl_source() method

The core crawl logic combines retry handling, circuit rotation, deduplication, and S3 storage into a single orchestration method:

```python
async def crawl_source(self, source: SourceDefinition) -> CrawlResult:
    """Crawl a dark web source via Tor proxy with retry logic and circuit breaker."""
    if not self._is_running:
        raise RuntimeError("CrawlingEngine is not running. Call start() first.")

    # Check circuit breaker state
    source_url_hash = compute_content_hash(source.url)
    circuit_breaker = self._get_circuit_breaker_state(source_url_hash)

    if circuit_breaker.is_open and not circuit_breaker.should_attempt_recovery:
        raise CrawlError(
            f"Circuit breaker open for {source.url}. "
            f"Consecutive failures: {circuit_breaker.consecutive_failures}. "
            f"Recovery timeout not elapsed."
        )

    max_retries = self._crawl_config.max_retries
    last_exception: Optional[Exception] = None

    for attempt in range(max_retries):
        proxy_identity = self._current_ip or "initial"

        try:
            # Rotate circuit on retry (not on first attempt)
            if attempt > 0:
                proxy_identity = await self.rotate_circuit()

            crawl_timestamp = datetime.now(UTC)
            proxy_url = self.get_proxy_url()

            # Connect via Tor SOCKS5 proxy and fetch content
            connector = aiohttp.TCPConnector()
            timeout = aiohttp.ClientTimeout(
                total=self._crawl_config.request_timeout
            )

            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get(
                    source.url, proxy=proxy_url
                ) as response:
                    response_status = response.status
                    raw_html = await response.text()

            # Extract plain text from HTML
            raw_content = _strip_html_tags(raw_html)

            # Compute content hash for deduplication
            content_hash = compute_content_hash(raw_content)

            # Store artifact in S3 with annotation
            metadata = {
                "source_url": source.url,
                "source_category": source.category,
                "crawl_timestamp": crawl_timestamp,
                "proxy_identity": proxy_identity,
                "response_status": response_status,
                "content_hash": content_hash,
            }

            s3_artifact_key, s3_annotation_id = store_artifact(
                content=raw_content,
                metadata=metadata,
                s3_bucket=self._crawl_config.s3_bucket,
                s3_client=self._s3_client,
            )

            # Record success in circuit breaker
            circuit_breaker.record_success()
            self._save_circuit_breaker_state(circuit_breaker)

            return CrawlResult(
                source_url=source.url,
                source_category=source.category,
                raw_content=raw_content,
                crawl_timestamp=crawl_timestamp,
                proxy_identity=proxy_identity,
                response_status=response_status,
                content_hash=content_hash,
                s3_artifact_key=s3_artifact_key,
                s3_annotation_id=s3_annotation_id,
            )

        except CrawlError:
            raise
        except Exception as e:
            last_exception = e
            circuit_breaker.record_failure()

            # On connectivity loss, attempt reconnection within 60 seconds
            if self._is_connectivity_error(e):
                await self._attempt_reconnection()

    # All retries exhausted
    self._save_circuit_breaker_state(circuit_breaker)
    raise CrawlError(
        f"All {max_retries} crawl attempts failed for {source.url}. "
        f"Last error: {last_exception}"
    )
```

Note the flow: on first attempt the agent uses the current circuit. On subsequent retries it rotates to a fresh exit node. Each failure increments the circuit breaker, and on connectivity errors the agent proactively attempts reconnection before the next retry.

### ECS Fargate deployment model

The Crawling Engine runs on Amazon ECS Fargate as a two-container task definition:

- **App container** — The Python crawling engine (`crawling-engine`) running `aiohttp` with the SOCKS5 proxy configuration.
- **Tor sidecar** — A lightweight container running the Tor daemon with the control port exposed on localhost. The app container connects to `127.0.0.1:9050` (SOCKS) and `127.0.0.1:9051` (control).

This sidecar pattern keeps Tor management separate from application logic. The Fargate task runs in a private subnet with egress through a NAT Gateway, so Tor traffic reaches the public internet while AWS API calls route through VPC Interface Endpoints.

The CDK stack provisions FARGATE_SPOT (weight 2) with a FARGATE base of 1 task, optimizing cost while maintaining availability for at least one crawl task at all times.

## Agent 2: Content Analyst

The Content Analyst receives raw text from the Crawling Engine and performs three operations in a single Amazon Bedrock invocation: fraud relevance classification, entity extraction, and technique categorization. It scores severity using a composite algorithm and applies a coached-secrecy keyword override for detecting pig-butchering scripts.

### Single-call architecture

Early versions of this agent made three separate Bedrock calls (classify, extract entities, categorize technique). The production implementation uses a single `COMBINED_ANALYSIS_PROMPT` that returns all three outputs in one JSON response. This reduces Bedrock cost by approximately 3x and latency by approximately 2x.

```python
COMBINED_ANALYSIS_PROMPT = """You are a banking fraud intelligence analyst. Analyse the following dark web content and return a single JSON response covering ALL of: fraud relevance, entity extraction, and technique categorisation.

Content:
<content>
{text}
</content>

Respond ONLY with this JSON structure:
{{
  "is_fraud_relevant": true or false,
  "confidence": float 0.0-1.0,
  "reasoning": "brief explanation",
  "entities": [
    {{"entity_type": "bank_name|bin_range|swift_code|btc_wallet|email|url|ip_address",
      "value": "...", "context": "surrounding 50 chars", "confidence": float}}
  ],
  "affected_institutions": ["Bank A", "Bank B"],
  "estimated_record_count": null,
  "fraud_category": "mfa_bypass|synthetic_identity|phishing_kit|cnp_fraud|account_takeover|new_account_fraud|recurring_billing_fraud|money_mule|investment_fraud|social_engineering|null"
}}

Fraud relevance criteria: MFA bypass, stolen credentials/Fullz, phishing kits, account takeover,
synthetic identity, CNP fraud, BIN/SWIFT data, crypto wallets used for fraud proceeds,
fake investment platforms, romance/pig-butchering scripts, mule recruitment, recurring billing abuse.
Fraud categories: mfa_bypass, synthetic_identity, phishing_kit, cnp_fraud, account_takeover,
new_account_fraud, recurring_billing_fraud, money_mule, investment_fraud, social_engineering.
Entity types: bank_name, bin_range, swift_code, btc_wallet, email, url, ip_address,
merchant_id, acquiring_bin, national_id, sort_code, iban, monero_wallet.
If content is not fraud-relevant, entities and fraud_category should be empty/null.
Confidence < 0.7 indicates uncertainty — flag for manual review."""
```

The prompt instructs the model to return a single JSON object covering all three analysis dimensions. If the combined response fails to parse, the agent falls back to the three-call pattern for resilience.

### Fraud categories

The Content Analyst classifies content into one of ten fraud categories:

| Category | Description |
|----------|-------------|
| `mfa_bypass` | Techniques for bypassing multi-factor authentication (2FA, OTP interception, SIM swapping) |
| `synthetic_identity` | Creating fake identities using real and fabricated data (Fullz manipulation, synthetic SSNs) |
| `phishing_kit` | Phishing tools, kits, or templates targeting financial institutions |
| `cnp_fraud` | Card-not-present fraud techniques (stolen card data, BIN attacks, online transaction fraud) |
| `account_takeover` | Methods for taking over existing bank accounts (credential stuffing, session hijacking) |
| `new_account_fraud` | Opening accounts using stolen Fullz or fabricated identities |
| `recurring_billing_fraud` | Enrolling stolen cards in recurring subscriptions or small-amount billing schemes |
| `money_mule` | Mule recruitment, reverse money mule schemes, unwitting account holders forwarding proceeds |
| `investment_fraud` | Fake investment platforms, pig-butchering schemes, fake crypto exchanges, HYIP scams |
| `social_engineering` | Romance scripts, coached-secrecy guides, mule recruitment scripts, social manipulation |

```python
VALID_FRAUD_CATEGORIES = (
    "mfa_bypass",
    "synthetic_identity",
    "phishing_kit",
    "cnp_fraud",
    "account_takeover",
    "new_account_fraud",
    "recurring_billing_fraud",
    "money_mule",
    "investment_fraud",
    "social_engineering",
)
```

### Entity extraction (13 entity types)

The agent extracts 13 distinct entity types from dark web content:

```python
class EntityType(str, Enum):
    """Recognized entity types for extraction from dark web content."""

    BANK_NAME = "bank_name"
    BIN_RANGE = "bin_range"
    SWIFT_CODE = "swift_code"
    BTC_WALLET = "btc_wallet"
    EMAIL = "email"
    URL = "url"
    IP_ADDRESS = "ip_address"
    MERCHANT_ID = "merchant_id"         # ISO DF42 MID — PS-001 merchant watchlist
    ACQUIRING_BIN = "acquiring_bin"     # Acquiring bank BIN — PS-001 storefront detection
    NATIONAL_ID = "national_id"         # NI / SSN in Fullz listings — DC-007
    SORT_CODE = "sort_code"             # UK sort codes in Fullz / CHAPS credential listings
    IBAN = "iban"                       # IBAN in cross-border CHAPS credential listings
    MONERO_WALLET = "monero_wallet"     # XMR addresses in pig-butchering laundering chains
```

Each entity type maps to specific fraud patterns. For example, `merchant_id` entities anchor the PS-001 purchase-scam merchant watchlist, while `monero_wallet` addresses trace laundering chains in pig-butchering operations (XC-007).

### Severity scoring

Severity scores range from 1 to 10 and combine multiple factors:

- **Base score**: 3 for any fraud-relevant content.
- **Institution count**: +1 per `bank_name` entity, capped at +3.
- **Category severity**: +1 for high-severity categories (`account_takeover`, `mfa_bypass`).
- **Confidence bonus**: +1 if confidence exceeds 0.8.
- **Entity diversity**: +1 if multiple entity types are present (indicating complete intelligence).

The final score is clamped to [1, 10].

### Record-count severity boost

Large-scale data dumps warrant immediate alerts rather than waiting for campaign convergence. The `adjust_severity_for_record_count()` method boosts severity when the extracted `estimated_record_count` crosses volume thresholds:

```python
# Record-count severity boost constants
_RECORD_COUNT_HIGH_THRESHOLD = 5_000   # +2 severity
_RECORD_COUNT_MED_THRESHOLD  = 1_000   # +1 severity

def adjust_severity_for_record_count(
    self, severity: int, estimated_record_count: int | None
) -> int:
    """Boost severity score when a large-scale data dump is detected.

    A 10,000-card dump at DC-008 severity 6 becomes severity 8 (immediate alert).
    """
    if estimated_record_count is None:
        return severity
    if estimated_record_count >= self._RECORD_COUNT_HIGH_THRESHOLD:
        return min(10, severity + 2)
    if estimated_record_count >= self._RECORD_COUNT_MED_THRESHOLD:
        return min(10, severity + 1)
    return severity
```

Consider the DC-008 scenario: a dump listing 10,000 card records with a base severity of 6. The record count exceeds 5,000, so severity jumps to 8, which crosses the high-severity threshold (7) and triggers an immediate alert without waiting for campaign convergence.

### Coached-secrecy keyword override (XC-007)

Pig-butchering operations coach victims to keep transactions secret from their banks. These coached-secrecy phrases are unambiguous markers of investment fraud social engineering. When any of these keywords appear in raw content, the agent forces classification to `social_engineering` regardless of LLM output:

```python
_COACHED_SECRECY_KEYWORDS = (
    "don't tell your bank",
    "dont tell your bank",
    "they'll freeze your funds",
    "they will freeze your funds",
    "investment protection scheme",
    "authorized push payment",
    "tell them it's for",
    "tell them its for",
    "romance script",
    "pig butcher",
    "sha zhu pan",
    "wrong number text",
)
```

This override prevents false negatives on pig-butchering content that the LLM might classify as generic financial discussion. The confidence is also boosted to 0.85 to ensure the item does not get flagged for manual review.

### Bedrock Guardrails integration

Every Bedrock invocation includes a Guardrails identifier. The guardrail configuration protects against:

- **Prompt injection** — Malicious dark web content attempting to manipulate the model's analysis through embedded instructions.
- **Sensitive data detection** — Prevents accidental echo of PII values in the model's reasoning output.

When guardrails intervene, the agent returns `is_fraud_relevant=False` with `confidence=0.0`, ensuring blocked content does not propagate through the pipeline.

### Hybrid extraction: LLM plus regex fallback

Entity extraction uses a two-layer approach:

1. **LLM extraction** — The Bedrock model identifies context-dependent entities (bank names referenced indirectly, BINs discussed in narrative text, wallet addresses embedded in code blocks).
2. **Regex fallback** — Compiled patterns provide reliable extraction for structured identifiers that have well-defined formats, supplementing LLM results and catching entities the model misses.

The agent merges both result sets, deduplicating by `(entity_type, value)` pairs:

```python
# Regex patterns for fallback entity extraction
_BIN_PATTERN = re.compile(r'\b([3-6]\d{5,7})\b')  # 6-8 digits (ISO 7812 moved to 8-digit IINs in 2022)
_BTC_BASE58_PATTERN = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
_BTC_BECH32_PATTERN = re.compile(r'\b(bc1[a-z0-9]{39,59})\b')          # bech32/taproot (>40% of BTC txns)
_MONERO_PATTERN = re.compile(r'\b([48][1-9A-HJ-NP-Za-km-z]{94})\b')   # 95 chars total, full Base58
_IBAN_PATTERN = re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}(?:[A-Z0-9]?)*)\b')
_SORT_CODE_PATTERN = re.compile(r'\b(\d{2}-\d{2}-\d{2})\b')       # Hyphenated only — avoids overlap with BIN \d{6}
_MID_PATTERN = re.compile(r'\b(\d{15})\b')                           # Context-gated: only fires near 'MID', 'merchant', 'acquir'
```

These patterns are **context-gated** in the `_extract_entities_via_regex()` method: each match is validated against surrounding keywords before being promoted to an `ExtractedEntity`. BIN matches require financial context ("bin", "card", "pan"), sort codes require banking context ("sort", "account"), and MID matches require merchant context ("MID", "merchant", "acquir"). This prevents false positives from date strings, phone numbers, and other numeric sequences. The BIN pattern supports both legacy 6-digit and modern 8-digit IINs (ISO 7812-1:2022), and the BTC pattern covers both Base58 legacy addresses and bech32 addresses (which now represent over 40% of Bitcoin transactions). The regex checks surrounding text for keywords like "bin", "card", "visa", "mastercard", "fullz", or "dump" before flagging a match. This prevents false positives on arbitrary six-digit numbers.

Monero wallet extraction targets 95-character addresses starting with 4 or 8, which are used in pig-butchering laundering chains where proceeds move from Bitcoin to Monero for additional anonymity.

IBAN extraction catches cross-border credential listings (CHAPS-026 pattern), and sort code extraction targets UK Fullz listings where sort codes identify the victim's bank branch.

## Agent 3: Data Structurer

The Data Structurer converts classified entities from the Content Analyst into STIX 2.1 (Structured Threat Information Expression) objects. It classifies intelligence tiers, generates vector embeddings for semantic correlation, and indexes structured objects into OpenSearch Serverless.

### STIX 2.1 object model

The agent creates three categories of STIX objects:

**SDOs (Domain Objects)** represent high-level threat concepts:
- `Identity` — Target financial institutions (bank names are victims, not threat actors).
- `ThreatActor` — Genuine threat actor handles or group names.
- `AttackPattern` — Fraud techniques mapped from the ten fraud categories.
- `Indicator` — Detection patterns with STIX pattern expressions.

**SCOs (Cyber-observable Objects)** represent atomic technical observables:
- `IPv4Address` — IP addresses found in infrastructure references.
- `URL` — Web URLs and .onion addresses.
- `EmailAddress` — Email addresses used in phishing or communication.
- `DomainName` — Domains without a scheme (extracted from URL-type entities).
- `Artifact` — BTC wallet addresses (STIX lacks a native cryptocurrency observable type, so wallet addresses are encoded as Artifact payloads).

**SROs (Relationship Objects)** link domain objects to observables:
- `uses` — Threat Actor uses an Attack Pattern.
- `indicates` — Indicator indicates an Attack Pattern or Threat Actor.
- `targets` — Threat Actor targets an Institution (Identity).

### SDO category mapping

The agent maps entity types and fraud categories to the correct STIX SDO type:

```python
_SDO_CATEGORY_MAP = {
    # bank_name entities are TARGET INSTITUTIONS (victims), not threat actors.
    # They are modelled as stix2.Identity(identity_class="organization").
    "bank_name": "identity",
    "fraud_technique": "attack-pattern",
}

_FRAUD_CATEGORY_TO_SDO = {
    "mfa_bypass": "attack-pattern",
    "synthetic_identity": "attack-pattern",
    "phishing_kit": "attack-pattern",
    "cnp_fraud": "attack-pattern",
    "account_takeover": "attack-pattern",
}
```

A critical design decision here: bank names extracted from dark web content represent **victim institutions**, not threat actors. They are modelled as `stix2.Identity(identity_class="organization")`. This prevents SIEM rules from incorrectly associating legitimate banks with threat actor indicators.

### Intelligence tier classification

Not all intelligence items warrant the same treatment. The Data Structurer classifies each item into one of three tiers:

- **Observable** — Atomic data points (IPs, URLs, emails, wallets) with no behavioral context. Useful for blocklists.
- **Indicator** — Composite patterns combining multiple observables with temporal or logical context. Generates detection rules.
- **TTP** — Technique/procedure-level intelligence describing adversarial methodology. Maps to MITRE ATT&CK techniques and informs strategic response.

```python
def classify_tier(self, content: ClassifiedContent) -> IntelligenceTier:
    """Classify content into an intelligence tier."""
    # Check if content describes TTP-level behavior
    if self._is_ttp(content):
        return IntelligenceTier.TTP

    # Check if content describes an indicator-level pattern
    if self._is_indicator(content):
        return IntelligenceTier.INDICATOR

    # Default: atomic observables for blocking
    return IntelligenceTier.OBSERVABLE
```

TTP classification triggers when the fraud category maps to a technique methodology (`mfa_bypass`, `synthetic_identity`, `phishing_kit`, `account_takeover`) or when the severity score reaches 8+ with behavioral context. Indicator classification fires when multiple diverse entity types appear together or the fraud category is `cnp_fraud`.

### Vector embedding generation

Each STIX object receives a 1024-dimension vector embedding generated by Amazon Titan Embed Text v2 through Bedrock. The embedding text is a pipe-separated summary of the object's type, name, description, and value fields:

```python
def _generate_embedding(self, stix_obj) -> list[float]:
    """Generate vector embedding for a STIX object using Bedrock."""
    text = self._get_object_summary(stix_obj)
    model_id = (
        self._config.bedrock_embedding_model_id
        if self._config
        else "amazon.titan-embed-text-v2:0"
    )

    response = self._bedrock_client.invoke_model(
        modelId=model_id,
        body=json.dumps({"inputText": text}),
        contentType="application/json",
    )
    result = json.loads(response["body"].read())
    return result["embedding"]
```

These embeddings enable the Alert Generator (covered in Part 3) to discover semantically related intelligence items even when they use different terminology for the same technique.

### OpenSearch Serverless VECTORSEARCH indexing

The Data Structurer maintains an OpenSearch Serverless collection of type VECTORSEARCH. The index mapping includes:

- `intelligence_vector` — knn_vector field (1024 dimensions, HNSW algorithm, cosine similarity).
- `stix_id`, `stix_type`, `tier`, `fraud_category` — Keyword fields for filtering.
- `severity_score` — Integer field for range queries.
- `entities` — Nested field for entity-level queries.
- `content_summary` — Text field for full-text search.

The OpenSearch client authenticates using AWS SigV4 signing for the `aoss` service. All traffic stays within the VPC through the OpenSearch Serverless VPC Interface Endpoint provisioned by the CDK stack.

### STIX Bundle creation

The agent assembles all STIX objects for a given intelligence item into a Bundle using the `cti-python-stix2` library:

```python
def build_bundle(self, objects: list) -> stix2.Bundle:
    """Assemble a STIX 2.1 Bundle from STIX objects."""
    if not objects:
        raise ValueError("Cannot build a Bundle with an empty objects list.")
    return stix2.Bundle(objects=objects)
```

The `stix2` library performs schema validation on creation, ensuring every Bundle conforms to the STIX 2.1 specification before serialization to S3.

### Provenance chain

The Data Structurer maintains a full provenance chain from raw crawl artifact to indexed intelligence:

1. `source_ref` — The S3 artifact key from the Crawling Engine (`crawl-artifacts/2026/07/15/abc123/xyz.txt`).
2. `stix_id` — The deterministic STIX identifier for each object in the Bundle (format: `{type}--{uuid}`).
3. `bundle_key` — The S3 key where the serialized Bundle is stored (`stix-bundles/{path}.stix.json`).

This chain allows any alert produced by the Alert Generator to trace back through the Data Structurer's STIX Bundle, the Content Analyst's classification, and the Crawling Engine's raw artifact, all the way to the original dark web source URL.

## Prerequisites

To build and test the three agents locally, you need the following:

- An AWS account with Amazon Bedrock model access enabled for Anthropic Claude and Amazon Titan Embed Text v2.
- Python 3.11 or later
- **Lambda sizing** (for deployment in Part 3): Content Analyst requires 1024 MB memory / 300s timeout (Bedrock inference latency); Data Structurer and Tagging Engine require 512 MB / 120s; Alert Generator requires 256 MB / 60s. All use ARM64 architecture for cost efficiency.
- AWS CLI v2 configured with credentials that have Bedrock InvokeModel permissions.
- Docker (for local Tor sidecar testing).

Add the following to your `requirements.txt`:

```
boto3>=1.34.0
aiohttp>=3.9.0
aiohttp-socks>=0.8.0
beautifulsoup4>=4.12.0
stem>=1.8.1
stix2>=3.0.1
pymisp>=2.4.180
opensearch-py>=2.4.0
requests-aws4auth>=1.2.0
```

Clone the repository to get started:

```bash
git clone https://github.com/farishaddad/DarkWeb
cd dark-web-fraud-signals
pip install -r requirements.txt
```

## Clean up

Part 3 covers the full CDK deployment and includes comprehensive cleanup instructions for all provisioned AWS resources. For the agents covered in this post, if you are running locally with mocked AWS services (using tools like `moto` or `localstack`), no AWS resources are created and no cleanup is necessary.

If you deployed any AWS resources for testing (S3 buckets, DynamoDB tables, or Secrets Manager secrets), delete them manually or wait for Part 3's CDK `destroy` workflow which handles all resources across all three stacks.

## What's next

In Part 3, I walk through the remaining two agents:

- **Tagging Engine** — Applies MITRE ATT&CK technique tags, custom banking fraud taxonomy tags, MISP Galaxy cluster matching via Knowledge Base queries, and threat-level classification.
- **Alert Generator** — Detects campaign convergence (3+ items referencing the same TTP within 24 hours), cross-entity co-occurrence (the same institution appearing in credential listings and mule recruitment posts), and generates Sigma detection rules for SIEM integration.

Part 3 also covers:
- Full CDK infrastructure deployment across three stacks (Core, Compute, Pipeline).
- Five real fraud patterns walked end-to-end through the pipeline: DC-007 (large Fullz batch), DC-008 (high-volume card dump), CHAPS-026 (cross-border credential composite), XC-007 (pig-butchering scripts), and PS-001 (purchase-scam merchant watchlist).

## Conclusion

In this post, I showed how to build the first three agents of a dark web fraud intelligence pipeline: the Crawling Engine for Tor-based content collection with circuit breaker resilience, the Content Analyst for single-call Bedrock classification with hybrid LLM and regex entity extraction, and the Data Structurer for STIX 2.1 intelligence modeling with vector embeddings indexed into OpenSearch Serverless.

These three agents transform raw dark web forum posts, marketplace listings, and paste site dumps into structured, searchable, schema-validated intelligence objects with full provenance tracking. The severity scoring algorithm, record-count boost, and coached-secrecy keyword override ensure that high-impact findings (large-scale card dumps, pig-butchering scripts) surface immediately rather than waiting for multi-signal convergence.

The complete source code for this solution is available in the [GitHub repository](https://github.com/farishaddad/DarkWeb). I encourage you to clone the repository, explore the test suite, and experiment with the agents locally before deploying to AWS.

If you have questions or feedback about this approach, leave a comment on this post. I would like to hear how your team is approaching dark web intelligence integration with existing fraud detection systems.

---

**About the author**

**Faris Haddad** is a Solutions Architect at AWS, working in the AABG Centre of Excellence (COE). He helps financial services customers build AI-powered fraud detection systems that integrate non-traditional intelligence sources with existing anti-fraud infrastructure.
