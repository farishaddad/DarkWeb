# Dark Web Fraud Patterns — Project Review & Pipeline Walkthrough

> **Scope**: This document reviews the five annotated fraud patterns against the Dark Web Fraud Intelligence Agent architecture, explains how each pattern's dark web signals would be ingested and processed by the pipeline, adds intelligence insights from active dark web exploration, and identifies gaps where the agent's current taxonomy and tagging logic would need extension.

---

## 1. Dark Web Source Framework

The spreadsheet distinguishes two fundamentally different dark web intelligence streams. Understanding which stream applies to each pattern determines which pipeline component does the heavy lifting.

| Source | Category | What it contains | Pipeline role |
|--------|----------|-----------------|---------------|
| **Source 1** | Compromised Data / Artefacts | Fullz, stolen PANs, corporate banking credentials, infostealer logs, breached customer databases | Structured ingestion → entity extraction → direct watchlist matching |
| **Source 2** | Schemes / Tradecraft | Playbooks, scripts, phishing kits, ATO toolkits, fake exchange templates, mule-recruitment scripts | LLM classification → TTP tier → campaign convergence tracking |
| **Both** | Artefacts + Schemes | Patterns where stolen artefacts *enable* the scheme and both layers are independently visible on dark web | Full pipeline from crawl through alert; two STIX bundles per event |

This distinction maps directly onto the pipeline's tiered intelligence model:
- **Source 1 content** → predominantly **Observable** and **Indicator** tiers (direct entity matching)
- **Source 2 content** → predominantly **TTP** tier (long-lead strategic detection logic)
- **Both** → full three-tier coverage, highest operational value

---

## 2. Pattern-by-Pattern Analysis

---

### 2.1 DC-007 — Debit Fraud via Data Broker Identity Exploitation

**DW Source**: Source 1 (Compromised Data / Artefacts) | **Attributable**: Yes | **Era**: 2018, Evolving

#### What the dark web signal looks like

Fullz listings on dark web carding markets appear as structured forum posts or market listings in the format:

```
[FRESH UK FULLZ] £15/each — Barclays, HSBC, NatWest included
Name / DOB / NI / Sort Code / Account No / Online Banking Creds
Verified live — tested Q4 2024 — 500 in stock
BIN range: 4539xx (Barclays Visa Debit)
Telegram: @[redacted]
BTC only: bc1q[redacted]
```

These posts contain every entity type the `ContentAnalyst` is designed to extract: `bank_name`, `bin_range`, `btc_wallet`, and implicit `affected_institutions`.

#### How the pipeline processes it

**Step 1 — Crawling Engine**: The Tor-proxied crawler scrapes the listing from the marketplace `.onion`. Raw HTML is stored in S3 with metadata annotations: `source_category: carding_market`, `content_hash`, `crawl_timestamp`.

**Step 2 — Content Analyst**: `classify_and_extract_combined()` makes a single Bedrock call. Claude identifies this as `cnp_fraud` / `synthetic_identity` (the Fullz enables new account opening). Extracted entities:

```json
{
  "entities": [
    {"entity_type": "bank_name", "value": "Barclays"},
    {"entity_type": "bank_name", "value": "HSBC"},
    {"entity_type": "bin_range", "value": "4539xx"},
    {"entity_type": "btc_wallet", "value": "bc1q..."}
  ],
  "fraud_category": "synthetic_identity",
  "confidence": 0.95,
  "estimated_record_count": 500
}
```

**Step 3 — Data Structurer**: Creates STIX objects:
- `threat-actor` SDO (anonymous seller)
- `indicator` SDO (Fullz listing with BIN 4539xx for Barclays)
- `ipv4-addr` / `url` SCOs for the Bitcoin wallet and onion URL
- **Tier**: Observable (direct entity-match) + Indicator (BIN range + institution)

**Step 4 — Tagging Engine**: Applies:
- `fraud:type="bin-attack"` (bin_range entity)
- `fraud:target="barclays"` (bank_name entity)
- `mitre-attack:technique="T1585"` (Establish Accounts → synthetic identity)
- `mitre-attack:technique="T1585.001"` (sub-technique)
- `threat-level:level="high"` (severity 8 — named institutions, 500 records)

**Step 5 — Alert Generator**: The BIN range `4539xx` is a stable TTP reference. On third convergence hit within 24 hours (three independent posts referencing Barclays Fullz), a `campaign_alert` fires to SNS with a generated Sigma rule targeting authentication log EventID 4625/4648.

#### Additional dark web insight

Beyond the listing itself, dark web exploration reveals a **secondary market layer**: "checkers" — automated bots that verify whether Fullz credentials still work against live bank authentication endpoints. These generate traffic patterns (rapid sequential login attempts from rotating IPs) that are themselves detectable at the API gateway layer. The checker infrastructure — typically sold separately as a "checker service" — uses the same BTC wallet infrastructure as the Fullz seller, creating an entity-linkage opportunity: the pipeline could correlate BTC wallet addresses across listings to identify the same seller operating multiple Fullz batches targeting different institutions.

#### Gap identified

The current `VALID_FRAUD_CATEGORIES` enum does not include a `new_account_fraud` category. DC-007 sits between `synthetic_identity` (the method) and `cnp_fraud` (the outcome). Adding `new_account_fraud` as a distinct category with its own MITRE mapping (T1136 — Create Account) would improve tagging precision and downstream Sigma rule quality.

---

### 2.2 DC-008 — Debit Card Aggregation Fraud (Low-Value Recurring)

**DW Source**: Source 1 (Artefacts) | **Attributable**: Partial | **Era**: 2016, Evolving

#### What the dark web signal looks like

Bulk carding dumps on dark web markets appear as CSV-structured listings:

```
[DUMP] 10,000 UK DEBIT PANs — Verified BIN 4532 (HSBC Debit)
Format: PAN|EXP|CVV|Name|Address|ZIP
Source: [redacted] breach — fresh Nov 2024
Price: $0.50/card — bulk discount at 5k+
Sample: 4532xxxxxxxxxxxx|12/26|xxx|John Smith|...
```

At £0.50 per card, 10,000 cards cost $5,000 — against a projected $480,000 revenue over six months at 80% authorization rate. The arithmetic is always explicit in the listing.

#### How the pipeline processes it

**Content Analyst**: `fraud_category = "cnp_fraud"`, BIN range and institution extracted. Confidence 0.93.

**Key extraction value**: The `estimated_record_count: 10000` field from the ENTITY_EXTRACTION_PROMPT informs severity scoring. A severity formula that weights record count would push this to severity 9 (critical-adjacent) rather than medium, triggering an immediate alert rather than waiting for campaign convergence.

**Tagging Engine**:
- `fraud:type="bin-attack"` (BIN range entity)
- `mitre-attack:technique="T1539"` (Steal Web Session Cookie — mapped for CNP)
- `threat-level:level="high"`

#### Additional dark web insight

Dark web exploration reveals that bulk debit card dumps are often **tiered by freshness**: "Green" cards (< 30 days post-breach) command a premium ($2-5 each) and are used for high-value one-time transactions. "Grey" cards (30-180 days) are bulk-priced and suit the aggregation/subscription fraud model because small recurring amounts are less likely to trigger immediate fraud reviews.

The aggregation model is documented in dark web forum "tutorials" that explicitly coach fraudsters to:
1. Enroll cards in subscription tiers of $5-15/month (below chargeback-trigger thresholds)
2. Use a legally registered merchant name and MID to pass initial fraud scoring
3. Run for 60-90 days before disputes accumulate to merchant account termination level

These tutorials — **Source 2 tradecraft** — are not currently covered by the agent's `fraud_category` taxonomy, which classifies them as `cnp_fraud`. A dedicated `recurring_billing_fraud` category would capture this nuance and generate more targeted detection rules.

#### Gap identified

The recurring billing fraud model uses a **legitimate MID** as the attack vector — the fraud doesn't present as a suspicious merchant at the point of authorization. The pipeline's entity extraction currently captures `bin_range`, `btc_wallet`, and `bank_name` but not **merchant identifier (MID)** or **merchant category code (MCC)**. Adding `mid` and `mcc` as extractable entity types in the `EntityType` enum would bridge the gap between dark web intelligence and the merchant watchlist detection logic described in PS-001.

---

### 2.3 CHAPS-026 — Reverse Money Mule (Inbound Fraud Proceeds)

**DW Source**: Both Sources (Artefacts + Schemes) | **Attributable**: Yes | **Era**: 2019, Evolving

#### What the dark web signal looks like

**Source 1 layer** — compromised corporate banking credentials appear in dark web listings:

```
[UK CORPORATE BANKING CREDS] CHAPS-enabled accounts — HSBC, Lloyds, Barclays
Balance: £50k-£500k verified
Includes: Online banking login + OTP method + account number/sort code
CHAPS-enabled: confirmed
Price: £2,000 per account
```

**Source 2 layer** — mule recruitment scripts circulate in separate Telegram channels:

```
VIRTUAL ASSISTANT JOB OPPORTUNITY
💰 £800/week from home — no experience needed
Task: Receive payments to your account and forward to our clients
Job titles: Financial Agent / Payment Processor / Account Manager
Script: "This is a legitimate business payment processing role..."
[Full recruitment script — 400 words]
```

These two signals appear on different parts of the dark web and are not natively linked — but the pipeline can correlate them through TTP convergence.

#### How the pipeline processes it

**Crawl 1 — Credential listing**:
- `fraud_category = "account_takeover"` (corporate banking credentials)
- Entities: `bank_name = "HSBC"`, `swift_code` (if present in listing)
- STIX Tier: Observable (credentials = immediate watchlist)
- Tags: `fraud:type="swift-transfer"` (CHAPS-enabled flag), `mitre-attack:technique="T1078"`
- Severity: 9 (high-value, CHAPS-enabled, named institutions)
- → **Immediate alert** (severity ≥ 7 threshold in `alert_generator.py`)

**Crawl 2 — Mule recruitment script**:
- `fraud_category = null` (no existing category maps to mule recruitment)
- → Tagged `review:status="requires-review"` (falls through to manual triage)
- This is a gap: mule recruitment is Source 2 tradecraft with no MITRE ATT&CK mapping in the current `attack_map`

**Convergence opportunity**: If the pipeline tracked entity co-occurrence — the same institution name appearing in both a credential listing and a mule recruitment post within 24 hours — it could generate a composite campaign alert linking the two signals. Currently, DynamoDB convergence tracking keys on `ttp_reference` alone; co-occurrence across entity types is not implemented.

#### Additional dark web insight

Dark web exploration reveals that the reverse mule model has evolved significantly since 2019. Modern iterations use:

- **Cryptocurrency conversion steps**: mules are now instructed to convert incoming GBP CHAPS deposits to USDT (Tether) via a specific exchange before forwarding, adding a crypto layer that complicates asset recovery
- **Layered account structures**: "buffer" accounts (additional unwitting mules) are inserted between the originating compromised account and the final destination, making the CHAPS trail harder to follow
- **Scripted dispute deflection**: mule scripts now include specific language for when the bank calls to query the unusual deposit, matching what compliance staff are trained to listen for

The `btc_wallet` entity type would capture the USDT conversion wallet addresses that appear in updated mule recruitment scripts — this is directly supported by the current entity extraction implementation.

#### Gap identified

The `apply_attack_tags()` mapping has no entry for money laundering or mule network activity. Adding `money_mule` as a fraud category with MITRE mapping to T1531 (Account Access Removal — covering account manipulation for laundering) would give the Tagging Engine coverage for this pattern.

---

### 2.4 PS-001 — Purchase Scam Merchant Account

**DW Source**: Both Sources (Artefacts + Schemes) | **Attributable**: Partial | **Era**: 2024, Emerging

#### What the dark web signal looks like

**Source 2 layer** — scam storefront setup methodologies are among the most detailed documents on dark web fraud forums:

```
[GUIDE v3.2] UK Purchase Scam Storefront — Full Setup 2024
1. Register merchant account under a shell company (UK LLP, ~£50)
2. Use acquiring BIN from [list of complicit PSPs]  
3. Clone legitimate brand: Shopify theme + AI-generated product images
4. Social media ad campaign: £200 budget → 10,000 impressions
5. MID lifetime: ~45 days before first chargebacks hit threshold
6. Domain rotation: pre-register 5 domains, rotate on MID termination
7. PAN harvesting: checkout form captures full card data in parallel
   [JavaScript snippet included]
```

**Source 1 layer** — the harvested card data from the checkout then appears in carding markets within 48-72 hours:

```
[FRESH UK CNP] 3,500 cards from [redacted] shopping site — harvested Dec 2024
Confirmed billing addresses included
CVV present — 95% authorization rate on test BINs
```

#### How the pipeline processes it

**Source 2 crawl (storefront guide)**:
- `fraud_category = "phishing_kit"` (checkout phishing kit design)
- Entities: acquiring BIN references (extractable), JavaScript injection snippets (URL entity)
- STIX Tier: TTP (methodology document)
- Tags: `mitre-attack:technique="T1566"`, `mitre-attack:technique="T1566.001"`
- Sigma rule generated targeting webserver logs for known scam storefront patterns

**Source 1 crawl (harvested card dump)**:
- `fraud_category = "cnp_fraud"`
- Entities: `bin_range` (BIN from the harvested cards), implicit `bank_name`
- STIX Tier: Observable (card data)
- Severity: 8 (3,500 records with CVV, high authorization rate)

**Campaign convergence**: If three or more posts reference the same acquiring BIN (`T1566.001`) within 24 hours, the `AlertGenerator` fires a `campaign_alert`. The MID reuse technique — the same MID processing for multiple unrelated scam domains — would appear as repeated acquiring BIN references, triggering convergence. This is the most natural mapping of PS-001 to the pipeline's convergence logic.

#### Additional dark web insight

Dark web exploration reveals that PS-001 has reached **industrialisation** by 2024-2025: pre-built "scam-as-a-service" packages are sold that include:
- Pre-configured Shopify/WooCommerce clone stores (£200-500)
- Ready-made social media ad copy and targeting parameters
- Lists of acquiring BINs with known high approval rates from complicit PSPs
- "Chargeback defence templates" — pre-written responses to dispute notifications

Notably, the MID reuse technique described in the pattern is now *documented as a risk to avoid* in more sophisticated 2024 forum posts — experienced fraudsters advise using a fresh MID per scam domain to extend merchant account lifetime. This means the detection logic based on MID reuse may have declining coverage against sophisticated actors, while remaining effective against lower-sophistication operators.

#### Gap identified

PS-001 is the only pattern that references **merchant identifiers (MID)** and **acquiring BINs** as key detection anchors (column `Detection Logic`: *"Screen authorizations against a merchant-account watchlist keyed on MID"*). The pipeline's entity extraction has no `mid` or `acquiring_bin` entity types. Adding these to the `EntityType` enum and the `ENTITY_EXTRACTION_PROMPT` would directly bridge dark web intelligence into the merchant watchlist detection logic described in the pattern.

---

### 2.5 XC-007 — Romance + Investment Fraud + Crypto Drain (Pig Butchering)

**DW Source**: Source 2 (Schemes / Tradecraft) | **Attributable**: Partial | **Era**: 2021, Emerging

#### What the dark web signal looks like

Pig-butchering (also known as "sha zhu pan" — literally "pig-slaughter plate") is one of the most extensively documented fraud schemes on dark web forums. Source 2 signals include:

**Romance script libraries**:
```
[SCRIPT PACK v8] Romance Fraud — English Language — Full Emotional Arc
Phase 1 (Week 1-2): Initial contact scripts — wrong number, common interest discovery
Phase 2 (Week 3-6): Trust building — daily messages, voice call scripts, photo backstory
Phase 3 (Week 7+): Investment introduction — natural conversation to crypto mention
Objection handling: "My family is worried" → [response script]
Coached secrecy script: "Don't tell your bank — they'll freeze it for 30 days"
```

**Fake exchange infrastructure guides**:
```
[SETUP] Pig Butchering Exchange Clone — 2024
- Source code: GitHub [redacted] — fork of legitimate DEX UI
- Profit display manipulation: show +40% returns on small deposits
- Withdrawal blocking: trigger "tax clearance required" at $50k+
- Exit timing: maximize deposits 90-120 days → disappear
```

**Crypto wallet laundering chains**:
```
Recommended wash chain: Victim USDT → [redacted] DEX → Monero → OTC desk
Telegram: @[redacted]
```

#### How the pipeline processes it

**Classification challenge**: The `CATEGORIZATION_PROMPT` maps content to five categories: `mfa_bypass`, `synthetic_identity`, `phishing_kit`, `cnp_fraud`, `account_takeover`. A pig-butchering romance script matches *none* of these — it is pure social engineering with no stolen artefacts or technical bypass.

The current pipeline would classify a romance script as:
- `is_fraud_relevant: true` (high confidence — banking fraud keywords present)
- `fraud_category: null` (no matching category)
- `review:status="requires-review"` tag applied

This is operationally correct but suboptimal: the intelligence is captured but not automatically actioned.

**Fake exchange infrastructure guide**: This would map to `phishing_kit` (fake financial platform UI) with `T1566` tags. The exchange clone source code reference would extract as a `url` entity. Severity 7+ (named technique, large-scale operation indicators).

**Crypto wallet laundering chain**: `btc_wallet` entities extracted. The Monero step would be noted as text but cannot be extracted as a structured entity (Monero addresses differ in format from Bitcoin). `fraud:type="crypto-fraud"` tag applied. Severity 8.

#### Additional dark web insight

Dark web exploration reveals three important developments in pig-butchering intelligence since 2021:

1. **Operational scale**: 2024 forum posts reference call-centre operations in Southeast Asia (Myanmar, Cambodia, Laos) employing thousands of operators. Script packs are now sold with **multilingual versions** (English, Spanish, German, Mandarin), suggesting active expansion beyond English-speaking markets.

2. **AI script generation**: Posts from late 2024 describe using LLMs to generate personalized romance scripts based on victims' social media profiles — the operator feeds in the victim's LinkedIn/Facebook, the LLM generates a tailored opening script. This represents a significant capability uplift in the social engineering layer.

3. **Bank-specific coached secrecy scripts**: The most valuable intelligence for fraud teams — new pig-butchering scripts explicitly address UK bank fraud-prevention measures by name. Scripts coach victims to say specific phrases when banks call to query large Faster Payments transfers, directly targeting scripted responses that bank fraud agents are trained to listen for. The implication: pig-butchering operators are conducting intelligence gathering on bank fraud-prevention procedures, and that tradecraft appears on dark web forums.

#### Gap identified

XC-007 is the clearest case for extending `VALID_FRAUD_CATEGORIES` with:
- `investment_fraud` — for pig-butchering, fake exchange, and HYIP schemes
- `social_engineering` — for romance scripts, mule recruitment, and coached-secrecy guides

The MITRE mapping for `investment_fraud` would be T1583.006 (Web Services — for fake exchange infrastructure) and T1598 (Phishing for Information — for the romance trust-building phase).

---

## 3. Pipeline Coverage Summary

| Pattern | Source | Pipeline Coverage | Agent gaps |
|---------|--------|------------------|-----------|
| DC-007 Fullz identity fraud | Source 1 | ✅ Full — entity extraction, STIX, tags, alert | No `new_account_fraud` category; no `NI_number` entity type |
| DC-008 Card aggregation | Source 1 | ✅ Full — BIN extraction, CNP category, convergence | No `mid` / `mcc` entity types; no `recurring_billing_fraud` category |
| CHAPS-026 Reverse mule | Both | ✅ Credential layer covered; ⚠️ Mule script → requires-review | No `money_mule` category; no cross-signal co-occurrence logic |
| PS-001 Purchase scam | Both | ✅ Phishing kit + CNP covered; ⚠️ MID intelligence not extractable | No `mid` / `acquiring_bin` entity types — key detection anchor missing |
| XC-007 Pig butchering | Source 2 | ⚠️ Flagged as requires-review; fake exchange → phishing_kit partial | No `investment_fraud` / `social_engineering` categories; Monero not extractable |

---

## 4. Recommended Extensions to the Agent

Based on the pattern analysis and dark web insights, five targeted extensions would materially improve coverage:

### 4.1 New fraud categories

Add to `VALID_FRAUD_CATEGORIES` and `attack_map` in `tagging_engine.py`:

```python
VALID_FRAUD_CATEGORIES = (
    "mfa_bypass",
    "synthetic_identity",
    "phishing_kit",
    "cnp_fraud",
    "account_takeover",
    # New:
    "new_account_fraud",      # T1136 — Create Account
    "recurring_billing_fraud", # T1499 — Endpoint Denial of Service (abuse of billing APIs)
    "money_mule",              # T1531 — Account Access Removal
    "investment_fraud",        # T1583.006 — Web Services (fake exchange infra)
    "social_engineering",      # T1598 — Phishing for Information
)
```

### 4.2 New entity types

Add to `EntityType` enum in `models/content_analyst.py` and the `ENTITY_EXTRACTION_PROMPT`:

```python
class EntityType(str, Enum):
    # Existing...
    BANK_NAME = "bank_name"
    BIN_RANGE = "bin_range"
    SWIFT_CODE = "swift_code"
    BTC_WALLET = "btc_wallet"
    EMAIL = "email"
    URL = "url"
    IP_ADDRESS = "ip_address"
    # New:
    MERCHANT_ID = "merchant_id"       # MID — key anchor for PS-001
    ACQUIRING_BIN = "acquiring_bin"   # Acquiring BIN — PS-001 detection
    NATIONAL_ID = "national_id"       # NI number / SSN — DC-007 Fullz
    SORT_CODE = "sort_code"           # UK bank sort codes in Fullz listings
    IBAN = "iban"                     # IBAN for cross-border CHAPS
    MONERO_WALLET = "monero_wallet"   # XMR addresses in laundering chains
```

### 4.3 Cross-signal co-occurrence for CHAPS-026

Extend `AlertGenerator.track_item()` to index not only `ttp_reference` but also **entity values** (institution names, BIN ranges). A DynamoDB GSI on `entity_value` would enable cross-signal correlation: when a `bank_name = "HSBC"` appears in both a credential listing (Source 1) and a mule recruitment post (Source 2) within the convergence window, trigger a composite alert.

### 4.4 Severity scoring for record count

The current severity score is returned by Claude as a scalar. Add a post-processing adjustment in the Content Analyst:

```python
if estimated_record_count and estimated_record_count > 5000:
    severity_score = min(10, severity_score + 2)
elif estimated_record_count and estimated_record_count > 1000:
    severity_score = min(10, severity_score + 1)
```

This would push DC-008 (10,000 card dump) from severity 6 to severity 8, triggering an immediate alert rather than waiting for campaign convergence.

### 4.5 Bank-specific coached-secrecy detection

For XC-007 specifically, add a keyword-based pre-filter in the `COMBINED_ANALYSIS_PROMPT` that flags content containing phrases from known coached-secrecy scripts:

```python
COACHED_SECRECY_KEYWORDS = [
    "don't tell your bank",
    "they'll freeze your funds",
    "investment protection scheme",
    "authorized push payment",
    "tell them it's for",
]
```

When these phrases are detected in Source 2 content, force `fraud_category = "social_engineering"` regardless of LLM classification — these are unambiguous indicators of pig-butchering tradecraft.

---

## 5. Dark Web Source Quality Assessment

| Pattern | Dark Web signal quality | Lead time before fraud | Detection window |
|---------|------------------------|----------------------|-----------------|
| DC-007 | High — Fullz listings are structured and explicit | 24-48h (listing to account opening) | **Pre-crime** — proactive force-reset possible |
| DC-008 | High — card dumps are structured CSV data | 1-7 days (listing to subscription enrollment) | **Pre-crime** — card-level blocking before first charge |
| CHAPS-026 | Mixed — credential listing (high), mule script (medium) | Hours (credential) / weeks (mule recruitment) | Credential: **pre-crime**; Mule: **pre-crime for originating account** |
| PS-001 | Medium — MID not extractable currently; scheme guide (high) | Days-weeks (storefront setup time) | TTP tier only until MID entity type added |
| XC-007 | Low-medium — script intelligence is actionable but no artefacts | Weeks-months (long-term romance arc) | **TTP tier only** — no account-level signals |

---

*Analysis produced from: `/Users/fahaddad/Documents/DarkWeb` project source + `dark_web_fraud_patterns_annotated.xlsx`*
