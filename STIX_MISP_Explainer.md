# STIX & MISP — Threat Intelligence Standards

## STIX — Structured Threat Information eXpression

A **standardized language and serialization format** for representing cyber threat intelligence. Think of it as a common vocabulary that lets organizations describe and share threat data in a machine-readable way.

### Key Concepts

- Defines **objects** (called SDOs — STIX Domain Objects) such as:
  - `Threat Actor`, `Malware`, `Attack Pattern`, `Indicator`, `Campaign`, `Vulnerability`
- Objects are connected by **relationships** (SROs — STIX Relationship Objects)
- Currently on **STIX 2.1** (JSON-based), replacing the older XML-based STIX 1.x

### Example Use Case

Describing a ransomware campaign — the malware, the TTPs (tactics/techniques), the indicators of compromise (IoCs), and the threat actor — all in a structured, shareable format.

---

## MISP — Malware Information Sharing Platform

An **open-source threat intelligence platform** for collecting, storing, distributing, and sharing IoCs and threat intelligence.

### Key Features

- Acts as a **central repository** for threat data (IPs, domains, hashes, URLs, etc.)
- Supports **correlation** — automatically links related events
- **Sharing communities** — organizations share intel feeds with trusted peers
- Supports STIX export/import, so it interoperates with the broader CTI ecosystem
- Originally built by CIRCL (Computer Incident Response Center Luxembourg)

---

## How They Relate

| | STIX | MISP |
|---|---|---|
| **Type** | Data format/language | Platform/tool |
| **Purpose** | Describe & structure threat intel | Store, share & correlate threat intel |
| **Format** | JSON (STIX 2.1) | Native MISP format + STIX export |
| **Analogy** | Like PDF (the format) | Like Google Docs (the platform) |

They are **complementary** — MISP can ingest and export STIX, and STIX-formatted feeds can be loaded into MISP for analysis and sharing.

---

## Relevance to This Project

The Dark Web Fraud Intelligence Agent produces output in **STIX 2.1 / MISP format**, meaning its findings — threat actors, fraud patterns, and indicators of compromise — are structured in these standards. This makes them directly consumable by any SOC tool or threat intelligence platform that supports them.


---

## Extended Coverage (v0.2.0)

The Dark Web Fraud Intelligence Agent now produces STIX 2.1 / MISP output covering:

### Fraud Categories → STIX Attack Patterns (SDOs)
| Category | MITRE ATT&CK ID | STIX SDO |
|----------|-----------------|----------|
| `mfa_bypass` | T1111 | Attack Pattern |
| `synthetic_identity` | T1585 | Attack Pattern |
| `phishing_kit` | T1566 | Attack Pattern |
| `cnp_fraud` | T1539 | Attack Pattern |
| `account_takeover` | T1078 | Attack Pattern |
| `new_account_fraud` | T1136 | Attack Pattern |
| `recurring_billing_fraud` | T1565 | Attack Pattern |
| `money_mule` | T1537 | Attack Pattern |
| `investment_fraud` | T1583 | Attack Pattern |
| `social_engineering` | T1598 | Attack Pattern |

### Entity Types → STIX Cyber-observable Objects (SCOs)
| Entity Type | STIX SCO | MISP Attribute |
|-------------|----------|----------------|
| `bank_name` | Identity (organization) | `target-org` |
| `bin_range` | Artifact (custom) | `bank-card-bin` |
| `swift_code` | Artifact (custom) | `swift-bic` |
| `btc_wallet` | Artifact (crypto) | `btc` |
| `monero_wallet` | Artifact (crypto) | `xmr` |
| `email` | EmailAddress | `email-src` |
| `url` | URL | `url` |
| `ip_address` | IPv4Address | `ip-src` |
| `merchant_id` | Artifact (custom) | `payment-merchant-id` |
| `acquiring_bin` | Artifact (custom) | `payment-acquiring-bin` |
| `national_id` | Artifact (identity) | `national-id` |
| `sort_code` | Artifact (custom) | `bank-sort-code` |
| `iban` | Artifact (custom) | `iban` |
