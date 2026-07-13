"""Unit tests for taxonomy loading and validation (Task 8.1).

Tests load_taxonomy() with MISP format, S3-based loading via moto,
MITRE ATT&CK STIX loading, and banking fraud taxonomy schema validation.
"""

import json

import boto3
import pytest
from moto import mock_aws

from dark_web_fraud_agent.agents.tagging_engine import (
    TaggingEngine,
    TaxonomyDefinition,
    TaxonomyEntry,
    TaxonomyPredicate,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BANKING_FRAUD_TAXONOMY = {
    "namespace": "fraud",
    "description": "Banking fraud classification taxonomy",
    "version": 1,
    "predicates": [
        {"value": "type", "expanded": "Fraud Type"},
        {"value": "target", "expanded": "Fraud Target"},
    ],
    "values": [
        {
            "predicate": "type",
            "entry": [
                {"value": "mfa_bypass", "expanded": "MFA Bypass"},
                {"value": "synthetic_identity", "expanded": "Synthetic Identity"},
                {"value": "phishing_kit", "expanded": "Phishing Kit"},
                {"value": "card_not_present", "expanded": "Card Not Present Fraud"},
                {"value": "account_takeover", "expanded": "Account Takeover"},
            ],
        },
        {
            "predicate": "target",
            "entry": [
                {"value": "retail_bank", "expanded": "Retail Banking"},
                {"value": "investment_bank", "expanded": "Investment Banking"},
                {"value": "fintech", "expanded": "Financial Technology"},
                {"value": "payment_processor", "expanded": "Payment Processor"},
                {"value": "crypto_exchange", "expanded": "Cryptocurrency Exchange"},
            ],
        },
    ],
}

MINIMAL_ATTACK_STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--test-001",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--test-001",
            "name": "Phishing",
            "description": "Adversaries send phishing messages to gain access.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--test-002",
            "name": "Valid Accounts",
            "description": "Adversaries use stolen credentials.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1078"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
            ],
        },
        {
            "type": "malware",
            "id": "malware--test-001",
            "name": "Banking Trojan",
            "description": "Not an attack-pattern, should be skipped.",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--test-003",
            "name": "No External ID Pattern",
            "description": "Missing mitre-attack external_id, should be skipped.",
            "external_references": [
                {"source_name": "other-source", "external_id": "X999"}
            ],
        },
    ],
}

S3_BUCKET = "dark-web-fraud-test-bucket"
TAXONOMY_S3_PREFIX = "taxonomies/"
ATTACK_STIX_S3_KEY = "attack-data/enterprise-attack.json"


# ---------------------------------------------------------------------------
# MISP format taxonomy loading
# ---------------------------------------------------------------------------


class TestLoadTaxonomyMISPFormat:
    """Tests for load_taxonomy() with MISP-format values array."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_load_misp_format_taxonomy_parses_values_array(self):
        """MISP-format taxonomy with values array loads entries correctly."""
        result = self.engine.load_taxonomy(json.dumps(BANKING_FRAUD_TAXONOMY))

        assert result.namespace == "fraud"
        assert result.version == 1
        assert len(result.predicates) == 2

    def test_load_misp_format_entries_mapped_to_correct_predicate(self):
        """Values array entries are assigned to their matching predicate."""
        result = self.engine.load_taxonomy(json.dumps(BANKING_FRAUD_TAXONOMY))

        type_pred = next(p for p in result.predicates if p.value == "type")
        target_pred = next(p for p in result.predicates if p.value == "target")

        assert len(type_pred.entries) == 5
        assert len(target_pred.entries) == 5

    def test_load_misp_format_entry_values_preserved(self):
        """Entry values and expanded names are preserved from values array."""
        result = self.engine.load_taxonomy(json.dumps(BANKING_FRAUD_TAXONOMY))

        type_pred = next(p for p in result.predicates if p.value == "type")
        entry_values = [e.value for e in type_pred.entries]

        assert "mfa_bypass" in entry_values
        assert "synthetic_identity" in entry_values
        assert "phishing_kit" in entry_values
        assert "card_not_present" in entry_values
        assert "account_takeover" in entry_values

    def test_load_misp_format_expanded_names_preserved(self):
        """Expanded names are correctly parsed from values array."""
        result = self.engine.load_taxonomy(json.dumps(BANKING_FRAUD_TAXONOMY))

        target_pred = next(p for p in result.predicates if p.value == "target")
        expanded_map = {e.value: e.expanded for e in target_pred.entries}

        assert expanded_map["retail_bank"] == "Retail Banking"
        assert expanded_map["fintech"] == "Financial Technology"

    def test_load_misp_format_taxonomy_stored_by_namespace(self):
        """MISP-format taxonomy is stored and retrievable."""
        self.engine.load_taxonomy(json.dumps(BANKING_FRAUD_TAXONOMY))

        loaded = self.engine.get_loaded_taxonomies()
        assert "fraud" in loaded
        assert loaded["fraud"].description == "Banking fraud classification taxonomy"

    def test_load_misp_format_values_not_list_raises_valueerror(self):
        """Non-list 'values' field raises ValueError."""
        taxonomy = {
            "namespace": "bad",
            "predicates": [{"value": "x", "expanded": "X"}],
            "values": "not a list",
        }

        with pytest.raises(ValueError, match="'values' must be a list"):
            self.engine.load_taxonomy(json.dumps(taxonomy))

    def test_load_misp_format_values_item_not_dict_raises_valueerror(self):
        """Non-dict item in 'values' array raises ValueError."""
        taxonomy = {
            "namespace": "bad",
            "predicates": [{"value": "x", "expanded": "X"}],
            "values": ["not a dict"],
        }

        with pytest.raises(ValueError, match="must be an object"):
            self.engine.load_taxonomy(json.dumps(taxonomy))

    def test_load_misp_format_values_missing_predicate_raises_valueerror(self):
        """Values item without 'predicate' field raises ValueError."""
        taxonomy = {
            "namespace": "bad",
            "predicates": [{"value": "x", "expanded": "X"}],
            "values": [{"entry": [{"value": "a", "expanded": "A"}]}],
        }

        with pytest.raises(ValueError, match="'predicate' field"):
            self.engine.load_taxonomy(json.dumps(taxonomy))

    def test_load_misp_format_entry_not_list_raises_valueerror(self):
        """Non-list 'entry' in values raises ValueError."""
        taxonomy = {
            "namespace": "bad",
            "predicates": [{"value": "x", "expanded": "X"}],
            "values": [{"predicate": "x", "entry": "not a list"}],
        }

        with pytest.raises(ValueError, match="'entry' in values must be a list"):
            self.engine.load_taxonomy(json.dumps(taxonomy))

    def test_load_misp_format_entry_missing_value_raises_valueerror(self):
        """Entry in values array without 'value' raises ValueError."""
        taxonomy = {
            "namespace": "bad",
            "predicates": [{"value": "x", "expanded": "X"}],
            "values": [{"predicate": "x", "entry": [{"expanded": "Missing Value"}]}],
        }

        with pytest.raises(ValueError, match="'value' and 'expanded'"):
            self.engine.load_taxonomy(json.dumps(taxonomy))

    def test_load_mixed_format_merges_inline_and_values_entries(self):
        """Entries from both inline 'entries' and 'values' array are merged."""
        taxonomy = {
            "namespace": "mixed",
            "predicates": [
                {
                    "value": "type",
                    "expanded": "Type",
                    "entries": [{"value": "inline_a", "expanded": "Inline A"}],
                }
            ],
            "values": [
                {
                    "predicate": "type",
                    "entry": [{"value": "values_b", "expanded": "Values B"}],
                }
            ],
        }

        result = self.engine.load_taxonomy(json.dumps(taxonomy))
        type_pred = result.predicates[0]

        assert len(type_pred.entries) == 2
        entry_values = [e.value for e in type_pred.entries]
        assert "inline_a" in entry_values
        assert "values_b" in entry_values


# ---------------------------------------------------------------------------
# Banking fraud taxonomy schema
# ---------------------------------------------------------------------------


class TestBankingFraudTaxonomy:
    """Tests validating the custom banking fraud taxonomy schema."""

    def setup_method(self):
        self.engine = TaggingEngine()
        self.taxonomy = self.engine.load_taxonomy(json.dumps(BANKING_FRAUD_TAXONOMY))

    def test_namespace_is_fraud(self):
        assert self.taxonomy.namespace == "fraud"

    def test_has_type_predicate(self):
        pred_values = [p.value for p in self.taxonomy.predicates]
        assert "type" in pred_values

    def test_has_target_predicate(self):
        pred_values = [p.value for p in self.taxonomy.predicates]
        assert "target" in pred_values

    def test_type_predicate_has_fraud_categories(self):
        type_pred = next(p for p in self.taxonomy.predicates if p.value == "type")
        entry_values = {e.value for e in type_pred.entries}

        assert "mfa_bypass" in entry_values
        assert "synthetic_identity" in entry_values
        assert "phishing_kit" in entry_values
        assert "card_not_present" in entry_values
        assert "account_takeover" in entry_values

    def test_target_predicate_has_institution_types(self):
        target_pred = next(p for p in self.taxonomy.predicates if p.value == "target")
        entry_values = {e.value for e in target_pred.entries}

        assert "retail_bank" in entry_values
        assert "investment_bank" in entry_values
        assert "fintech" in entry_values
        assert "payment_processor" in entry_values
        assert "crypto_exchange" in entry_values


# ---------------------------------------------------------------------------
# S3-based taxonomy loading (moto)
# ---------------------------------------------------------------------------


class TestLoadTaxonomyFromS3:
    """Tests for load_taxonomy_from_s3 and load_taxonomies_from_s3_prefix with moto."""

    def setup_method(self):
        self.engine = TaggingEngine()

    @mock_aws
    def test_load_taxonomy_from_s3_parses_valid_file(self):
        """Valid taxonomy JSON in S3 is loaded and parsed correctly."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key="taxonomies/fraud.json",
            Body=json.dumps(BANKING_FRAUD_TAXONOMY).encode(),
        )

        result = self.engine.load_taxonomy_from_s3(
            S3_BUCKET, "taxonomies/fraud.json", s3_client=s3
        )

        assert result.namespace == "fraud"
        assert len(result.predicates) == 2

    @mock_aws
    def test_load_taxonomy_from_s3_invalid_json_raises_valueerror(self):
        """Invalid JSON in S3 raises ValueError."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key="taxonomies/bad.json",
            Body=b"not valid json {{{",
        )

        with pytest.raises(ValueError, match="Invalid taxonomy JSON"):
            self.engine.load_taxonomy_from_s3(
                S3_BUCKET, "taxonomies/bad.json", s3_client=s3
            )

    @mock_aws
    def test_load_taxonomy_from_s3_nonexistent_key_raises_runtimeerror(self):
        """Non-existent S3 key raises RuntimeError."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        with pytest.raises(RuntimeError, match="Failed to load taxonomy"):
            self.engine.load_taxonomy_from_s3(
                S3_BUCKET, "taxonomies/nonexistent.json", s3_client=s3
            )

    @mock_aws
    def test_load_taxonomies_from_s3_prefix_loads_multiple(self):
        """Multiple taxonomy files under prefix are all loaded."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        fraud_taxonomy = json.dumps(BANKING_FRAUD_TAXONOMY)
        tlp_taxonomy = json.dumps({
            "namespace": "tlp",
            "description": "Traffic Light Protocol",
            "predicates": [{"value": "color", "expanded": "TLP Color"}],
        })

        s3.put_object(Bucket=S3_BUCKET, Key="taxonomies/fraud.json", Body=fraud_taxonomy.encode())
        s3.put_object(Bucket=S3_BUCKET, Key="taxonomies/tlp.json", Body=tlp_taxonomy.encode())

        results = self.engine.load_taxonomies_from_s3_prefix(
            S3_BUCKET, "taxonomies/", s3_client=s3
        )

        assert len(results) == 2
        namespaces = {t.namespace for t in results}
        assert "fraud" in namespaces
        assert "tlp" in namespaces

    @mock_aws
    def test_load_taxonomies_from_s3_prefix_skips_non_json(self):
        """Non-JSON files under prefix are skipped."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        s3.put_object(
            Bucket=S3_BUCKET,
            Key="taxonomies/fraud.json",
            Body=json.dumps(BANKING_FRAUD_TAXONOMY).encode(),
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key="taxonomies/readme.txt",
            Body=b"This is not a taxonomy",
        )

        results = self.engine.load_taxonomies_from_s3_prefix(
            S3_BUCKET, "taxonomies/", s3_client=s3
        )

        assert len(results) == 1
        assert results[0].namespace == "fraud"

    @mock_aws
    def test_load_taxonomies_from_s3_prefix_skips_invalid_json(self):
        """Invalid JSON files are skipped with a warning, not raising."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        s3.put_object(
            Bucket=S3_BUCKET,
            Key="taxonomies/good.json",
            Body=json.dumps(BANKING_FRAUD_TAXONOMY).encode(),
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key="taxonomies/bad.json",
            Body=b"invalid json content",
        )

        results = self.engine.load_taxonomies_from_s3_prefix(
            S3_BUCKET, "taxonomies/", s3_client=s3
        )

        assert len(results) == 1
        assert results[0].namespace == "fraud"

    @mock_aws
    def test_load_taxonomies_from_s3_prefix_empty_returns_empty_list(self):
        """Empty prefix returns empty list."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        results = self.engine.load_taxonomies_from_s3_prefix(
            S3_BUCKET, "taxonomies/", s3_client=s3
        )

        assert results == []


# ---------------------------------------------------------------------------
# MITRE ATT&CK STIX loading from S3 (moto)
# ---------------------------------------------------------------------------


class TestLoadAttackTechniquesFromS3:
    """Tests for load_attack_techniques_from_s3 with moto."""

    def setup_method(self):
        self.engine = TaggingEngine()

    @mock_aws
    def test_load_attack_stix_parses_techniques(self):
        """Valid STIX bundle with attack-patterns extracts technique metadata."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=json.dumps(MINIMAL_ATTACK_STIX_BUNDLE).encode(),
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        assert "T1566" in result
        assert "T1078" in result
        assert len(result) == 2  # malware and no-external-id skipped

    @mock_aws
    def test_load_attack_stix_extracts_technique_name(self):
        """Technique name is correctly extracted."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=json.dumps(MINIMAL_ATTACK_STIX_BUNDLE).encode(),
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        assert result["T1566"]["name"] == "Phishing"
        assert result["T1078"]["name"] == "Valid Accounts"

    @mock_aws
    def test_load_attack_stix_extracts_tactics(self):
        """Kill chain phases are extracted as tactics list."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=json.dumps(MINIMAL_ATTACK_STIX_BUNDLE).encode(),
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        assert result["T1566"]["tactics"] == ["initial-access"]
        assert set(result["T1078"]["tactics"]) == {"defense-evasion", "persistence"}

    @mock_aws
    def test_load_attack_stix_skips_non_attack_patterns(self):
        """Objects that are not attack-patterns are ignored."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=json.dumps(MINIMAL_ATTACK_STIX_BUNDLE).encode(),
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        # Malware object should not appear in techniques
        technique_ids = list(result.keys())
        assert all(t.startswith("T") for t in technique_ids)

    @mock_aws
    def test_load_attack_stix_skips_non_mitre_external_refs(self):
        """Attack-patterns without mitre-attack source_name are skipped."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=json.dumps(MINIMAL_ATTACK_STIX_BUNDLE).encode(),
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        # "No External ID Pattern" has source_name="other-source" and should be skipped
        assert "X999" not in result

    @mock_aws
    def test_load_attack_stix_nonexistent_key_returns_empty(self):
        """Non-existent S3 key returns empty dict (graceful fallback)."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, "nonexistent-key.json", s3_client=s3
        )

        assert result == {}

    @mock_aws
    def test_load_attack_stix_invalid_json_returns_empty(self):
        """Invalid JSON in S3 returns empty dict (graceful fallback)."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=b"not valid json",
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        assert result == {}

    @mock_aws
    def test_load_attack_stix_empty_bundle_returns_empty(self):
        """Empty STIX bundle returns empty dict."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=json.dumps({"type": "bundle", "objects": []}).encode(),
        )

        result = self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        assert result == {}

    @mock_aws
    def test_load_attack_stix_stores_on_instance(self):
        """Loaded techniques are stored on the engine instance."""
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket=S3_BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=ATTACK_STIX_S3_KEY,
            Body=json.dumps(MINIMAL_ATTACK_STIX_BUNDLE).encode(),
        )

        self.engine.load_attack_techniques_from_s3(
            S3_BUCKET, ATTACK_STIX_S3_KEY, s3_client=s3
        )

        assert hasattr(self.engine, "_attack_techniques")
        assert "T1566" in self.engine._attack_techniques


# ---------------------------------------------------------------------------
# Validation edge cases
# ---------------------------------------------------------------------------


class TestTaxonomyValidationEdgeCases:
    """Edge cases for taxonomy JSON validation."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_non_object_json_raises_valueerror(self):
        """JSON that parses to a non-dict (e.g. list) raises ValueError."""
        with pytest.raises(ValueError, match="must be an object"):
            self.engine.load_taxonomy(json.dumps([1, 2, 3]))

    def test_null_json_raises_valueerror(self):
        """JSON null raises ValueError."""
        with pytest.raises(ValueError, match="must be an object"):
            self.engine.load_taxonomy("null")

    def test_numeric_json_raises_valueerror(self):
        """JSON number raises ValueError."""
        with pytest.raises(ValueError, match="must be an object"):
            self.engine.load_taxonomy("42")

    def test_empty_predicates_list_accepted(self):
        """Empty predicates list is technically valid (no predicates defined)."""
        taxonomy_json = json.dumps({
            "namespace": "empty",
            "predicates": [],
        })

        result = self.engine.load_taxonomy(taxonomy_json)

        assert result.namespace == "empty"
        assert result.predicates == []

    def test_taxonomy_replaces_existing_same_namespace(self):
        """Loading a taxonomy with same namespace replaces the previous one."""
        v1 = json.dumps({
            "namespace": "fraud",
            "version": 1,
            "predicates": [{"value": "type", "expanded": "Type"}],
        })
        v2 = json.dumps({
            "namespace": "fraud",
            "version": 2,
            "predicates": [
                {"value": "type", "expanded": "Type"},
                {"value": "target", "expanded": "Target"},
            ],
        })

        self.engine.load_taxonomy(v1)
        self.engine.load_taxonomy(v2)

        loaded = self.engine.get_loaded_taxonomies()
        assert loaded["fraud"].version == 2
        assert len(loaded["fraud"].predicates) == 2
