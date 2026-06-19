"""Unit tests for the Tagging Engine agent - taxonomy loading and severity mapping."""

import json

import pytest

from dark_web_fraud_agent.agents.tagging_engine import (
    MachineTag,
    TaggingEngine,
    TaxonomyDefinition,
    TaxonomyEntry,
    TaxonomyPredicate,
)
from dark_web_fraud_agent.models.shared import AgentConfig


class TestTaxonomyLoading:
    """Tests for load_taxonomy with valid and invalid inputs."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_load_valid_taxonomy_basic(self):
        """A valid taxonomy JSON loads successfully with correct namespace."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
                "description": "Banking fraud taxonomy",
                "version": 2,
                "predicates": [
                    {
                        "value": "type",
                        "expanded": "Fraud Type",
                        "entries": [
                            {"value": "phishing", "expanded": "Phishing Attack"},
                            {"value": "carding", "expanded": "Card Fraud"},
                        ],
                    }
                ],
            }
        )

        result = self.engine.load_taxonomy(taxonomy_json)

        assert isinstance(result, TaxonomyDefinition)
        assert result.namespace == "fraud"
        assert result.description == "Banking fraud taxonomy"
        assert result.version == 2
        assert len(result.predicates) == 1
        assert result.predicates[0].value == "type"
        assert result.predicates[0].expanded == "Fraud Type"
        assert len(result.predicates[0].entries) == 2
        assert result.predicates[0].entries[0].value == "phishing"
        assert result.predicates[0].entries[1].value == "carding"

    def test_load_taxonomy_multiple_predicates(self):
        """A taxonomy with multiple predicates loads all of them."""
        taxonomy_json = json.dumps(
            {
                "namespace": "threat-level",
                "description": "Threat level classification",
                "predicates": [
                    {"value": "severity", "expanded": "Severity Level"},
                    {"value": "impact", "expanded": "Impact Assessment"},
                ],
            }
        )

        result = self.engine.load_taxonomy(taxonomy_json)

        assert len(result.predicates) == 2
        assert result.predicates[0].value == "severity"
        assert result.predicates[1].value == "impact"

    def test_load_taxonomy_no_entries(self):
        """Predicates without entries load with empty entries list."""
        taxonomy_json = json.dumps(
            {
                "namespace": "simple",
                "description": "Minimal taxonomy",
                "predicates": [
                    {"value": "category", "expanded": "Category"},
                ],
            }
        )

        result = self.engine.load_taxonomy(taxonomy_json)

        assert result.predicates[0].entries == []

    def test_load_taxonomy_default_version(self):
        """Missing version field defaults to 1."""
        taxonomy_json = json.dumps(
            {
                "namespace": "test",
                "predicates": [{"value": "p", "expanded": "P"}],
            }
        )

        result = self.engine.load_taxonomy(taxonomy_json)

        assert result.version == 1

    def test_load_taxonomy_default_description(self):
        """Missing description field defaults to empty string."""
        taxonomy_json = json.dumps(
            {
                "namespace": "test",
                "predicates": [{"value": "p", "expanded": "P"}],
            }
        )

        result = self.engine.load_taxonomy(taxonomy_json)

        assert result.description == ""

    def test_load_taxonomy_stored_by_namespace(self):
        """Loaded taxonomies are accessible via get_loaded_taxonomies."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
                "description": "Fraud types",
                "predicates": [{"value": "type", "expanded": "Type"}],
            }
        )

        self.engine.load_taxonomy(taxonomy_json)
        loaded = self.engine.get_loaded_taxonomies()

        assert "fraud" in loaded
        assert loaded["fraud"].namespace == "fraud"

    def test_load_multiple_taxonomies(self):
        """Multiple taxonomies can be loaded and stored independently."""
        fraud_json = json.dumps(
            {
                "namespace": "fraud",
                "predicates": [{"value": "type", "expanded": "Fraud Type"}],
            }
        )
        tlp_json = json.dumps(
            {
                "namespace": "tlp",
                "predicates": [{"value": "color", "expanded": "TLP Color"}],
            }
        )

        self.engine.load_taxonomy(fraud_json)
        self.engine.load_taxonomy(tlp_json)

        loaded = self.engine.get_loaded_taxonomies()
        assert len(loaded) == 2
        assert "fraud" in loaded
        assert "tlp" in loaded

    def test_load_taxonomy_invalid_json_raises_valueerror(self):
        """Invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid taxonomy JSON"):
            self.engine.load_taxonomy("not valid json {{{")

    def test_load_taxonomy_empty_string_raises_valueerror(self):
        """Empty string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid taxonomy JSON"):
            self.engine.load_taxonomy("")

    def test_load_taxonomy_missing_namespace_raises_valueerror(self):
        """Missing 'namespace' field raises ValueError."""
        taxonomy_json = json.dumps(
            {
                "predicates": [{"value": "type", "expanded": "Type"}],
            }
        )

        with pytest.raises(ValueError, match="namespace"):
            self.engine.load_taxonomy(taxonomy_json)

    def test_load_taxonomy_missing_predicates_raises_valueerror(self):
        """Missing 'predicates' field raises ValueError."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
            }
        )

        with pytest.raises(ValueError, match="predicates"):
            self.engine.load_taxonomy(taxonomy_json)

    def test_load_taxonomy_predicates_not_list_raises_valueerror(self):
        """Non-list 'predicates' field raises ValueError."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
                "predicates": "not a list",
            }
        )

        with pytest.raises(ValueError, match="predicates"):
            self.engine.load_taxonomy(taxonomy_json)

    def test_load_taxonomy_predicate_missing_value_raises_valueerror(self):
        """Predicate without 'value' field raises ValueError."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
                "predicates": [{"expanded": "Type"}],
            }
        )

        with pytest.raises(ValueError, match="'value' and 'expanded'"):
            self.engine.load_taxonomy(taxonomy_json)

    def test_load_taxonomy_predicate_missing_expanded_raises_valueerror(self):
        """Predicate without 'expanded' field raises ValueError."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
                "predicates": [{"value": "type"}],
            }
        )

        with pytest.raises(ValueError, match="'value' and 'expanded'"):
            self.engine.load_taxonomy(taxonomy_json)

    def test_load_taxonomy_entry_missing_value_raises_valueerror(self):
        """Entry without 'value' field raises ValueError."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
                "predicates": [
                    {
                        "value": "type",
                        "expanded": "Type",
                        "entries": [{"expanded": "Phishing"}],
                    }
                ],
            }
        )

        with pytest.raises(ValueError, match="'value' and 'expanded'"):
            self.engine.load_taxonomy(taxonomy_json)

    def test_load_taxonomy_entry_missing_expanded_raises_valueerror(self):
        """Entry without 'expanded' field raises ValueError."""
        taxonomy_json = json.dumps(
            {
                "namespace": "fraud",
                "predicates": [
                    {
                        "value": "type",
                        "expanded": "Type",
                        "entries": [{"value": "phishing"}],
                    }
                ],
            }
        )

        with pytest.raises(ValueError, match="'value' and 'expanded'"):
            self.engine.load_taxonomy(taxonomy_json)


class TestSeverityMapping:
    """Tests for map_severity_to_threat_level."""

    def setup_method(self):
        self.engine = TaggingEngine()

    def test_severity_1_maps_to_low(self):
        assert self.engine.map_severity_to_threat_level(1) == "low"

    def test_severity_2_maps_to_low(self):
        assert self.engine.map_severity_to_threat_level(2) == "low"

    def test_severity_3_maps_to_low(self):
        assert self.engine.map_severity_to_threat_level(3) == "low"

    def test_severity_4_maps_to_medium(self):
        assert self.engine.map_severity_to_threat_level(4) == "medium"

    def test_severity_5_maps_to_medium(self):
        assert self.engine.map_severity_to_threat_level(5) == "medium"

    def test_severity_6_maps_to_medium(self):
        assert self.engine.map_severity_to_threat_level(6) == "medium"

    def test_severity_7_maps_to_high(self):
        assert self.engine.map_severity_to_threat_level(7) == "high"

    def test_severity_8_maps_to_high(self):
        assert self.engine.map_severity_to_threat_level(8) == "high"

    def test_severity_9_maps_to_high(self):
        assert self.engine.map_severity_to_threat_level(9) == "high"

    def test_severity_10_maps_to_critical(self):
        assert self.engine.map_severity_to_threat_level(10) == "critical"


class TestMachineTag:
    """Tests for MachineTag string representation."""

    def test_machine_tag_str(self):
        tag = MachineTag(namespace="fraud", predicate="type", value="phishing")
        assert str(tag) == 'fraud:type="phishing"'

    def test_machine_tag_fields(self):
        tag = MachineTag(namespace="tlp", predicate="color", value="red")
        assert tag.namespace == "tlp"
        assert tag.predicate == "color"
        assert tag.value == "red"


class TestTaggingEngineAgent:
    """Tests for TaggingEngine as an AgentBase implementation."""

    def test_default_config(self):
        engine = TaggingEngine()
        assert engine.config.agent_id == "tagging-engine"
        assert engine.config.agent_name == "Tagging Engine"

    def test_custom_config(self):
        config = AgentConfig(agent_id="custom-tagger", agent_name="Custom Tagger")
        engine = TaggingEngine(config=config)
        assert engine.config.agent_id == "custom-tagger"

    def test_health_returns_valid(self):
        engine = TaggingEngine()
        health = engine.get_health()
        assert health.agent_id == "tagging-engine"
        assert health.status == "healthy"

    def test_initial_taxonomies_empty(self):
        engine = TaggingEngine()
        assert engine.get_loaded_taxonomies() == {}
