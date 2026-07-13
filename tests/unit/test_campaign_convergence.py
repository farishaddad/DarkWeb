"""Unit tests for campaign convergence detection (Requirement 7.3).

Tests cover:
- DynamoDB-backed convergence tracking with TTL expiry
- OpenSearch vector similarity querying for related items
- Merged convergence detection (DynamoDB + OpenSearch)
- Consolidated campaign alert generation when 3+ items converge
- TTL epoch calculation for time window expiry

Uses moto for DynamoDB mocking and unittest.mock for OpenSearch.
"""

import os
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

import boto3
import moto
import pytest

from dark_web_fraud_agent.agents.alert_generator import (
    AlertGenerator,
    ConvergenceItem,
    _CONVERGENCE_THRESHOLD,
    _SIMILARITY_THRESHOLD,
)
from dark_web_fraud_agent.models.alerts import FraudAlert


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def dynamodb_table():
    """Create a mocked DynamoDB convergence table using moto."""
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="eu-west-2")
        client.create_table(
            TableName="dark-web-fraud-convergence",
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield boto3.resource("dynamodb", region_name="eu-west-2").Table(
            "dark-web-fraud-convergence"
        )


@pytest.fixture
def agent():
    """Create an AlertGenerator with a 24-hour convergence window."""
    return AlertGenerator(convergence_window=timedelta(hours=24))


@pytest.fixture
def mock_opensearch():
    """Create a mock OpenSearch client."""
    return MagicMock()


@pytest.fixture
def env_vars(monkeypatch):
    """Set environment variables for DynamoDB and OpenSearch."""
    monkeypatch.setenv("DYNAMODB_CONVERGENCE_TABLE", "dark-web-fraud-convergence")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    monkeypatch.setenv("OPENSEARCH_INDEX", "threat-intel")


# ---------------------------------------------------------------------------
# DynamoDB convergence tracking tests
# ---------------------------------------------------------------------------

class TestDynamoDBConvergenceTracking:
    """Test convergence tracking with DynamoDB (moto)."""

    def test_track_item_writes_to_dynamodb(self, dynamodb_table, env_vars):
        """track_item writes a TTP convergence item to DynamoDB with correct PK/SK."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            agent.track_item("stix-001", "mitre-attack:T1111", "indicator")

        # Verify item was written
        response = dynamodb_table.get_item(
            Key={"PK": "CONV#mitre-attack:T1111", "SK": "ITEM#stix-001"}
        )
        item = response["Item"]
        assert item["stix_id"] == "stix-001"
        assert item["ttp_reference"] == "mitre-attack:T1111"
        assert item["tier"] == "indicator"
        assert "TTL" in item
        assert "timestamp" in item

    def test_track_item_ttl_within_convergence_window(self, dynamodb_table, env_vars):
        """TTL epoch is set to current time + convergence_window."""
        window = timedelta(hours=12)
        agent = AlertGenerator(convergence_window=window)

        before = datetime.now(UTC)
        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            agent.track_item("stix-001", "ttp-test", "observable")
        after = datetime.now(UTC)

        response = dynamodb_table.get_item(
            Key={"PK": "CONV#ttp-test", "SK": "ITEM#stix-001"}
        )
        ttl = int(response["Item"]["TTL"])
        expected_min = int((before + window).timestamp())
        expected_max = int((after + window).timestamp())
        assert expected_min <= ttl <= expected_max

    def test_track_multiple_items_same_ttp(self, dynamodb_table, env_vars):
        """Multiple items with the same TTP reference are stored with distinct sort keys."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            agent.track_item("stix-001", "fraud:money_mule", "observable")
            agent.track_item("stix-002", "fraud:money_mule", "indicator")
            agent.track_item("stix-003", "fraud:money_mule", "ttp")

        # Query all items under the TTP partition
        from boto3.dynamodb.conditions import Key
        resp = dynamodb_table.query(
            KeyConditionExpression=Key("PK").eq("CONV#fraud:money_mule")
        )
        assert len(resp["Items"]) == 3

    def test_track_item_with_entity_values_writes_entity_pk(self, dynamodb_table, env_vars):
        """Entity values are indexed in DynamoDB with ENTITY# PK namespace."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            agent.track_item(
                "stix-001",
                "fraud:money_mule",
                "observable",
                entity_values=[{"entity_type": "bank_name", "value": "HSBC"}],
            )

        # Check entity PK was written
        response = dynamodb_table.get_item(
            Key={"PK": "ENTITY#bank_name#hsbc", "SK": "ITEM#stix-001"}
        )
        assert "Item" in response
        assert response["Item"]["entity_value"] == "hsbc"


class TestDynamoDBConvergenceDetection:
    """Test check_campaign_convergence with DynamoDB (moto)."""

    def test_no_convergence_with_zero_items(self, dynamodb_table, env_vars):
        """No items in DynamoDB → no convergence."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            with patch.object(agent, "query_opensearch_similar_items", return_value=[]):
                result = agent.check_campaign_convergence("ttp-unknown")

        assert result is None

    def test_no_convergence_with_two_items(self, dynamodb_table, env_vars):
        """Fewer than 3 items → no convergence."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            with patch.object(agent, "query_opensearch_similar_items", return_value=[]):
                agent.track_item("stix-001", "fraud:mfa_bypass", "indicator")
                agent.track_item("stix-002", "fraud:mfa_bypass", "observable")
                result = agent.check_campaign_convergence("fraud:mfa_bypass")

        assert result is None

    def test_convergence_with_three_items(self, dynamodb_table, env_vars):
        """Exactly 3 items with same TTP → convergence detected."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            with patch.object(agent, "query_opensearch_similar_items", return_value=[]):
                agent.track_item("stix-001", "fraud:mfa_bypass", "indicator")
                agent.track_item("stix-002", "fraud:mfa_bypass", "observable")
                agent.track_item("stix-003", "fraud:mfa_bypass", "ttp")
                result = agent.check_campaign_convergence("fraud:mfa_bypass")

        assert result is not None
        assert len(result) == 3
        assert set(result) == {"stix-001", "stix-002", "stix-003"}

    def test_convergence_with_five_items(self, dynamodb_table, env_vars):
        """More than 3 items still returns all converging IDs."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            with patch.object(agent, "query_opensearch_similar_items", return_value=[]):
                for i in range(5):
                    agent.track_item(f"stix-{i:03d}", "fraud:cnp", "indicator")
                result = agent.check_campaign_convergence("fraud:cnp")

        assert result is not None
        assert len(result) == 5

    def test_convergence_isolated_per_ttp(self, dynamodb_table, env_vars):
        """Convergence is per-TTP — items from different TTPs don't mix."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            with patch.object(agent, "query_opensearch_similar_items", return_value=[]):
                # 3 items for TTP-A
                for i in range(3):
                    agent.track_item(f"stix-a{i}", "fraud:ttp_a", "indicator")
                # 2 items for TTP-B
                for i in range(2):
                    agent.track_item(f"stix-b{i}", "fraud:ttp_b", "observable")

                assert agent.check_campaign_convergence("fraud:ttp_a") is not None
                assert agent.check_campaign_convergence("fraud:ttp_b") is None


# ---------------------------------------------------------------------------
# OpenSearch vector similarity query tests
# ---------------------------------------------------------------------------

class TestOpenSearchSimilarityQuery:
    """Test query_opensearch_similar_items with mocked OpenSearch client."""

    def test_returns_empty_when_no_client(self, env_vars):
        """Returns empty list when OpenSearch is not configured."""
        agent = AlertGenerator(opensearch_client=None)
        # Ensure no OPENSEARCH_ENDPOINT env var
        os.environ.pop("OPENSEARCH_ENDPOINT", None)
        result = agent.query_opensearch_similar_items("fraud:mfa_bypass")
        assert result == []

    def test_keyword_search_returns_stix_ids(self, env_vars):
        """Keyword search returns STIX IDs from matching documents."""
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_score": 5.2, "_source": {"stix_id": "stix-os-001", "ttp_reference": "fraud:mfa_bypass", "tier": "indicator"}},
                    {"_score": 4.1, "_source": {"stix_id": "stix-os-002", "ttp_reference": "fraud:mfa_bypass", "tier": "observable"}},
                ]
            }
        }

        agent = AlertGenerator(opensearch_client=mock_client)
        result = agent.query_opensearch_similar_items("fraud:mfa_bypass")

        assert result == ["stix-os-001", "stix-os-002"]
        mock_client.search.assert_called_once()

    def test_vector_search_filters_by_similarity_threshold(self, env_vars):
        """k-NN search filters out results below the similarity threshold."""
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_score": 0.92, "_source": {"stix_id": "stix-high", "ttp_reference": "T1111", "tier": "ttp"}},
                    {"_score": 0.80, "_source": {"stix_id": "stix-med", "ttp_reference": "T1111", "tier": "indicator"}},
                    {"_score": 0.50, "_source": {"stix_id": "stix-low", "ttp_reference": "T1111", "tier": "observable"}},
                ]
            }
        }

        agent = AlertGenerator(opensearch_client=mock_client)
        embedding = [0.1] * 768  # Dummy embedding vector
        result = agent.query_opensearch_similar_items("T1111", embedding_vector=embedding)

        # Only items with score >= 0.75 should be returned
        assert "stix-high" in result
        assert "stix-med" in result
        assert "stix-low" not in result

    def test_vector_search_uses_knn_query(self, env_vars):
        """When embedding_vector is provided, k-NN query is used."""
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": []}}

        agent = AlertGenerator(opensearch_client=mock_client)
        embedding = [0.5] * 256
        agent.query_opensearch_similar_items("T1078", embedding_vector=embedding, top_k=10)

        call_kwargs = mock_client.search.call_args.kwargs
        body = call_kwargs["body"]
        assert "knn" in str(body)
        assert body["size"] == 10

    def test_keyword_search_uses_bool_query(self, env_vars):
        """When no embedding_vector, keyword match query is used."""
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": []}}

        agent = AlertGenerator(opensearch_client=mock_client)
        agent.query_opensearch_similar_items("fraud:money_mule")

        call_kwargs = mock_client.search.call_args.kwargs
        body = call_kwargs["body"]
        assert "bool" in str(body)
        assert "match" in str(body)

    def test_handles_opensearch_error_gracefully(self, env_vars):
        """OpenSearch errors are caught and an empty list is returned."""
        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("Connection refused")

        agent = AlertGenerator(opensearch_client=mock_client)
        result = agent.query_opensearch_similar_items("fraud:test")

        assert result == []

    def test_skips_hits_without_stix_id(self, env_vars):
        """Hits without a stix_id field are skipped."""
        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_score": 5.0, "_source": {"ttp_reference": "T1111", "tier": "indicator"}},
                    {"_score": 4.0, "_source": {"stix_id": "stix-valid", "ttp_reference": "T1111", "tier": "observable"}},
                ]
            }
        }

        agent = AlertGenerator(opensearch_client=mock_client)
        result = agent.query_opensearch_similar_items("T1111")

        assert result == ["stix-valid"]

    def test_uses_correct_index_name(self, env_vars, monkeypatch):
        """Uses OPENSEARCH_INDEX env var for the index name."""
        monkeypatch.setenv("OPENSEARCH_INDEX", "custom-intel-index")
        mock_client = MagicMock()
        mock_client.search.return_value = {"hits": {"hits": []}}

        agent = AlertGenerator(opensearch_client=mock_client)
        agent.query_opensearch_similar_items("T1078")

        call_kwargs = mock_client.search.call_args.kwargs
        assert call_kwargs["index"] == "custom-intel-index"


# ---------------------------------------------------------------------------
# Merged convergence (DynamoDB + OpenSearch)
# ---------------------------------------------------------------------------

class TestMergedConvergenceDetection:
    """Test convergence detection combining DynamoDB and OpenSearch results."""

    def test_opensearch_adds_to_dynamodb_items_for_convergence(self, dynamodb_table, env_vars):
        """OpenSearch results are merged with DynamoDB items to reach threshold."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            # Only 2 items in DynamoDB — not enough alone
            agent.track_item("stix-001", "fraud:phishing", "indicator")
            agent.track_item("stix-002", "fraud:phishing", "observable")

            # OpenSearch returns 1 additional related item
            with patch.object(
                agent, "query_opensearch_similar_items", return_value=["stix-os-003"]
            ):
                result = agent.check_campaign_convergence("fraud:phishing")

        # 2 (DynamoDB) + 1 (OpenSearch) = 3 → convergence
        assert result is not None
        assert len(result) == 3
        assert "stix-001" in result
        assert "stix-002" in result
        assert "stix-os-003" in result

    def test_deduplicate_opensearch_and_dynamodb_results(self, dynamodb_table, env_vars):
        """Duplicate IDs from OpenSearch and DynamoDB are deduplicated."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            agent.track_item("stix-001", "fraud:ato", "indicator")
            agent.track_item("stix-002", "fraud:ato", "observable")
            agent.track_item("stix-003", "fraud:ato", "ttp")

            # OpenSearch returns duplicates of DynamoDB items
            with patch.object(
                agent, "query_opensearch_similar_items", return_value=["stix-001", "stix-002"]
            ):
                result = agent.check_campaign_convergence("fraud:ato")

        # Should be deduplicated to 3, not 5
        assert result is not None
        assert len(result) == 3

    def test_only_opensearch_results_can_trigger_convergence(self, dynamodb_table, env_vars):
        """Even with zero DynamoDB items, OpenSearch alone can trigger convergence."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            # No items tracked in DynamoDB
            with patch.object(
                agent,
                "query_opensearch_similar_items",
                return_value=["stix-os-1", "stix-os-2", "stix-os-3"],
            ):
                result = agent.check_campaign_convergence("fraud:test")

        assert result is not None
        assert len(result) == 3

    def test_below_threshold_even_with_opensearch(self, dynamodb_table, env_vars):
        """Combined results still below 3 → no convergence."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            agent.track_item("stix-001", "fraud:test", "indicator")

            with patch.object(
                agent, "query_opensearch_similar_items", return_value=["stix-os-1"]
            ):
                result = agent.check_campaign_convergence("fraud:test")

        # 1 (DynamoDB) + 1 (OpenSearch) = 2 → no convergence
        assert result is None


# ---------------------------------------------------------------------------
# Campaign alert generation on convergence
# ---------------------------------------------------------------------------

class TestCampaignAlertOnConvergence:
    """Test that convergence triggers a properly structured campaign alert."""

    def test_campaign_alert_generated_on_convergence(self, dynamodb_table, env_vars):
        """When convergence is detected, generate_campaign_alert produces a valid alert."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        with patch.object(agent, "_get_convergence_table", return_value=dynamodb_table):
            with patch.object(agent, "query_opensearch_similar_items", return_value=[]):
                agent.track_item("stix-001", "mitre-attack:T1078", "indicator")
                agent.track_item("stix-002", "mitre-attack:T1078", "observable")
                agent.track_item("stix-003", "mitre-attack:T1078", "ttp")

                converged = agent.check_campaign_convergence("mitre-attack:T1078")

        assert converged is not None

        alert = agent.generate_campaign_alert(
            ttp_reference="mitre-attack:T1078",
            ttp_description="Account takeover using valid credentials from dark web dump",
            affected_institutions=["HSBC", "Barclays"],
            related_ids=converged,
            source_url="http://darkforum.onion/post/12345",
            crawl_timestamp=datetime.now(UTC) - timedelta(minutes=15),
        )

        assert isinstance(alert, FraudAlert)
        assert alert.alert_type == "campaign_alert"
        assert alert.severity == "high"
        assert len(alert.related_intelligence) == 3
        assert "HSBC" in alert.affected_institutions
        assert alert.provenance.original_source_url == "http://darkforum.onion/post/12345"

    def test_campaign_alert_includes_sigma_detection_rule(self, dynamodb_table, env_vars):
        """Campaign alert includes a Sigma detection rule referencing the TTP."""
        agent = AlertGenerator(convergence_window=timedelta(hours=24))

        alert = agent.generate_campaign_alert(
            ttp_reference="mitre-attack:technique=\"T1566\"",
            ttp_description="Phishing kit deployment targeting UK banks",
            affected_institutions=["NatWest"],
            related_ids=["stix-001", "stix-002", "stix-003"],
            source_url="http://example.onion",
            crawl_timestamp=datetime.now(UTC),
        )

        assert len(alert.recommended_detection_rules) == 1
        rule = alert.recommended_detection_rules[0]
        assert rule.rule_type == "sigma"
        assert "T1566" in rule.rule_content
        assert rule.confidence == 0.8

    def test_campaign_alert_links_all_related_items(self):
        """Campaign alert's related_intelligence contains all converging item IDs."""
        agent = AlertGenerator()
        related = ["stix-a", "stix-b", "stix-c", "stix-d"]

        alert = agent.generate_campaign_alert(
            ttp_reference="fraud:cnp_fraud",
            ttp_description="Card-not-present fraud convergence",
            affected_institutions=[],
            related_ids=related,
            source_url="http://market.onion",
            crawl_timestamp=datetime.now(UTC),
        )

        assert alert.related_intelligence == related
        assert len(alert.related_intelligence) == 4

    def test_campaign_alert_provenance_chain(self):
        """Alert provenance includes full pipeline processing chain."""
        agent = AlertGenerator()

        alert = agent.generate_campaign_alert(
            ttp_reference="T1111",
            ttp_description="MFA bypass",
            affected_institutions=["Monzo"],
            related_ids=["stix-001", "stix-002", "stix-003"],
            source_url="http://forum.onion/thread/789",
            crawl_timestamp=datetime.now(UTC) - timedelta(hours=1),
        )

        chain = alert.provenance.processing_chain
        assert chain == [
            "crawling-engine",
            "content-analyst",
            "data-structurer",
            "tagging-engine",
            "alert-generator",
        ]


# ---------------------------------------------------------------------------
# TTL and time window expiry (in-memory)
# ---------------------------------------------------------------------------

class TestTTLTimeWindowExpiry:
    """Test TTL-based time window expiry logic (in-memory tracker)."""

    def test_items_outside_window_are_pruned(self):
        """Items older than convergence_window are pruned before convergence check."""
        agent = AlertGenerator(convergence_window=timedelta(hours=1))

        # Manually add expired items
        expired_time = datetime.now(UTC) - timedelta(hours=2)
        agent._convergence_tracker["ttp-test"] = [
            ConvergenceItem("stix-old-1", "ttp-test", "indicator", expired_time),
            ConvergenceItem("stix-old-2", "ttp-test", "observable", expired_time),
            ConvergenceItem("stix-old-3", "ttp-test", "ttp", expired_time),
        ]

        # Pruning should remove them
        agent._prune_expired("ttp-test")
        assert len(agent._convergence_tracker["ttp-test"]) == 0

    def test_fresh_items_survive_pruning(self):
        """Items within the convergence window are kept after pruning."""
        agent = AlertGenerator(convergence_window=timedelta(hours=2))

        recent_time = datetime.now(UTC) - timedelta(minutes=30)
        agent._convergence_tracker["ttp-test"] = [
            ConvergenceItem("stix-fresh", "ttp-test", "indicator", recent_time),
        ]

        agent._prune_expired("ttp-test")
        assert len(agent._convergence_tracker["ttp-test"]) == 1
        assert agent._convergence_tracker["ttp-test"][0].stix_id == "stix-fresh"

    def test_mixed_fresh_and_expired_items(self):
        """Only expired items are pruned; fresh items remain."""
        agent = AlertGenerator(convergence_window=timedelta(hours=1))

        old_time = datetime.now(UTC) - timedelta(hours=3)
        fresh_time = datetime.now(UTC) - timedelta(minutes=10)

        agent._convergence_tracker["ttp-mix"] = [
            ConvergenceItem("stix-old", "ttp-mix", "indicator", old_time),
            ConvergenceItem("stix-fresh-1", "ttp-mix", "observable", fresh_time),
            ConvergenceItem("stix-fresh-2", "ttp-mix", "ttp", fresh_time),
        ]

        agent._prune_expired("ttp-mix")
        ids = [item.stix_id for item in agent._convergence_tracker["ttp-mix"]]
        assert "stix-old" not in ids
        assert "stix-fresh-1" in ids
        assert "stix-fresh-2" in ids


# ---------------------------------------------------------------------------
# OpenSearch client initialization
# ---------------------------------------------------------------------------

class TestOpenSearchClientInit:
    """Test _get_opensearch_client initialization logic."""

    def test_returns_injected_client(self):
        """When opensearch_client is injected, it is returned directly."""
        mock_client = MagicMock()
        agent = AlertGenerator(opensearch_client=mock_client)
        assert agent._get_opensearch_client() is mock_client

    def test_returns_none_when_no_endpoint(self, monkeypatch):
        """When OPENSEARCH_ENDPOINT is not set, returns None."""
        monkeypatch.delenv("OPENSEARCH_ENDPOINT", raising=False)
        agent = AlertGenerator(opensearch_client=None)
        assert agent._get_opensearch_client() is None

    def test_returns_none_on_import_error(self, monkeypatch):
        """If opensearch-py is not importable, returns None gracefully."""
        monkeypatch.setenv("OPENSEARCH_ENDPOINT", "https://test.eu-west-2.aoss.amazonaws.com")
        agent = AlertGenerator(opensearch_client=None)

        with patch("builtins.__import__", side_effect=ImportError("no module")):
            result = agent._get_opensearch_client()

        # The exception is caught and None returned
        assert result is None
