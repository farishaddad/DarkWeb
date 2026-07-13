"""Unit tests for cross-entity co-occurrence detection (CHAPS-026 pattern).

AlertGenerator.check_entity_cooccurrence() fires a composite alert when the
same institution name appears in signals from two different intelligence tiers
(e.g. a Source 1 credential listing and a Source 2 mule-recruitment post).

These tests use the in-memory _convergence_tracker via track_item() with the
entity_values parameter, mirroring how unit tests work in test_alert_generator.py.

Note: Production co-occurrence uses DynamoDB (ENTITY# PK namespace). For unit
tests, we test the tier-diversity logic directly on the in-memory tracker by
simulating what DynamoDB would return via check_entity_cooccurrence on a patched
table, then separately test track_item entity routing logic.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from dark_web_fraud_agent.agents.alert_generator import (
    AlertGenerator,
    ConvergenceItem,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent(window_hours: int = 24) -> AlertGenerator:
    return AlertGenerator(convergence_window=timedelta(hours=window_hours))


def _bank_entity(name: str) -> dict:
    return {"entity_type": "bank_name", "value": name}


# ---------------------------------------------------------------------------
# track_item — entity_values parameter
# ---------------------------------------------------------------------------

class TestTrackItemEntityValues:
    """track_item routes entity values to DynamoDB when entity_values is provided."""

    def test_track_item_without_entity_values_works(self):
        """Original signature with no entity_values still works (backward compat)."""
        agent = _make_agent()
        # Should not raise; in-memory path used when no DynamoDB
        agent.track_item("stix-001", "fraud:money_mule", "observable")
        assert "fraud:money_mule" in agent._convergence_tracker

    def test_track_item_with_entity_values_none_works(self):
        """entity_values=None is treated the same as omitting the parameter."""
        agent = _make_agent()
        agent.track_item("stix-001", "fraud:money_mule", "observable", entity_values=None)
        assert "fraud:money_mule" in agent._convergence_tracker

    def test_track_item_entity_values_passed_to_dynamodb(self):
        """When entity_values contains a bank_name, it is written to DynamoDB."""
        agent = _make_agent()
        mock_table = MagicMock()

        with patch.object(agent, "_get_convergence_table", return_value=mock_table):
            agent.track_item(
                stix_id="stix-001",
                ttp_reference="fraud:money_mule",
                tier="observable",
                entity_values=[_bank_entity("HSBC")],
            )

        # put_item should be called twice: once for the TTP PK, once for the entity PK
        assert mock_table.put_item.call_count == 2
        calls = [c.kwargs["Item"] for c in mock_table.put_item.call_args_list]
        pks = [c["PK"] for c in calls]
        assert any("CONV#fraud:money_mule" == pk for pk in pks)
        assert any(pk.startswith("ENTITY#bank_name#hsbc") for pk in pks)

    def test_non_bank_name_entities_not_indexed(self):
        """Only bank_name entities are indexed for co-occurrence; others are skipped."""
        agent = _make_agent()
        mock_table = MagicMock()

        with patch.object(agent, "_get_convergence_table", return_value=mock_table):
            agent.track_item(
                stix_id="stix-001",
                ttp_reference="fraud:cnp_fraud",
                tier="observable",
                entity_values=[
                    {"entity_type": "bin_range", "value": "453200"},
                    {"entity_type": "btc_wallet", "value": "bc1qtest"},
                    {"entity_type": "ip_address", "value": "10.0.0.1"},
                ],
            )

        # Only the TTP PK write — no entity index writes
        assert mock_table.put_item.call_count == 1

    def test_multiple_bank_names_each_indexed(self):
        """Multiple bank_name entities in one signal each get their own DynamoDB entry."""
        agent = _make_agent()
        mock_table = MagicMock()

        with patch.object(agent, "_get_convergence_table", return_value=mock_table):
            agent.track_item(
                stix_id="stix-001",
                ttp_reference="fraud:money_mule",
                tier="observable",
                entity_values=[
                    _bank_entity("Barclays"),
                    _bank_entity("HSBC"),
                    _bank_entity("NatWest"),
                ],
            )

        # 1 TTP PK + 3 entity PKs = 4 put_item calls
        assert mock_table.put_item.call_count == 4
        calls = [c.kwargs["Item"]["PK"] for c in mock_table.put_item.call_args_list]
        assert "ENTITY#bank_name#barclays" in calls
        assert "ENTITY#bank_name#hsbc" in calls
        assert "ENTITY#bank_name#natwest" in calls

    def test_entity_value_lowercased_in_pk(self):
        """Bank names are lowercased in the DynamoDB PK for case-insensitive lookup."""
        agent = _make_agent()
        mock_table = MagicMock()

        with patch.object(agent, "_get_convergence_table", return_value=mock_table):
            agent.track_item(
                stix_id="stix-001",
                ttp_reference="fraud:money_mule",
                tier="ttp",
                entity_values=[_bank_entity("BARCLAYS BANK PLC")],
            )

        pks = [c.kwargs["Item"]["PK"] for c in mock_table.put_item.call_args_list]
        assert "ENTITY#bank_name#barclays bank plc" in pks


# ---------------------------------------------------------------------------
# check_entity_cooccurrence — tier diversity logic
# ---------------------------------------------------------------------------

class TestCheckEntityCooccurrence:
    """check_entity_cooccurrence fires only when ≥2 distinct tiers are present."""

    def _mock_dynamodb_items(self, items: list[dict]) -> MagicMock:
        """Build a mock DynamoDB table that returns the given items list."""
        table = MagicMock()
        table.query.return_value = {"Items": items}
        return table

    def test_no_items_returns_none(self):
        agent = _make_agent()
        table = self._mock_dynamodb_items([])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            result = agent.check_entity_cooccurrence("bank_name", "HSBC")
        assert result is None

    def test_single_item_returns_none(self):
        """One signal for an institution is not enough to trigger composite alert."""
        agent = _make_agent()
        table = self._mock_dynamodb_items([
            {"stix_id": "stix-001", "tier": "observable"},
        ])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            result = agent.check_entity_cooccurrence("bank_name", "HSBC")
        assert result is None

    def test_two_items_same_tier_returns_none(self):
        """Two signals from the SAME tier do not trigger composite alert."""
        agent = _make_agent()
        table = self._mock_dynamodb_items([
            {"stix_id": "stix-001", "tier": "observable"},
            {"stix_id": "stix-002", "tier": "observable"},
        ])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            result = agent.check_entity_cooccurrence("bank_name", "HSBC")
        assert result is None

    def test_two_items_different_tiers_fires(self):
        """CHAPS-026 composite: credential (observable) + mule script (ttp) → alert."""
        agent = _make_agent()
        table = self._mock_dynamodb_items([
            {"stix_id": "stix-credential", "tier": "observable"},
            {"stix_id": "stix-mule-script", "tier": "ttp"},
        ])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            result = agent.check_entity_cooccurrence("bank_name", "HSBC")
        assert result is not None
        assert "stix-credential" in result
        assert "stix-mule-script" in result

    def test_three_items_two_tiers_fires(self):
        """More than 2 items spanning 2 tiers still fires."""
        agent = _make_agent()
        table = self._mock_dynamodb_items([
            {"stix_id": "stix-001", "tier": "observable"},
            {"stix_id": "stix-002", "tier": "observable"},
            {"stix_id": "stix-003", "tier": "indicator"},
        ])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            result = agent.check_entity_cooccurrence("bank_name", "Barclays")
        assert result is not None
        assert len(result) == 3

    def test_all_three_tiers_fires(self):
        """Three signals each from a different tier all fire."""
        agent = _make_agent()
        table = self._mock_dynamodb_items([
            {"stix_id": "stix-001", "tier": "observable"},
            {"stix_id": "stix-002", "tier": "indicator"},
            {"stix_id": "stix-003", "tier": "ttp"},
        ])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            result = agent.check_entity_cooccurrence("bank_name", "NatWest")
        assert result is not None
        assert len(result) == 3

    def test_query_uses_correct_pk(self):
        """DynamoDB is queried with the ENTITY# PK format, lowercased."""
        agent = _make_agent()
        table = self._mock_dynamodb_items([])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            agent.check_entity_cooccurrence("bank_name", "BARCLAYS")
        table.query.assert_called_once()
        call_kwargs = table.query.call_args.kwargs
        # KeyConditionExpression should reference the lowercased entity PK
        expr_str = str(call_kwargs.get("KeyConditionExpression", ""))
        assert "bank_name" in expr_str
        assert "barclays" in expr_str

    def test_case_insensitive_lookup(self):
        """entity_value is lowercased before DynamoDB query."""
        agent = _make_agent()
        table = self._mock_dynamodb_items([
            {"stix_id": "stix-001", "tier": "observable"},
            {"stix_id": "stix-002", "tier": "ttp"},
        ])
        with patch.object(agent, "_get_convergence_table", return_value=table):
            # "HSBC" and "hsbc" should produce the same query
            result_upper = agent.check_entity_cooccurrence("bank_name", "HSBC")
            result_lower = agent.check_entity_cooccurrence("bank_name", "hsbc")
        # Both should fire (same DynamoDB query outcome for both)
        assert result_upper is not None
        assert result_lower is not None


# ---------------------------------------------------------------------------
# Extended ATT&CK tagging for new categories
# ---------------------------------------------------------------------------

class TestExtendedAttackTagsInAlertGenerator:
    """Verify Sigma maps include entries for all 5 new fraud categories."""

    from dark_web_fraud_agent.agents import alert_generator as _ag_module

    def test_sigma_logsource_map_covers_new_techniques(self):
        from dark_web_fraud_agent.agents.alert_generator import _SIGMA_LOGSOURCE_MAP
        for tid in ("T1136", "T1499", "T1531", "T1583", "T1598"):
            assert tid in _SIGMA_LOGSOURCE_MAP, f"Missing Sigma logsource entry for {tid}"

    def test_sigma_title_map_covers_new_techniques(self):
        from dark_web_fraud_agent.agents.alert_generator import _SIGMA_TITLE_MAP
        for tid in ("T1136", "T1499", "T1531", "T1583", "T1598"):
            assert tid in _SIGMA_TITLE_MAP, f"Missing Sigma title entry for {tid}"

    @pytest.mark.parametrize("technique,expected_fragment", [
        ("T1136", "New Account Fraud"),
        ("T1499", "Recurring Billing"),
        ("T1531", "Money Mule"),
        ("T1583", "Investment Fraud"),
        ("T1598", "Social Engineering"),
    ])
    def test_sigma_title_describes_pattern(self, technique, expected_fragment):
        from dark_web_fraud_agent.agents.alert_generator import _SIGMA_TITLE_MAP
        title = _SIGMA_TITLE_MAP[technique]
        assert expected_fragment in title, (
            f"Title for {technique} ({title!r}) missing expected fragment {expected_fragment!r}"
        )
