"""Comprehensive unit tests for all four Lambda handler functions.

Agents tested:
- content_analyst.handler
- data_structurer.handler
- tagging_engine.handler
- alert_generator.handler

Uses moto (@mock_aws) for S3/DynamoDB/SNS mocking and unittest.mock.patch
for Bedrock invoke_model calls.
"""

import io
import json
import os
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

TEST_BUCKET = "darkweb-test-bucket"
TEST_S3_KEY = "crawl-artifacts/2026/01/15/abc123/sample.txt"
TEST_EXECUTION_ID = "arn:aws:states:us-east-1:123456789012:execution:pipeline:test-exec"


def _bedrock_response_body(payload: dict) -> dict:
    """Build a mocked Bedrock invoke_model response dict."""
    body_bytes = json.dumps(payload).encode("utf-8")
    return {"body": io.BytesIO(body_bytes)}


def _combined_analysis_response(
    *,
    is_fraud_relevant: bool = True,
    confidence: float = 0.92,
    entities: list | None = None,
    fraud_category: str | None = "mfa_bypass",
    affected_institutions: list | None = None,
    guardrail_action: str | None = None,
) -> dict:
    """Build a complete Bedrock response for classify_and_extract_combined."""
    content_json = json.dumps({
        "is_fraud_relevant": is_fraud_relevant,
        "confidence": confidence,
        "reasoning": "Test response",
        "entities": entities or [
            {"entity_type": "ip_address", "value": "192.168.1.1",
             "context": "found at IP 192.168.1.1 in logs", "confidence": 0.95},
            {"entity_type": "bank_name", "value": "TestBank",
             "context": "targeting TestBank customers", "confidence": 0.9},
        ],
        "affected_institutions": affected_institutions or ["TestBank"],
        "estimated_record_count": None,
        "fraud_category": fraud_category,
    })
    payload = {"content": [{"text": content_json}]}
    if guardrail_action:
        payload["amazon-bedrock-guardrailAction"] = guardrail_action
    return _bedrock_response_body(payload)


@pytest.fixture
def env_vars():
    """Set required environment variables for all handlers."""
    env = {
        "BEDROCK_MODEL_ID": "anthropic.claude-opus-4-8-20260601-v1:0",
        "GUARDRAIL_ID": "test-guardrail-id",
        "KNOWLEDGE_BASE_ID": "test-kb-id",
        "CONFIDENCE_THRESHOLD": "0.7",
        "S3_BUCKET": TEST_BUCKET,
        "OPENSEARCH_ENDPOINT": "https://test-opensearch.us-east-1.aoss.amazonaws.com",
        "OPENSEARCH_INDEX": "threat-intel",
        "MISP_URL": "https://misp.test",
        "MISP_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:misp-api-key",
        "BEDROCK_EMBEDDING_MODEL_ID": "amazon.titan-embed-text-v2:0",
        "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:fraud-alerts",
        "HIGH_SEVERITY_THRESHOLD": "7",
        "DYNAMODB_CONVERGENCE_TABLE": "dark-web-fraud-convergence",
        "GUARDRAIL_VERSION": "1",
    }
    with patch.dict(os.environ, env, clear=False):
        yield env


@pytest.fixture
def s3_bucket_with_artifact():
    """Create a mocked S3 bucket with a sample artifact."""
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)
        s3.put_object(
            Bucket=TEST_BUCKET,
            Key=TEST_S3_KEY,
            Body=b"MFA bypass technique: use SIM swap to intercept OTP codes. "
                 b"Targeting TestBank. IP: 192.168.1.1",
        )
        yield s3


# ===========================================================================
# 1. CONTENT ANALYST HANDLER TESTS
# ===========================================================================


class TestContentAnalystHandler:
    """Tests for dark_web_fraud_agent.agents.content_analyst.handler."""

    @mock_aws
    def test_content_analyst_happy_path(self, env_vars):
        """S3 artifact fetched, classify_and_extract_combined called once, returns expected fields."""
        # Setup S3
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)
        s3.put_object(
            Bucket=TEST_BUCKET,
            Key=TEST_S3_KEY,
            Body=b"MFA bypass technique: use SIM swap to intercept OTP codes.",
        )

        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.return_value = _combined_analysis_response(
            is_fraud_relevant=True,
            confidence=0.92,
            fraud_category="mfa_bypass",
            entities=[
                {"entity_type": "ip_address", "value": "10.0.0.1",
                 "context": "server at 10.0.0.1", "confidence": 0.95},
            ],
        )

        with patch(
            "dark_web_fraud_agent.agents.content_analyst._bedrock_client",
            mock_bedrock,
        ):
            from dark_web_fraud_agent.agents.content_analyst import handler

            result = handler(
                {"s3_key": TEST_S3_KEY, "execution_id": TEST_EXECUTION_ID},
                None,
            )

        # classify_and_extract_combined is called once (not 3x)
        assert mock_bedrock.invoke_model.call_count == 1

        # Validate returned structure
        assert result["is_fraud_relevant"] is True
        assert result["confidence"] == pytest.approx(0.92)
        assert result["fraud_category"] == "mfa_bypass"
        assert result["s3_key"] == TEST_S3_KEY
        assert result["execution_id"] == TEST_EXECUTION_ID
        assert isinstance(result["entities"], list)
        assert len(result["entities"]) >= 1
        assert result["entities"][0]["entity_type"] == "ip_address"
        assert result["severity_score"] >= 1
        assert "requires_manual_review" in result

    @mock_aws
    def test_content_analyst_non_fraud_content(self, env_vars):
        """Non-fraud content returns is_fraud_relevant=False with empty entities."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)
        s3.put_object(
            Bucket=TEST_BUCKET,
            Key=TEST_S3_KEY,
            Body=b"General discussion about gardening tips and plant care.",
        )

        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.return_value = _combined_analysis_response(
            is_fraud_relevant=False,
            confidence=0.15,
            fraud_category=None,
            entities=[],
            affected_institutions=[],
        )

        with patch(
            "dark_web_fraud_agent.agents.content_analyst._bedrock_client",
            mock_bedrock,
        ):
            from dark_web_fraud_agent.agents.content_analyst import handler

            result = handler(
                {"s3_key": TEST_S3_KEY, "execution_id": TEST_EXECUTION_ID},
                None,
            )

        assert result["is_fraud_relevant"] is False
        assert result["entities"] == []
        assert result["fraud_category"] is None

    @mock_aws
    def test_content_analyst_guardrail_intervention(self, env_vars):
        """Bedrock guardrail GUARDRAIL_INTERVENED returns is_fraud_relevant=False, confidence=0.0."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)
        s3.put_object(
            Bucket=TEST_BUCKET,
            Key=TEST_S3_KEY,
            Body=b"Some potentially harmful content that triggers guardrails.",
        )

        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.return_value = _combined_analysis_response(
            guardrail_action="GUARDRAIL_INTERVENED",
        )

        with patch(
            "dark_web_fraud_agent.agents.content_analyst._bedrock_client",
            mock_bedrock,
        ):
            from dark_web_fraud_agent.agents.content_analyst import handler

            result = handler(
                {"s3_key": TEST_S3_KEY, "execution_id": TEST_EXECUTION_ID},
                None,
            )

        assert result["is_fraud_relevant"] is False
        assert result["confidence"] == 0.0
        assert result["entities"] == []

    @mock_aws
    def test_content_analyst_missing_s3_key(self, env_vars):
        """Missing s3_key in event raises KeyError."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)

        mock_bedrock = MagicMock()

        with patch(
            "dark_web_fraud_agent.agents.content_analyst._bedrock_client",
            mock_bedrock,
        ):
            from dark_web_fraud_agent.agents.content_analyst import handler

            with pytest.raises(KeyError):
                handler({"execution_id": TEST_EXECUTION_ID}, None)


# ===========================================================================
# 2. DATA STRUCTURER HANDLER TESTS
# ===========================================================================


class TestDataStructurerHandler:
    """Tests for dark_web_fraud_agent.agents.data_structurer.handler."""

    @mock_aws
    def test_data_structurer_happy_path(self, env_vars):
        """Valid entities produce a STIX bundle written to S3, doc IDs returned."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)

        mock_bedrock = MagicMock()
        # Mock embedding response for index_to_opensearch
        embedding_response = _bedrock_response_body({
            "embedding": [0.1] * 1024,
        })
        mock_bedrock.invoke_model.return_value = embedding_response

        event = {
            "s3_key": TEST_S3_KEY,
            "execution_id": TEST_EXECUTION_ID,
            "is_fraud_relevant": True,
            "confidence": 0.92,
            "fraud_category": "mfa_bypass",
            "severity_score": 7,
            "entities": [
                {"entity_type": "ip_address", "value": "192.168.1.1",
                 "context": "found at IP", "confidence": 0.95},
                {"entity_type": "email", "value": "attacker@evil.com",
                 "context": "contact at", "confidence": 0.88},
            ],
        }

        with patch(
            "dark_web_fraud_agent.agents.data_structurer._bedrock_client",
            mock_bedrock,
        ), patch(
            "dark_web_fraud_agent.agents.data_structurer.DataStructurer.index_to_opensearch",
            return_value=["doc-id-1", "doc-id-2"],
        ):
            from dark_web_fraud_agent.agents.data_structurer import handler

            result = handler(event, None)

        # Verify STIX bundle was written to S3
        assert result["stix_bundle_key"] is not None
        assert result["stix_bundle_key"].startswith("stix-bundles/")
        assert result["stix_bundle_key"].endswith(".stix.json")

        # Verify S3 object exists and is a valid STIX bundle
        s3_obj = s3.get_object(Bucket=TEST_BUCKET, Key=result["stix_bundle_key"])
        bundle_json = json.loads(s3_obj["Body"].read().decode("utf-8"))
        assert bundle_json["type"] == "bundle"
        assert len(bundle_json["objects"]) >= 2

        # Verify returned metadata
        assert result["stix_object_count"] >= 2
        assert result["opensearch_doc_ids"] == ["doc-id-1", "doc-id-2"]
        assert result["tier"] in ("observable", "indicator", "ttp")
        assert result["fraud_category"] == "mfa_bypass"
        assert result["severity_score"] == 7

    @mock_aws
    def test_data_structurer_non_relevant_passthrough(self, env_vars):
        """is_fraud_relevant=False returns stix_bundle_key=None, no S3 write."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)

        event = {
            "s3_key": TEST_S3_KEY,
            "execution_id": TEST_EXECUTION_ID,
            "is_fraud_relevant": False,
            "confidence": 0.2,
            "fraud_category": None,
            "severity_score": 1,
            "entities": [],
        }

        with patch(
            "dark_web_fraud_agent.agents.data_structurer._bedrock_client",
            MagicMock(),
        ):
            from dark_web_fraud_agent.agents.data_structurer import handler

            result = handler(event, None)

        assert result["stix_bundle_key"] is None
        assert result["stix_object_count"] == 0
        assert result["opensearch_doc_ids"] == []

        # Verify no objects were written to S3
        objs = s3.list_objects_v2(Bucket=TEST_BUCKET, Prefix="stix-bundles/")
        assert objs.get("KeyCount", 0) == 0

    @mock_aws
    def test_data_structurer_empty_entities(self, env_vars):
        """Empty entities list returns stix_object_count=0 and stix_bundle_key=None."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)

        event = {
            "s3_key": TEST_S3_KEY,
            "execution_id": TEST_EXECUTION_ID,
            "is_fraud_relevant": True,
            "confidence": 0.85,
            "fraud_category": "mfa_bypass",
            "severity_score": 5,
            "entities": [],  # No entities even though relevant
        }

        with patch(
            "dark_web_fraud_agent.agents.data_structurer._bedrock_client",
            MagicMock(),
        ), patch(
            "dark_web_fraud_agent.agents.data_structurer.DataStructurer.index_to_opensearch",
            return_value=[],
        ):
            from dark_web_fraud_agent.agents.data_structurer import handler

            result = handler(event, None)

        assert result["stix_object_count"] == 0
        assert result["stix_bundle_key"] is None


# ===========================================================================
# 3. TAGGING ENGINE HANDLER TESTS
# ===========================================================================


class TestTaggingEngineHandler:
    """Tests for dark_web_fraud_agent.agents.tagging_engine.handler."""

    @mock_aws
    def test_tagging_engine_happy_path(self, env_vars):
        """stix_bundle_key present results in tags applied and manifest written to S3."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)

        stix_bundle_key = "stix-bundles/2026/01/15/abc123/sample.txt.stix.json"
        s3.put_object(
            Bucket=TEST_BUCKET,
            Key=stix_bundle_key,
            Body=b'{"type": "bundle", "objects": []}',
        )

        event = {
            "s3_key": TEST_S3_KEY,
            "execution_id": TEST_EXECUTION_ID,
            "stix_bundle_key": stix_bundle_key,
            "fraud_category": "mfa_bypass",
            "severity_score": 7,
            "tier": "ttp",
        }

        from dark_web_fraud_agent.agents.tagging_engine import handler

        result = handler(event, None)

        # Tags were applied
        assert isinstance(result["tags"], list)
        assert len(result["tags"]) > 0

        # Tag manifest was written to S3
        assert result["tag_manifest_key"] is not None
        assert result["tag_manifest_key"].endswith(".tags.json")

        # Verify manifest contents in S3
        manifest_obj = s3.get_object(
            Bucket=TEST_BUCKET, Key=result["tag_manifest_key"]
        )
        manifest = json.loads(manifest_obj["Body"].read().decode("utf-8"))
        assert manifest["stix_bundle_key"] == stix_bundle_key
        assert manifest["fraud_category"] == "mfa_bypass"
        assert manifest["severity_score"] == 7
        assert isinstance(manifest["tags"], list)

        # Verify returned structure
        assert result["stix_bundle_key"] == stix_bundle_key
        assert result["fraud_category"] == "mfa_bypass"
        assert result["severity_score"] == 7

    @mock_aws
    def test_tagging_engine_no_bundle_key(self, env_vars):
        """No stix_bundle_key returns empty tags and no S3 write."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)

        event = {
            "s3_key": TEST_S3_KEY,
            "execution_id": TEST_EXECUTION_ID,
            "stix_bundle_key": None,
            "fraud_category": None,
            "severity_score": 3,
        }

        from dark_web_fraud_agent.agents.tagging_engine import handler

        result = handler(event, None)

        assert result["tags"] == []
        assert result["tag_manifest_key"] is None
        assert result["stix_bundle_key"] is None

        # Verify no manifest written
        objs = s3.list_objects_v2(Bucket=TEST_BUCKET, Prefix="stix-bundles/")
        assert objs.get("KeyCount", 0) == 0

    @mock_aws
    def test_tagging_engine_mfa_bypass_attack_tags(self, env_vars):
        """fraud_category=mfa_bypass correctly applies ATT&CK T1111 and high threat-level tags."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=TEST_BUCKET)

        stix_bundle_key = "stix-bundles/test/file.stix.json"
        s3.put_object(
            Bucket=TEST_BUCKET,
            Key=stix_bundle_key,
            Body=b'{"type": "bundle", "objects": []}',
        )

        event = {
            "s3_key": TEST_S3_KEY,
            "execution_id": TEST_EXECUTION_ID,
            "stix_bundle_key": stix_bundle_key,
            "fraud_category": "mfa_bypass",
            "severity_score": 8,
            "tier": "ttp",
        }

        from dark_web_fraud_agent.agents.tagging_engine import handler

        result = handler(event, None)

        tag_strings = result["tags"]
        # Should have ATT&CK technique tag for mfa_bypass (T1111)
        attack_tags = [t for t in tag_strings if "mitre-attack" in t and "T1111" in t]
        assert len(attack_tags) >= 1, f"Expected T1111 tag in {tag_strings}"

        # Should have high threat level tag (severity 8 maps to high)
        threat_tags = [t for t in tag_strings if "threat-level" in t]
        assert len(threat_tags) >= 1
        assert any("high" in t for t in threat_tags)

        # Galaxy match should be present for mfa_bypass
        assert result["galaxy_match"] is not None
        assert result["galaxy_match"]["cluster_value"] == "MFA Bypass"


# ===========================================================================
# 4. ALERT GENERATOR HANDLER TESTS
# ===========================================================================


class TestAlertGeneratorHandler:
    """Tests for dark_web_fraud_agent.agents.alert_generator.handler."""

    def _create_convergence_table(self):
        """Create the DynamoDB convergence table for testing."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
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
        table.meta.client.get_waiter("table_exists").wait(
            TableName="dark-web-fraud-convergence"
        )
        return table

    def _create_sns_topic(self):
        """Create a mocked SNS topic and return its ARN."""
        sns = boto3.client("sns", region_name="us-east-1")
        response = sns.create_topic(Name="fraud-alerts")
        return response["TopicArn"]

    @mock_aws
    def test_alert_generator_step_functions_no_convergence(self, env_vars):
        """Step Functions path: < 3 items in DynamoDB means no SNS publish."""
        table = self._create_convergence_table()
        topic_arn = self._create_sns_topic()

        # Override SNS_TOPIC_ARN with the real mocked ARN
        with patch.dict(os.environ, {"SNS_TOPIC_ARN": topic_arn}):
            # Pre-seed 1 item (below threshold of 3)
            table.put_item(Item={
                "PK": 'CONV#mitre-attack:technique="T1111"',
                "SK": "ITEM#existing-stix-1",
                "stix_id": "existing-stix-1",
                "ttp_reference": 'mitre-attack:technique="T1111"',
                "tier": "ttp",
                "timestamp": datetime.now(UTC).isoformat(),
                "TTL": 9999999999,
            })

            event = {
                "s3_key": TEST_S3_KEY,
                "execution_id": TEST_EXECUTION_ID,
                "stix_bundle_key": "stix-bundles/test.stix.json",
                "tags": ['mitre-attack:technique="T1111"'],
                "fraud_category": "mfa_bypass",
                "severity_score": 5,  # Below high severity threshold
                "tier": "ttp",
            }

            # Patch the module-level _sns_client to use moto's client
            sns_client = boto3.client("sns", region_name="us-east-1")
            with patch(
                "dark_web_fraud_agent.agents.alert_generator._sns_client",
                sns_client,
            ):
                from dark_web_fraud_agent.agents.alert_generator import handler

                result = handler(event, None)

        # No alert published (only 2 items: 1 pre-seeded + 1 tracked = below 3)
        assert result["alert_published"] is None
        assert result["convergence_ids"] is None

    @mock_aws
    def test_alert_generator_step_functions_convergence_detected(self, env_vars):
        """Step Functions path: 3 items in DynamoDB triggers convergence and SNS publish."""
        table = self._create_convergence_table()
        topic_arn = self._create_sns_topic()

        ttp_ref = 'mitre-attack:technique="T1111"'

        with patch.dict(os.environ, {"SNS_TOPIC_ARN": topic_arn}):
            # Pre-seed 2 items so that after track_item adds 1 more we have 3
            for i in range(2):
                table.put_item(Item={
                    "PK": f"CONV#{ttp_ref}",
                    "SK": f"ITEM#existing-stix-{i}",
                    "stix_id": f"existing-stix-{i}",
                    "ttp_reference": ttp_ref,
                    "tier": "ttp",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "TTL": 9999999999,
                })

            event = {
                "s3_key": TEST_S3_KEY,
                "execution_id": TEST_EXECUTION_ID,
                "stix_bundle_key": "stix-bundles/new-item.stix.json",
                "tags": ['mitre-attack:technique="T1111"'],
                "fraud_category": "mfa_bypass",
                "severity_score": 5,  # Below high severity — convergence alone triggers
                "tier": "ttp",
            }

            sns_client = boto3.client("sns", region_name="us-east-1")
            with patch(
                "dark_web_fraud_agent.agents.alert_generator._sns_client",
                sns_client,
            ):
                from dark_web_fraud_agent.agents.alert_generator import handler

                result = handler(event, None)

        # Convergence detected (3 items) → alert published
        assert result["convergence_ids"] is not None
        assert len(result["convergence_ids"]) >= 3
        assert result["alert_published"] is not None  # SNS MessageId

    @mock_aws
    def test_alert_generator_high_severity_immediate_alert(self, env_vars):
        """High severity (score >= 7) triggers immediate alert even without convergence."""
        table = self._create_convergence_table()
        topic_arn = self._create_sns_topic()

        with patch.dict(os.environ, {"SNS_TOPIC_ARN": topic_arn}):
            # No pre-seeded items — convergence NOT reached
            event = {
                "s3_key": TEST_S3_KEY,
                "execution_id": TEST_EXECUTION_ID,
                "stix_bundle_key": "stix-bundles/critical.stix.json",
                "tags": ['mitre-attack:technique="T1111"'],
                "fraud_category": "mfa_bypass",
                "severity_score": 9,  # >= 7 → immediate alert
                "tier": "ttp",
            }

            sns_client = boto3.client("sns", region_name="us-east-1")
            with patch(
                "dark_web_fraud_agent.agents.alert_generator._sns_client",
                sns_client,
            ):
                from dark_web_fraud_agent.agents.alert_generator import handler

                result = handler(event, None)

        # Immediate alert due to high severity, even without 3-item convergence
        assert result["alert_published"] is not None
        assert result["severity_score"] == 9

    @mock_aws
    def test_alert_generator_dynamodb_streams_path(self, env_vars):
        """DynamoDB Streams path: INSERT record triggers convergence check."""
        table = self._create_convergence_table()
        topic_arn = self._create_sns_topic()

        ttp_ref = 'mitre-attack:technique="T1566"'

        with patch.dict(os.environ, {"SNS_TOPIC_ARN": topic_arn}):
            # Pre-seed 3 items so convergence is immediately detected
            for i in range(3):
                table.put_item(Item={
                    "PK": f"CONV#{ttp_ref}",
                    "SK": f"ITEM#stream-stix-{i}",
                    "stix_id": f"stream-stix-{i}",
                    "ttp_reference": ttp_ref,
                    "tier": "indicator",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "TTL": 9999999999,
                })

            # Simulate DynamoDB Streams event (INSERT)
            event = {
                "Records": [
                    {
                        "eventName": "INSERT",
                        "dynamodb": {
                            "NewImage": {
                                "ttp_reference": {"S": ttp_ref},
                                "stix_id": {"S": "stream-stix-new"},
                            }
                        },
                    }
                ]
            }

            sns_client = boto3.client("sns", region_name="us-east-1")
            with patch(
                "dark_web_fraud_agent.agents.alert_generator._sns_client",
                sns_client,
            ):
                from dark_web_fraud_agent.agents.alert_generator import handler

                result = handler(event, None)

        # Streams path returns published_alerts list
        assert "published_alerts" in result
        assert len(result["published_alerts"]) >= 1
        # Each entry is an SNS MessageId (non-empty string)
        assert all(
            isinstance(mid, str) and len(mid) > 0
            for mid in result["published_alerts"]
        )

    @mock_aws
    def test_alert_generator_update_health_called(self, env_vars):
        """update_health is called after a successful invocation that publishes an alert."""
        table = self._create_convergence_table()
        topic_arn = self._create_sns_topic()

        with patch.dict(os.environ, {"SNS_TOPIC_ARN": topic_arn}):
            event = {
                "s3_key": TEST_S3_KEY,
                "execution_id": TEST_EXECUTION_ID,
                "stix_bundle_key": "stix-bundles/health-check.stix.json",
                "tags": ['mitre-attack:technique="T1111"'],
                "fraud_category": "mfa_bypass",
                "severity_score": 8,  # High severity → immediate alert
                "tier": "ttp",
            }

            sns_client = boto3.client("sns", region_name="us-east-1")
            with patch(
                "dark_web_fraud_agent.agents.alert_generator._sns_client",
                sns_client,
            ), patch(
                "dark_web_fraud_agent.agents.alert_generator.AlertGenerator.update_health"
            ) as mock_health:
                from dark_web_fraud_agent.agents.alert_generator import handler

                result = handler(event, None)

        # update_health was called after successful alert publish
        mock_health.assert_called_once_with(items_processed=1, errors=0)
        assert result["alert_published"] is not None
