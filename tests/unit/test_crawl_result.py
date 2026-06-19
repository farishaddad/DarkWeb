"""Unit tests for CrawlResult model and S3 artifact storage."""

import hashlib
import json
from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from dark_web_fraud_agent.infrastructure.s3_storage import store_artifact
from dark_web_fraud_agent.models.crawl_result import CrawlResult, _compute_content_hash


class TestCrawlResult:
    """Tests for the CrawlResult dataclass."""

    def test_valid_crawl_result_creation(self):
        """CrawlResult with valid fields should construct without error."""
        result = CrawlResult(
            source_url="http://example.onion/forum",
            source_category="forum",
            raw_content="Some dark web content",
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="exit-node-1",
            response_status=200,
            s3_artifact_key="crawl-artifacts/abc.txt",
            s3_annotation_id="annotation-123",
        )
        assert result.source_url == "http://example.onion/forum"
        assert result.source_category == "forum"
        assert result.response_status == 200
        assert result.content_hash != ""

    def test_content_hash_is_sha256(self):
        """content_hash should be a valid SHA-256 hex digest of raw_content."""
        content = "test content for hashing"
        result = CrawlResult(
            source_url="http://example.onion",
            source_category="marketplace",
            raw_content=content,
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-1",
            response_status=200,
        )
        expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert result.content_hash == expected_hash

    def test_content_hash_changes_with_content(self):
        """Different raw_content should produce different content_hash."""
        result1 = CrawlResult(
            source_url="http://example.onion",
            source_category="forum",
            raw_content="content A",
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-1",
            response_status=200,
        )
        result2 = CrawlResult(
            source_url="http://example.onion",
            source_category="forum",
            raw_content="content B",
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-1",
            response_status=200,
        )
        assert result1.content_hash != result2.content_hash

    def test_same_content_produces_same_hash(self):
        """Identical raw_content should produce identical content_hash (deduplication)."""
        content = "duplicate content"
        result1 = CrawlResult(
            source_url="http://example1.onion",
            source_category="forum",
            raw_content=content,
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-1",
            response_status=200,
        )
        result2 = CrawlResult(
            source_url="http://example2.onion",
            source_category="marketplace",
            raw_content=content,
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-2",
            response_status=200,
        )
        assert result1.content_hash == result2.content_hash

    def test_empty_source_url_raises_value_error(self):
        """source_url must be non-empty; empty string should raise ValueError."""
        with pytest.raises(ValueError, match="source_url must be non-empty"):
            CrawlResult(
                source_url="",
                source_category="forum",
                raw_content="some content",
                crawl_timestamp=datetime.now(UTC),
                proxy_identity="proxy-1",
                response_status=200,
            )

    def test_response_status_must_be_int(self):
        """response_status must be an integer; non-int should raise TypeError."""
        with pytest.raises(TypeError, match="response_status must be an integer"):
            CrawlResult(
                source_url="http://example.onion",
                source_category="forum",
                raw_content="some content",
                crawl_timestamp=datetime.now(UTC),
                proxy_identity="proxy-1",
                response_status="200",  # type: ignore
            )

    def test_empty_content_produces_valid_hash(self):
        """Empty raw_content should still produce a valid SHA-256 hash."""
        result = CrawlResult(
            source_url="http://example.onion",
            source_category="paste",
            raw_content="",
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-1",
            response_status=200,
        )
        expected_hash = hashlib.sha256(b"").hexdigest()
        assert result.content_hash == expected_hash

    def test_default_s3_fields_are_empty_string(self):
        """s3_artifact_key and s3_annotation_id default to empty string."""
        result = CrawlResult(
            source_url="http://example.onion",
            source_category="telegram",
            raw_content="content",
            crawl_timestamp=datetime.now(UTC),
            proxy_identity="proxy-1",
            response_status=200,
        )
        assert result.s3_artifact_key == ""
        assert result.s3_annotation_id == ""


class TestComputeContentHash:
    """Tests for the _compute_content_hash utility function."""

    def test_sha256_output_length(self):
        """SHA-256 hex digest should always be 64 characters."""
        assert len(_compute_content_hash("test")) == 64

    def test_deterministic(self):
        """Same input should always produce same output."""
        assert _compute_content_hash("hello") == _compute_content_hash("hello")

    def test_unicode_content(self):
        """Unicode content should be hashed correctly via UTF-8 encoding."""
        content = "こんにちは世界 🌐"
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert _compute_content_hash(content) == expected


class TestStoreArtifact:
    """Tests for S3 artifact storage using moto mock."""

    @mock_aws
    def test_store_artifact_uploads_content(self):
        """store_artifact should upload content to S3 and return valid keys."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "test-crawl-bucket"
        s3.create_bucket(Bucket=bucket)

        content = "raw dark web content"
        metadata = {
            "source_url": "http://example.onion/page",
            "source_category": "forum",
            "crawl_timestamp": "2024-01-15T10:30:00Z",
            "proxy_identity": "exit-node-5",
            "response_status": 200,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),
        }

        s3_key, annotation_id = store_artifact(bucket, content, metadata, s3_client=s3)

        assert s3_key.startswith("crawl-artifacts/")
        assert s3_key.endswith(".txt")
        assert annotation_id != ""

    @mock_aws
    def test_store_artifact_content_retrievable(self):
        """Stored content should be retrievable from S3."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "test-crawl-bucket"
        s3.create_bucket(Bucket=bucket)

        content = "retrievable content"
        metadata = {"source_url": "http://test.onion", "source_category": "paste"}

        s3_key, _ = store_artifact(bucket, content, metadata, s3_client=s3)

        response = s3.get_object(Bucket=bucket, Key=s3_key)
        stored_content = response["Body"].read().decode("utf-8")
        assert stored_content == content

    @mock_aws
    def test_store_artifact_annotation_contains_metadata(self):
        """Annotation JSON should contain the source metadata."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "test-crawl-bucket"
        s3.create_bucket(Bucket=bucket)

        content = "some content"
        metadata = {
            "source_url": "http://forum.onion/thread/123",
            "source_category": "forum",
            "crawl_timestamp": "2024-01-15T10:30:00Z",
            "proxy_identity": "exit-node-3",
            "response_status": 200,
            "content_hash": "abc123",
        }

        _, annotation_id = store_artifact(bucket, content, metadata, s3_client=s3)

        # Retrieve the annotation
        annotation_key = f"crawl-annotations/{annotation_id}.json"
        response = s3.get_object(Bucket=bucket, Key=annotation_key)
        annotation = json.loads(response["Body"].read().decode("utf-8"))

        assert annotation["source_url"] == "http://forum.onion/thread/123"
        assert annotation["source_category"] == "forum"
        assert annotation["proxy_identity"] == "exit-node-3"
        assert annotation["annotation_id"] == annotation_id

    @mock_aws
    def test_store_artifact_s3_object_metadata(self):
        """S3 object should have source metadata in object metadata headers."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "test-crawl-bucket"
        s3.create_bucket(Bucket=bucket)

        content = "test"
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        metadata = {
            "source_url": "http://market.onion",
            "source_category": "marketplace",
            "content_hash": content_hash,
        }

        s3_key, _ = store_artifact(bucket, content, metadata, s3_client=s3)

        response = s3.head_object(Bucket=bucket, Key=s3_key)
        obj_metadata = response["Metadata"]
        assert obj_metadata["source_url"] == "http://market.onion"
        assert obj_metadata["source_category"] == "marketplace"
        assert obj_metadata["content_hash"] == content_hash

    @mock_aws
    def test_store_artifact_unique_keys_per_call(self):
        """Each call to store_artifact should produce unique S3 keys."""
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket = "test-crawl-bucket"
        s3.create_bucket(Bucket=bucket)

        metadata = {"source_url": "http://test.onion", "source_category": "forum"}

        key1, id1 = store_artifact(bucket, "content1", metadata, s3_client=s3)
        key2, id2 = store_artifact(bucket, "content2", metadata, s3_client=s3)

        assert key1 != key2
        assert id1 != id2
