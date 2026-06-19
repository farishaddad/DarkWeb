"""S3 artifact storage for the Crawling Engine.

Provides functionality to upload raw crawl content to S3 and create
S3 Annotations with source metadata for queryable intelligence context.
"""

import json
import uuid
from typing import Any

import boto3


def store_artifact(
    bucket: str,
    content: str,
    metadata: dict[str, Any],
    s3_client: Any | None = None,
) -> tuple[str, str]:
    """Upload raw content to S3 and create an S3 Annotation with source metadata.

    Stores the raw crawl content as an S3 object and attaches a JSON annotation
    containing source metadata (URL, category, timestamp, proxy identity, etc.)
    for downstream queryability.

    Args:
        bucket: S3 bucket name for artifact storage.
        content: Raw text content to store.
        metadata: Source metadata dict to attach as annotation. Expected keys
            include source_url, source_category, crawl_timestamp, proxy_identity,
            response_status, and content_hash.
        s3_client: Optional pre-configured boto3 S3 client (useful for testing).

    Returns:
        A tuple of (s3_key, annotation_id) where:
            - s3_key: The S3 object key where the content was stored.
            - annotation_id: A unique ID for the metadata annotation.

    Raises:
        botocore.exceptions.ClientError: If the S3 upload or annotation fails.
    """
    if s3_client is None:
        s3_client = boto3.client("s3")

    # Generate a unique key for the artifact
    artifact_id = str(uuid.uuid4())
    s3_key = f"crawl-artifacts/{artifact_id}.txt"

    # Upload raw content to S3
    s3_client.put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=content.encode("utf-8"),
        ContentType="text/plain",
        Metadata={
            "source_url": metadata.get("source_url", ""),
            "source_category": metadata.get("source_category", ""),
            "content_hash": metadata.get("content_hash", ""),
        },
    )

    # Create annotation metadata as a separate JSON object
    annotation_id = str(uuid.uuid4())
    annotation_key = f"crawl-annotations/{annotation_id}.json"

    annotation_payload = {
        "annotation_id": annotation_id,
        "artifact_key": s3_key,
        **metadata,
    }

    s3_client.put_object(
        Bucket=bucket,
        Key=annotation_key,
        Body=json.dumps(annotation_payload, default=str).encode("utf-8"),
        ContentType="application/json",
    )

    return s3_key, annotation_id
