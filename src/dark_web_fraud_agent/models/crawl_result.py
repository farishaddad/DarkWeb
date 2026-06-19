"""CrawlResult model for the Crawling Engine agent.

Represents the output of a single crawl operation, including the raw content,
source metadata, S3 artifact references, and a SHA-256 content hash for deduplication.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from typing import Optional


def _compute_content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for deduplication.

    Args:
        content: Raw text content to hash.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass
class CrawlResult:
    """Result of a single crawl operation from the Crawling Engine.

    Contains source metadata, raw content, S3 artifact references,
    and a SHA-256 content hash used for deduplication across crawl cycles.

    Attributes:
        source_url: The URL of the crawled source (must be non-empty).
        source_category: Category of the source (forum, marketplace, telegram, paste).
        raw_content: Raw textual content extracted from the source.
        crawl_timestamp: UTC timestamp when the crawl was performed.
        proxy_identity: The Tor exit node or proxy identity used for the crawl.
        response_status: HTTP response status code (integer).
        content_hash: SHA-256 hash of raw_content for deduplication.
        s3_artifact_key: S3 object key where the raw artifact is stored.
        s3_annotation_id: S3 Annotation ID containing source metadata.
    """

    source_url: str
    source_category: str
    raw_content: str
    crawl_timestamp: datetime
    proxy_identity: str
    response_status: int
    s3_artifact_key: str = ""
    s3_annotation_id: str = ""
    content_hash: str = field(init=False, default="")

    def __post_init__(self) -> None:
        """Validate fields and compute content hash after initialization."""
        if not self.source_url:
            raise ValueError("source_url must be non-empty")
        if not isinstance(self.response_status, int):
            raise TypeError("response_status must be an integer")
        self.content_hash = _compute_content_hash(self.raw_content)
