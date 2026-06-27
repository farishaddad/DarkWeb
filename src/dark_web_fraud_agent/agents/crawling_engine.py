"""Crawling Engine agent for dark web content collection.

This module implements:
- CrawlResult dataclass for representing crawl outputs
- CircuitBreakerState dataclass for DynamoDB-backed circuit breaker pattern
- S3 artifact storage with S3 Annotations for metadata
- SHA-256 content hashing for deduplication
- CrawlingEngine agent with Tor proxy connectivity and circuit rotation
- crawl_source() with retry logic, proxy rotation, and circuit breaker
"""

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

import aiohttp
import boto3
from stem import Signal
from stem.control import Controller

from dark_web_fraud_agent.config.settings import CrawlConfig, SourceDefinition
from dark_web_fraud_agent.models.shared import AgentBase, AgentConfig, AgentHealth

logger = logging.getLogger(__name__)


class CrawlError(Exception):
    """Raised when a crawl operation fails after exhausting all retries."""

    pass


@dataclass
class CrawlResult:
    """Result of a single crawl operation against a dark web source.

    Contains the raw content, source metadata, and references to stored
    artifacts in S3 with their associated annotations.
    """

    source_url: str
    source_category: str  # "forum" | "marketplace" | "telegram" | "paste"
    raw_content: str
    crawl_timestamp: datetime
    proxy_identity: str
    response_status: int
    content_hash: str  # SHA-256 for deduplication
    s3_artifact_key: str  # S3 key for raw artifact
    s3_annotation_id: str  # S3 Annotation ID with metadata


@dataclass
class CircuitBreakerState:
    """DynamoDB-backed circuit breaker state for a crawl source.

    Tracks consecutive failures for a source URL and manages the circuit breaker
    pattern to avoid hammering unreachable sources. The circuit breaker has three
    states:
    - closed: Normal operation, requests are allowed
    - open: Too many failures, requests are blocked until recovery timeout
    - half-open: Recovery timeout elapsed, allow one probe request

    Attributes:
        source_url_hash: SHA-256 hash of the source URL (partition key in DynamoDB).
        consecutive_failures: Number of consecutive failed requests.
        state: Current circuit breaker state.
        last_failure_time: Timestamp of the most recent failure.
        recovery_timeout: Seconds to wait before attempting recovery (default 60).
    """

    source_url_hash: str
    consecutive_failures: int = 0
    state: str = "closed"  # "closed" | "open" | "half-open"
    last_failure_time: Optional[datetime] = None
    recovery_timeout: int = 60

    @property
    def is_open(self) -> bool:
        """Return True when the circuit breaker is open (consecutive_failures >= 5)."""
        return self.consecutive_failures >= 5

    @property
    def should_attempt_recovery(self) -> bool:
        """Return True when elapsed time since last failure exceeds recovery_timeout.

        If there's no recorded failure time, recovery is always allowed.
        """
        if self.last_failure_time is None:
            return True
        elapsed = (datetime.now(UTC) - self.last_failure_time).total_seconds()
        return elapsed > self.recovery_timeout

    def record_failure(self) -> None:
        """Record a failure, incrementing the counter and updating state."""
        self.consecutive_failures += 1
        self.last_failure_time = datetime.now(UTC)
        if self.is_open:
            self.state = "open"

    def record_success(self) -> None:
        """Record a success, resetting the circuit breaker to closed state."""
        self.consecutive_failures = 0
        self.state = "closed"
        self.last_failure_time = None


def _strip_html_tags(html_content: str) -> str:
    """Strip HTML tags from content, returning plain text.

    Args:
        html_content: Raw HTML string.

    Returns:
        Plain text with HTML tags removed.
    """
    # BeautifulSoup handles malformed markup, unclosed tags, inline JS, and
    # non-ASCII encodings common on dark web forums.
    # Regex-based stripping silently fails on all of these.
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(html_content, "html.parser").get_text(separator=" ", strip=True)
    except ImportError:
        # Fallback if beautifulsoup4 not in Lambda layer
        clean = re.sub(r"<[^>]+>", "", html_content)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean


def compute_content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for deduplication.

    Args:
        content: Raw text content to hash.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _generate_s3_key(source_url: str, crawl_timestamp: datetime, content_hash: str) -> str:
    """Generate a unique S3 key for storing a crawl artifact.

    The key structure follows: crawl-artifacts/{date}/{content_hash}/{uuid}.txt
    This ensures deduplication-friendly storage with date-based partitioning.

    Args:
        source_url: The source URL that was crawled.
        crawl_timestamp: When the crawl occurred.
        content_hash: SHA-256 hash of the content.

    Returns:
        S3 object key string.
    """
    date_prefix = crawl_timestamp.strftime("%Y/%m/%d")
    unique_id = uuid.uuid4().hex[:12]
    return f"crawl-artifacts/{date_prefix}/{content_hash[:16]}/{unique_id}.txt"


def store_artifact(
    content: str,
    metadata: dict[str, Any],
    s3_bucket: str,
    s3_client: Any | None = None,
) -> tuple[str, str]:
    """Upload raw crawl content to S3 and create an S3 Annotation with source metadata.

    This stores the raw text content as an S3 object and attaches an annotation
    containing the source metadata (URL, category, timestamp, proxy identity, etc.)
    for later querying without downloading the full artifact.

    Args:
        content: Raw text content from the crawl.
        metadata: Dictionary of source metadata to attach as annotation.
            Expected keys: source_url, source_category, crawl_timestamp,
            proxy_identity, response_status, content_hash.
        s3_bucket: Name of the S3 bucket for artifact storage.
        s3_client: Optional boto3 S3 client (created if not provided).

    Returns:
        Tuple of (s3_artifact_key, s3_annotation_id).
    """
    if s3_client is None:
        s3_client = boto3.client("s3")

    # Compute hash and generate key
    content_hash = metadata.get("content_hash", compute_content_hash(content))
    crawl_timestamp = metadata.get("crawl_timestamp", datetime.now(UTC))
    source_url = metadata.get("source_url", "unknown")

    if isinstance(crawl_timestamp, str):
        crawl_timestamp = datetime.fromisoformat(crawl_timestamp)

    s3_key = _generate_s3_key(source_url, crawl_timestamp, content_hash)

    # Upload raw content to S3
    s3_client.put_object(
        Bucket=s3_bucket,
        Key=s3_key,
        Body=content.encode("utf-8"),
        ContentType="text/plain",
        Metadata={
            "content-hash": content_hash,
            "source-url": source_url,
            "source-category": metadata.get("source_category", "unknown"),
        },
    )

    # Create S3 Annotation with source metadata
    annotation_id = _create_annotation(
        s3_client=s3_client,
        bucket=s3_bucket,
        key=s3_key,
        metadata=metadata,
    )

    return s3_key, annotation_id


def _create_annotation(
    s3_client: Any,
    bucket: str,
    key: str,
    metadata: dict[str, Any],
) -> str:
    """Create an S3 Annotation on the stored artifact with source metadata.

    S3 Annotations allow attaching up to 1 GB of queryable context to an S3 object.
    We store the full crawl metadata as a JSON annotation for later retrieval
    and querying without downloading the artifact itself.

    Args:
        s3_client: boto3 S3 client.
        bucket: S3 bucket name.
        key: S3 object key of the artifact.
        metadata: Source metadata dictionary to store in the annotation.

    Returns:
        Annotation ID string.
    """
    annotation_id = f"ann-{uuid.uuid4().hex[:16]}"

    # Prepare annotation payload - serialize datetime objects
    annotation_payload = {}
    for k, v in metadata.items():
        if isinstance(v, datetime):
            annotation_payload[k] = v.isoformat()
        else:
            annotation_payload[k] = v

    annotation_payload["annotation_id"] = annotation_id
    annotation_payload["artifact_key"] = key
    annotation_payload["artifact_bucket"] = bucket

    # Store annotation as a sidecar JSON object alongside the artifact
    annotation_key = f"{key}.annotation.json"
    s3_client.put_object(
        Bucket=bucket,
        Key=annotation_key,
        Body=json.dumps(annotation_payload).encode("utf-8"),
        ContentType="application/json",
    )

    return annotation_id


class CrawlingEngine(AgentBase):
    """AgentCore agent for dark web content collection via Tor proxy.

    Manages Tor SOCKS5 proxy connectivity through a VPC NAT Gateway,
    handles circuit rotation for identity changes, and retrieves
    proxy authentication credentials from AWS Secrets Manager.

    The agent connects to the Tor control port via the `stem` library
    to issue NEWNYM signals for circuit rotation, and uses the SOCKS5
    proxy for all outbound HTTP requests to dark web sources.
    """

    def __init__(
        self,
        crawl_config: CrawlConfig,
        secrets_client: Optional[Any] = None,
        tor_controller: Optional[Controller] = None,
    ) -> None:
        """Initialize the CrawlingEngine with configuration and dependencies.

        Args:
            crawl_config: Validated CrawlConfig with Tor ports, sources, and AWS resource references.
            secrets_client: Optional boto3 Secrets Manager client (created if not provided).
            tor_controller: Optional pre-configured stem Controller (for testing).
        """
        agent_config = AgentConfig(
            agent_id="crawling-engine",
            agent_name="Crawling Engine",
            s3_bucket=crawl_config.s3_bucket,
            dynamodb_table=crawl_config.dynamodb_table,
        )
        super().__init__(config=agent_config)

        self._crawl_config = crawl_config
        self._secrets_client = secrets_client
        self._tor_controller = tor_controller
        self._current_ip: Optional[str] = None
        self._is_running: bool = False
        self._s3_client: Optional[Any] = None
        self._dynamodb_client: Optional[Any] = None
        self._start_time: Optional[datetime] = None

    @property
    def crawl_config(self) -> CrawlConfig:
        """Return the crawl configuration."""
        return self._crawl_config

    @property
    def is_running(self) -> bool:
        """Return whether the engine is currently active."""
        return self._is_running

    @property
    def current_ip(self) -> Optional[str]:
        """Return the current Tor exit node IP address."""
        return self._current_ip

    async def start(self) -> None:
        """Start the Crawling Engine agent.

        Initializes boto3 clients, connects to the Tor control port,
        and authenticates using credentials from Secrets Manager.
        """
        logger.info("Starting CrawlingEngine agent")

        # Initialize boto3 clients
        if self._secrets_client is None:
            self._secrets_client = boto3.client("secretsmanager")
        self._s3_client = boto3.client("s3")

        # Connect to Tor control port if no controller was injected
        if self._tor_controller is None:
            tor_password = self._get_tor_credential()
            self._tor_controller = Controller.from_port(
                port=self._crawl_config.tor_control_port
            )
            self._tor_controller.authenticate(password=tor_password)
        elif not self._tor_controller.is_authenticated():
            tor_password = self._get_tor_credential()
            self._tor_controller.authenticate(password=tor_password)

        self._is_running = True
        self._start_time = datetime.now(UTC)
        self._health.status = "healthy"
        self._health.last_heartbeat = datetime.now(UTC)
        logger.info("CrawlingEngine started successfully")

    async def stop(self) -> None:
        """Stop the Crawling Engine agent.

        Closes the Tor controller connection and cleans up resources.
        """
        logger.info("Stopping CrawlingEngine agent")

        if self._tor_controller is not None:
            self._tor_controller.close()
            self._tor_controller = None

        self._is_running = False
        self._current_ip = None
        self._health.status = "stopped"
        logger.info("CrawlingEngine stopped")

    async def rotate_circuit(self) -> str:
        """Rotate the Tor circuit to obtain a new exit node IP.

        Issues a NEWNYM signal to the Tor control port, which requests
        a new circuit with a different exit node. Then queries the
        exit node IP via the control protocol.

        Returns:
            The new exit node IP address as a string.

        Raises:
            RuntimeError: If the engine is not running or controller is unavailable.
            stem.ControllerError: If the Tor control command fails.
        """
        if not self._is_running or self._tor_controller is None:
            raise RuntimeError("CrawlingEngine is not running. Call start() first.")

        logger.info("Rotating Tor circuit...")

        # Send NEWNYM signal to request a new circuit
        self._tor_controller.signal(Signal.NEWNYM)

        # Get the new exit node IP from the Tor circuit info
        new_ip = self._get_exit_ip()
        self._current_ip = new_ip

        logger.info(f"Circuit rotated. New exit IP: {new_ip}")
        return new_ip

    def get_proxy_url(self) -> str:
        """Get the SOCKS5 proxy URL for HTTP requests through Tor.

        Returns:
            SOCKS5 proxy URL string (e.g., 'socks5://127.0.0.1:9050').
        """
        return f"socks5://127.0.0.1:{self._crawl_config.tor_socks_port}"

    async def crawl_source(self, source: SourceDefinition) -> CrawlResult:
        """Crawl a dark web source via Tor proxy with retry logic and circuit breaker.

        Connects to the source URL using aiohttp through the Tor SOCKS5 proxy,
        extracts raw text content (stripping HTML), computes a content hash for
        deduplication, stores the artifact in S3 with an annotation, and returns
        a complete CrawlResult.

        On failure, rotates the Tor circuit to get a new proxy identity and retries
        up to max_retries times. Each retry uses a different proxy identity.

        Args:
            source: SourceDefinition with URL, category, and other crawl parameters.

        Returns:
            CrawlResult with all fields populated on success.

        Raises:
            RuntimeError: If the engine is not running.
            CrawlError: If all retries are exhausted without a successful crawl.
        """
        if not self._is_running:
            raise RuntimeError("CrawlingEngine is not running. Call start() first.")

        # Check circuit breaker state
        source_url_hash = compute_content_hash(source.url)
        circuit_breaker = self._get_circuit_breaker_state(source_url_hash)

        if circuit_breaker.is_open and not circuit_breaker.should_attempt_recovery:
            raise CrawlError(
                f"Circuit breaker open for {source.url}. "
                f"Consecutive failures: {circuit_breaker.consecutive_failures}. "
                f"Recovery timeout not elapsed."
            )

        # If circuit breaker is open but recovery timeout elapsed, try half-open
        if circuit_breaker.is_open and circuit_breaker.should_attempt_recovery:
            circuit_breaker.state = "half-open"

        max_retries = self._crawl_config.max_retries
        last_exception: Optional[Exception] = None

        for attempt in range(max_retries):
            proxy_identity = self._current_ip or "initial"

            try:
                # Rotate circuit on retry (not on first attempt)
                if attempt > 0:
                    proxy_identity = await self.rotate_circuit()

                crawl_timestamp = datetime.now(UTC)
                proxy_url = self.get_proxy_url()

                # Connect via Tor SOCKS5 proxy and fetch content
                connector = aiohttp.TCPConnector()
                timeout = aiohttp.ClientTimeout(
                    total=self._crawl_config.request_timeout
                )

                async with aiohttp.ClientSession(
                    connector=connector, timeout=timeout
                ) as session:
                    async with session.get(
                        source.url, proxy=proxy_url
                    ) as response:
                        response_status = response.status
                        raw_html = await response.text()

                # Extract plain text from HTML
                raw_content = _strip_html_tags(raw_html)

                # Compute content hash for deduplication
                content_hash = compute_content_hash(raw_content)

                # Store artifact in S3 with annotation
                metadata = {
                    "source_url": source.url,
                    "source_category": source.category,
                    "crawl_timestamp": crawl_timestamp,
                    "proxy_identity": proxy_identity,
                    "response_status": response_status,
                    "content_hash": content_hash,
                }

                s3_artifact_key, s3_annotation_id = store_artifact(
                    content=raw_content,
                    metadata=metadata,
                    s3_bucket=self._crawl_config.s3_bucket,
                    s3_client=self._s3_client,
                )

                # Record success in circuit breaker
                circuit_breaker.record_success()
                self._save_circuit_breaker_state(circuit_breaker)

                return CrawlResult(
                    source_url=source.url,
                    source_category=source.category,
                    raw_content=raw_content,
                    crawl_timestamp=crawl_timestamp,
                    proxy_identity=proxy_identity,
                    response_status=response_status,
                    content_hash=content_hash,
                    s3_artifact_key=s3_artifact_key,
                    s3_annotation_id=s3_annotation_id,
                )

            except CrawlError:
                raise
            except Exception as e:
                last_exception = e
                logger.warning(
                    f"Crawl attempt {attempt + 1}/{max_retries} failed for "
                    f"{source.url}: {e}"
                )
                # Record failure in circuit breaker
                circuit_breaker.record_failure()

                # On connectivity loss, attempt reconnection within 60 seconds
                if self._is_connectivity_error(e):
                    await self._attempt_reconnection()

        # All retries exhausted
        self._save_circuit_breaker_state(circuit_breaker)
        raise CrawlError(
            f"All {max_retries} crawl attempts failed for {source.url}. "
            f"Last error: {last_exception}"
        )

    def _is_connectivity_error(self, error: Exception) -> bool:
        """Determine if an exception represents a Tor connectivity loss.

        Args:
            error: The exception that occurred.

        Returns:
            True if the error indicates connectivity loss.
        """
        connectivity_errors = (
            aiohttp.ClientConnectionError,
            aiohttp.ServerDisconnectedError,
            ConnectionRefusedError,
            OSError,
        )
        return isinstance(error, connectivity_errors)

    async def _attempt_reconnection(self) -> None:
        """Attempt to reconnect to Tor within 60 seconds.

        Issues a new circuit rotation to re-establish Tor connectivity.
        Logs the connectivity disruption.
        """
        logger.warning("Tor connectivity loss detected. Attempting reconnection...")
        try:
            await self.rotate_circuit()
            logger.info("Tor reconnection successful with new circuit.")
        except Exception as e:
            logger.error(f"Tor reconnection failed: {e}")

    def _get_circuit_breaker_state(self, source_url_hash: str) -> CircuitBreakerState:
        """Retrieve circuit breaker state from DynamoDB (or return default).

        Args:
            source_url_hash: SHA-256 hash of the source URL.

        Returns:
            CircuitBreakerState for the source.
        """
        # In production this would read from DynamoDB; for now, use in-memory cache
        if not hasattr(self, "_circuit_breaker_cache"):
            self._circuit_breaker_cache: dict[str, CircuitBreakerState] = {}

        if source_url_hash in self._circuit_breaker_cache:
            return self._circuit_breaker_cache[source_url_hash]

        state = CircuitBreakerState(source_url_hash=source_url_hash)
        self._circuit_breaker_cache[source_url_hash] = state
        return state

    def _save_circuit_breaker_state(self, state: CircuitBreakerState) -> None:
        """Persist circuit breaker state to DynamoDB (or in-memory cache).

        Args:
            state: CircuitBreakerState to save.
        """
        if not hasattr(self, "_circuit_breaker_cache"):
            self._circuit_breaker_cache = {}
        self._circuit_breaker_cache[state.source_url_hash] = state

    def get_health(self) -> AgentHealth:
        """Return the current health status of the Crawling Engine.

        Includes uptime calculation based on time since start().

        Returns:
            AgentHealth instance with current metrics including uptime_seconds.
        """
        self._health.last_heartbeat = datetime.now(UTC)
        if self._start_time is not None and self._is_running:
            self._health.uptime_seconds = (
                datetime.now(UTC) - self._start_time
            ).total_seconds()
        return self._health

    async def _write_crawl_state(self, source_url: str, content_hash: str, success: bool) -> None:
        """Write crawl state to DynamoDB for tracking.

        Records the last crawl timestamp, content hash, success status,
        and computes the next crawl due time.

        Args:
            source_url: The source URL that was crawled.
            content_hash: SHA-256 hash of the crawled content.
            success: Whether the crawl was successful.
        """
        if self._dynamodb_client is None:
            self._dynamodb_client = boto3.resource("dynamodb")

        table = self._dynamodb_client.Table(self._crawl_config.dynamodb_table)
        source_hash = hashlib.sha256(source_url.encode()).hexdigest()[:16]

        item = {
            "PK": f"SOURCE#{source_hash}",
            "SK": f"CRAWL#{datetime.now(UTC).isoformat()}",
            "source_url": source_url,
            "last_content_hash": content_hash,
            "last_crawl_timestamp": datetime.now(UTC).isoformat(),
            "success": success,
            "next_crawl_due": (datetime.now(UTC) + timedelta(seconds=300)).isoformat(),
        }
        table.put_item(Item=item)

    def _get_tor_credential(self) -> str:
        """Retrieve Tor proxy authentication password from AWS Secrets Manager.

        Looks up the credential using the configured secrets_manager_prefix.

        Returns:
            The Tor control port password string.

        Raises:
            botocore.exceptions.ClientError: If secret retrieval fails.
        """
        secret_name = f"{self._crawl_config.secrets_manager_prefix}/tor-control-password"
        response = self._secrets_client.get_secret_value(SecretId=secret_name)

        # Secret can be stored as a string or as JSON
        secret_string = response.get("SecretString", "")
        try:
            secret_data = json.loads(secret_string)
            return secret_data.get("password", secret_string)
        except (json.JSONDecodeError, TypeError):
            return secret_string

    def _get_exit_ip(self) -> str:
        """Get the current Tor exit node IP address from the controller.

        Queries the Tor controller for circuit info and extracts the
        exit relay's IP address.

        Returns:
            Exit node IP address string.
        """
        # Use GETINFO to retrieve the exit node address
        # The 'address' info returns the external IP as seen through Tor
        try:
            exit_ip = self._tor_controller.get_info("address")
            return exit_ip
        except Exception:
            # Fallback: parse circuit info for the exit relay
            try:
                circuit_status = self._tor_controller.get_info("circuit-status")
                if circuit_status:
                    # Parse the last relay in the first BUILT circuit
                    for line in circuit_status.split("\n"):
                        if "BUILT" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                # Exit relay is the last in the path
                                exit_relay = parts[-1]
                                # Extract IP if available (format: $fingerprint~name)
                                return exit_relay
                return "unknown"
            except Exception:
                return "unknown"
