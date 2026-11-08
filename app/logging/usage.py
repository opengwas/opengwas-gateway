"""
Usage event logging via Redis pub/sub → Logstash → Elasticsearch.

The gateway publishes a structured JSON event to the REDIS_LOG_CHANNEL after
each proxied request. Logstash subscribes to that channel and persists events to ES.

Publishing is fire-and-forget (asyncio.create_task) so it never blocks the
response path. A failure to publish is logged locally but never surfaced to the
client.

Schema notes
────────────
This is a redesigned schema — not backward-compatible with legacy monolith logs.
The Logstash pipeline config will need updating to consume the new channel and
index template. Legacy ES data can be re-imported separately if needed.

Key additions over the legacy format:
  • response.status_code and response.duration_ms (previously unavailable because
    logging happened pre-response in the monolith)
  • user.tier for per-tier analytics
  • request.source_client / source_version from X-API-SOURCE header
  • gateway.version for correlating log format changes across deploys
"""

import asyncio
import ipaddress
import json
import logging
import time

from redis.asyncio import Redis

from app.config import Settings

logger = logging.getLogger(__name__)


def _anonymize_ip(ip_str: str | None) -> str | None:
    """Zero the last octet (IPv4) or the last 80 bits (IPv6) for privacy."""
    if not ip_str:
        return None
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            parts = ip_str.split('.')
            return '.'.join(parts[:3] + ['0'])
        else:
            # IPv6: zero last 80 bits (keep first 48 bits)
            packed = addr.packed
            return str(ipaddress.IPv6Address(packed[:6] + b'\x00' * 10))
    except ValueError:
        return None


def _build_event(
    *,
    uid: str | None,
    tier: str | None,
    remote_addr: str | None,
    method: str,
    path: str,
    query_string: str,
    source_client: str,
    source_version: str,
    user_agent: str,
    request_size: int,
    status_code: int,
    response_size: int,
    duration_ms: float,
) -> dict:
    return {
        '@timestamp': time.strftime('%Y-%m-%dT%H:%M:%S.', time.gmtime())
                      + f"{int(time.time() * 1000) % 1000:03d}Z",
        'request': {
            'method': method,
            'path': path,
            'query': query_string,
            'source_client': source_client,
            'source_version': source_version,
            'user_agent': user_agent,
            'size_bytes': request_size,
        },
        'user': {
            'uid': uid,
            'tier': tier,
            'remote_addr': _anonymize_ip(remote_addr),
        },
        'response': {
            'status_code': status_code,
            'size_bytes': response_size,
            'duration_ms': round(duration_ms, 1),
        },
        'gateway': {
            'version': Settings.VERSION,
        },
    }


async def _publish(redis_client: Redis, event: dict) -> None:
    try:
        await redis_client.publish(Settings.REDIS_LOG_CHANNEL, json.dumps(event))
    except Exception as exc:
        logger.warning("Failed to publish usage event: %s", exc)


def log_usage(
    redis_client: Redis,
    *,
    uid: str | None,
    tier: str | None,
    remote_addr: str | None,
    method: str,
    path: str,
    query_string: str,
    source_client: str,
    source_version: str,
    user_agent: str,
    request_size: int,
    status_code: int,
    response_size: int,
    duration_ms: float,
) -> None:
    """
    Schedule a non-blocking publish to the Redis pub/sub log channel.
    Safe to call from a BackgroundTask or directly from a route handler.
    """
    event = _build_event(
        uid=uid,
        tier=tier,
        remote_addr=remote_addr,
        method=method,
        path=path,
        query_string=query_string,
        source_client=source_client,
        source_version=source_version,
        user_agent=user_agent,
        request_size=request_size,
        status_code=status_code,
        response_size=response_size,
        duration_ms=duration_ms,
    )
    asyncio.create_task(_publish(redis_client, event))
