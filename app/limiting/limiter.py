"""
Tier-based rate limiting.

Uses the `limits` library directly (the same underlying library as flask-limiter
in the monolith) with a Redis fixed-window strategy. Preserves the same response
headers clients already rely on:
  X-Allowance-Limit
  X-Allowance-Remaining
  X-Allowance-Reset

IP ranges in Settings.RATE_LIMIT_EXEMPT_CIDRS bypass the limiter entirely
(internal monitoring, load balancer probes, etc.).
Test-mode bypass via X-TEST-NO-RATE-LIMIT-KEY is also supported.
Requests authenticated with a service key (internal components) are not limited.
"""

import ipaddress
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import JSONResponse
from limits import parse, storage as limits_storage, strategies

from app.config import Settings


# ── Initialisation (called once from main.py lifespan) ───────────────────────

_storage: limits_storage.RedisStorage | None = None
_strategy: strategies.FixedWindowRateLimiter | None = None

_EXEMPT_RANGES = [ipaddress.ip_network(c) for c in Settings.RATE_LIMIT_EXEMPT_CIDRS]


def init_limiter() -> None:
    """Connect to Redis. Must be called during app startup."""
    global _storage, _strategy
    redis_url = (
        f"redis://:{Settings.REDIS_PASSWORD}"
        f"@{Settings.REDIS_HOST}:{Settings.REDIS_PORT}"
        f"/{Settings.REDIS_DB_LIMITER}"
    )
    _storage = limits_storage.RedisStorage(redis_url)
    _strategy = strategies.FixedWindowRateLimiter(_storage)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_client_ip(request: Request) -> str:
    # X-Forwarded-For is set by the OCI load balancer (ProxyFix equivalent).
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.client.host if request.client else '0.0.0.0'


def _is_exempt_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _EXEMPT_RANGES)
    except ValueError:
        return False


def _get_limit_key(request: Request) -> str:
    """Key by uid when authenticated, fall back to IP for anonymous requests."""
    user = getattr(request.state, 'user', None)
    if user:
        return f"uid:{user['uid']}"
    return f"ip:{_get_client_ip(request)}"


def _get_tier_limit(request: Request) -> str:
    user = getattr(request.state, 'user', None)
    tier = user.get('_tier', 'NONE') if user else 'NONE'
    return Settings.ALLOWANCE_BY_USER_TIER[tier]


def _format_reset_time(reset_ts: float) -> str:
    return datetime.fromtimestamp(reset_ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M %Z')


# ── Main check ────────────────────────────────────────────────────────────────

def check_rate_limit(request: Request) -> JSONResponse | None:
    """
    Apply rate limiting for the current request.

    Returns None if the request is allowed, or a 429 JSONResponse if the limit
    is exceeded. Attaches rate-limit stats to request.state.rate_limit_stats so
    the proxy layer can add the response headers.
    """
    # No-rate-limit test key bypass. Off when no key is configured, so an empty
    # header can't match an empty key.
    if Settings.TEST_NO_RATE_LIMIT_KEY and \
            request.headers.get('X-TEST-NO-RATE-LIMIT-KEY') == Settings.TEST_NO_RATE_LIMIT_KEY:
        request.state.rate_limit_stats = None
        return None

    # Internal components authenticated by service key.
    if getattr(request.state, 'service', None):
        request.state.rate_limit_stats = None
        return None

    # IP whitelist bypass.
    client_ip = _get_client_ip(request)
    if _is_exempt_ip(client_ip):
        request.state.rate_limit_stats = None
        return None

    limit_string = _get_tier_limit(request)
    limit_item = parse(limit_string)
    key = _get_limit_key(request)

    allowed = _strategy.hit(limit_item, key)
    stats = _strategy.get_window_stats(limit_item, key)

    rate_limit_stats = {
        'limit': limit_item.amount,
        'remaining': max(0, stats.remaining),
        'reset_at': int(stats.reset_time),
    }
    request.state.rate_limit_stats = rate_limit_stats

    if not allowed:
        return JSONResponse(
            {
                'message': (
                    f"Too many requests. Allowance: {limit_string}. "
                    f"Please try again after {_format_reset_time(stats.reset_time)}."
                )
            },
            status_code=429,
            headers=_build_allowance_headers(rate_limit_stats),
        )

    return None


def _build_allowance_headers(stats: dict) -> dict:
    return {
        'X-Allowance-Limit': str(stats['limit']),
        'X-Allowance-Remaining': str(stats['remaining']),
        'X-Allowance-Reset': str(stats['reset_at']),
    }


def get_allowance_headers(request: Request) -> dict:
    """Called by the proxy layer to attach rate-limit headers to the response."""
    stats = getattr(request.state, 'rate_limit_stats', None)
    if stats is None:
        return {}
    return _build_allowance_headers(stats)
