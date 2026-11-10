"""
Gateway configuration.

Reads from the same vault/app_conf.json used by the existing monolith so the
gateway can share the same secrets infrastructure during the transition.

Required keys (under the 'local' / 'production' section):
  backends      — {namespace: {'url': ..., 'key': ..., 'service_uuid': ...}}, one
                  per service behind the gateway, e.g. 'ogdb'. url is the service's
                  root; the key is sent upstream as a Bearer token (each service has
                  its own auth); service_uuid is the user for service-key calls
  service_keys  — {component_name: key}; other components (not end users) send
                  one of these in the X-Service-Key header to call the gateway
"""

import json
import os


class Settings:
    VERSION = '1.0.0'
    GROUP = os.environ.get('GROUP', 'prod')

    _root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    with open(os.path.join(_root_path, 'vault', 'app_conf.json')) as _f:
        _raw = json.load(_f)

    app_config = _raw['production'] if GROUP in ['prod', 'test'] else _raw['local']

    # ── JWT ──────────────────────────────────────────────────────────────────
    with open(os.path.join(_root_path, 'vault', 'api-jwt.pub')) as _f:
        JWT_PUBLIC_KEY = _f.read()

    JWT_VALIDITY = 14 * 86400   # seconds — must match UI service
    JWT_AUDIENCE = 'api.opengwas.io'

    # ── Backends, by namespace ────────────────────────────────────────────────
    # /{namespace}/{path} is proxied to the backend's url + /{path}.
    #   key          — static token the backend accepts from the gateway. Unrelated
    #                  to user JWTs, which are never forwarded upstream.
    #   service_uuid — the user the backend counts service-key requests against.
    BACKENDS: dict[str, dict] = {
        ns: {
            'url': backend['url'].rstrip('/'),
            'key': backend['key'],
            'service_uuid': backend['service_uuid'],
        }
        for ns, backend in app_config['backends'].items()
    }

    # ── Service keys ──────────────────────────────────────────────────────────
    # Keys for internal components calling the gateway (not used by end users).
    # A request whose X-Service-Key matches any of these skips JWT auth.
    SERVICE_KEYS: dict[str, str] = {
        name: key for name, key in app_config.get('service_keys', {}).items() if key
    }

    # ── Neo4j ─────────────────────────────────────────────────────────────────
    # Gateway only performs user lookups (read-only, auth path).
    NEO4J_URI: str = f"bolt://{app_config['neo4j']['host']}:{app_config['neo4j']['port']}"
    NEO4J_USER: str = app_config['neo4j']['user']
    NEO4J_PASSWORD: str = app_config['neo4j']['passwd']
    NEO4J_MAX_CONNECTION_LIFETIME: int = 5  # seconds — same as existing monolith

    # ── Redis ─────────────────────────────────────────────────────────────────
    _redis = app_config['redis']['oci']
    REDIS_HOST: str = _redis['host']
    REDIS_PORT: int = int(_redis['port'])
    REDIS_PASSWORD: str = _redis['pass']
    REDIS_DB_LIMITER: int = 1   # matches existing monolith
    REDIS_DB_LOG: int = 3       # matches existing monolith
    REDIS_LOG_CHANNEL: str = 'gateway-usage-log'  # Logstash subscribes here

    # ── Rate limiting ─────────────────────────────────────────────────────────
    # Must be kept in sync with the UI service's token generation page so users
    # see accurate limits when they view their profile.
    ALLOWANCE_BY_USER_TIER: dict[str, str] = {
        'UOB':        '400000 per 10 minutes',
        'COMMERCIAL': '100000 per 10 minutes',
        'STANDARD':   '100000 per 10 minutes',
        'TRIAL':      '100000 per 10 minutes',
        'NONE':       '0 per 10 minutes',
    }

    # IP ranges exempt from rate limiting (internal monitoring, load balancers).
    RATE_LIMIT_EXEMPT_CIDRS: list[str] = [
        '89.248.48.224/27',
        '213.123.49.48/29',
        '157.96.33.80/28',
    ]

    # ── Test / CI bypass ─────────────────────────────────────────────────────
    _test = app_config.get('test', {})
    TEST_STATIC_TOKEN: str = _test.get('static_token', '')
    TEST_UID: str = _test.get('uid', '')
    TEST_NO_RATE_LIMIT_KEY: str = _test.get('no_rate_limit_key', '')
