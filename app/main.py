"""
OpenGWAS Gateway — FastAPI entry point.

Responsibilities:
  • Authenticate every /api/* request (JWT → Neo4j user lookup).
  • Apply tier-based rate limiting via Redis.
  • Proxy authorised requests to the data API (streaming).
  • Publish a usage log event to Redis pub/sub (→ Logstash → ES).

The gateway is intentionally stateless with respect to business data: it holds
no GWAS metadata and performs no dataset-level access control. All dataset
permissions are simplified to "public" at the data API level for now.
"""

import logging
import shutil
import time
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from neo4j import AsyncGraphDatabase

from app.auth.middleware import AuthMiddleware
from app.config import Settings
from app.limiting.limiter import check_rate_limit, init_limiter
from app.proxy import proxy_request

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting OpenGWAS Gateway v%s (group=%s)", Settings.VERSION, Settings.GROUP)

    # Neo4j async driver — used by auth middleware for every request.
    app.state.neo4j = AsyncGraphDatabase.driver(
        Settings.NEO4J_URI,
        auth=(Settings.NEO4J_USER, Settings.NEO4J_PASSWORD),
        max_connection_lifetime=Settings.NEO4J_MAX_CONNECTION_LIFETIME,
    )

    # Redis client for rate limiting (db=1).
    _redis_url_base = (
        f"redis://:{Settings.REDIS_PASSWORD}"
        f"@{Settings.REDIS_HOST}:{Settings.REDIS_PORT}"
    )
    app.state.redis_limiter = aioredis.from_url(
        f"{_redis_url_base}/{Settings.REDIS_DB_LIMITER}",
        decode_responses=True,
    )

    # Redis client for usage log pub/sub (db=3).
    app.state.redis_log = aioredis.from_url(
        f"{_redis_url_base}/{Settings.REDIS_DB_LOG}",
    )

    # Initialise the limits library rate-limiter (synchronous Redis storage).
    init_limiter()

    # Shared httpx client — long-lived, keeps a connection pool to the data API.
    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=5.0,
            read=300.0,   # large association queries can take a while
            write=60.0,
            pool=10.0,
        ),
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        follow_redirects=False,
    )

    logger.info("Gateway ready. Backends: %s",
                {ns: b['url'] for ns, b in Settings.BACKENDS.items()})

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    await app.state.neo4j.close()
    await app.state.redis_limiter.aclose()
    await app.state.redis_log.aclose()
    await app.state.http_client.aclose()
    logger.info("Gateway shut down cleanly.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title='OpenGWAS Gateway',
    version=Settings.VERSION,
    # The gateway's own spec and docs are off: /openapi.json and /docs below
    # serve the data API's spec instead.
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(AuthMiddleware)


# ── Probe endpoints (no auth) ─────────────────────────────────────────────────

@app.get('/probe/health')
async def probe_health():
    disk_free_mb = 0
    try:
        disk_free_mb = shutil.disk_usage('/').free / 1_048_576
    except Exception:
        pass
    if disk_free_mb >= 512:
        return {'time': int(time.time()), 'disk_free_space_megabytes': disk_free_mb}
    return JSONResponse({'message': 'Disk free space too low'}, status_code=503)


@app.get('/probe/readiness')
async def probe_readiness(request: Request):
    """Readiness check: verify Neo4j and Redis are reachable."""
    try:
        async with request.app.state.neo4j.session() as session:
            await session.run("RETURN 1")
        await request.app.state.redis_limiter.ping()
        return {'message': 'Gateway ready'}
    except Exception as exc:
        logger.error("Readiness check failed: %s", exc)
        return JSONResponse({'message': 'Gateway not ready'}, status_code=503)


# ── Service index, specs and docs (no auth) ───────────────────────────────────

@app.get('/', include_in_schema=False)
async def index():
    """List the services behind the gateway, with their prefixes, specs and docs."""
    return {
        'gateway': {'version': Settings.VERSION},
        'services': [
            {
                'name': ns,
                'prefix': f'/{ns}',
                'spec': f'/{ns}/openapi.json',
                'docs': f'/docs?service={ns}',
            }
            for ns in Settings.BACKENDS
        ],
    }


@app.get('/docs', include_in_schema=False)
async def docs(service: str = next(iter(Settings.BACKENDS))):
    if service not in Settings.BACKENDS:
        return JSONResponse({'message': f'Unknown service {service!r}'}, status_code=404)
    return get_swagger_ui_html(openapi_url=f'/{service}/openapi.json',
                               title=f'OpenGWAS API: {service}')


async def _rate_limit_and_proxy(request: Request, backend: dict, upstream_url: str):
    # Auth is already resolved by AuthMiddleware; request.state.user is set.
    # Rate limiting — returns a 429 response if the limit is exceeded.
    rate_limit_response = check_rate_limit(request)
    if rate_limit_response is not None:
        return rate_limit_response
    return await proxy_request(request, backend, upstream_url)


# ── /api/* → ogdb's /api/* (as before; its future is undecided) ───────────────

# Fails at startup if app_conf.json has no backends.ogdb.
_API_BACKEND = Settings.BACKENDS['ogdb']


@app.api_route('/api/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
async def api_proxy(request: Request, path: str):
    return await _rate_limit_and_proxy(request, _API_BACKEND, f"{_API_BACKEND['url']}/api/{path}")


# ── Namespaced services: /{namespace}/... ─────────────────────────────────────

# Each backend's spec, fetched once and cached; restart to refresh.
_specs: dict[str, dict] = {}


@app.get('/{namespace}/openapi.json', include_in_schema=False)
async def service_spec(request: Request, namespace: str):
    backend = Settings.BACKENDS.get(namespace)
    if backend is None:
        return JSONResponse({'message': f'Unknown service {namespace!r}'}, status_code=404)
    if namespace not in _specs:
        try:
            response = await request.app.state.http_client.get(f"{backend['url']}/openapi.json")
            response.raise_for_status()
            spec = response.json()
        except Exception as exc:
            logger.error("Fetching the %s spec failed: %s", namespace, exc)
            return JSONResponse({'message': 'API specification unavailable'}, status_code=502)
        # Calls from the docs go through the gateway, under the namespace.
        spec['servers'] = [{'url': f'/{namespace}'}]
        _specs[namespace] = spec
    return _specs[namespace]


@app.api_route('/{namespace}/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
async def service_proxy(request: Request, namespace: str, path: str):
    backend = Settings.BACKENDS.get(namespace)
    if backend is None:
        return JSONResponse({'message': 'Not found'}, status_code=404)
    return await _rate_limit_and_proxy(request, backend, f"{backend['url']}/{path}")
