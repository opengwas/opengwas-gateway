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

    logger.info("Gateway ready. Data API upstream: %s", Settings.DATA_API_URL)

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
    # Disable the auto-generated docs on the gateway itself — the data API's
    # Swagger UI is what clients should use.
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


# ── API proxy (all methods, all paths under /api/) ────────────────────────────

@app.api_route('/api/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
async def api_proxy(request: Request, path: str):
    # Auth is already resolved by AuthMiddleware; request.state.user is set.

    # Rate limiting — returns a 429 response if the limit is exceeded.
    rate_limit_response = check_rate_limit(request)
    if rate_limit_response is not None:
        return rate_limit_response

    return await proxy_request(request, path)
