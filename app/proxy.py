"""
Reverse proxy to the data API.

Uses httpx streaming so large association payloads (potentially hundreds of MB)
are never buffered in the gateway — bytes flow straight from the data API socket
to the client socket.

Request flow:
  1. Build the upstream URL from DATA_API_URL + original path + query string.
  2. Forward request headers, stripping hop-by-hop headers and X-Service-Key.
     Replace the caller's Authorization with the gateway's own data API token.
  3. Stream the response body back to the client.
  4. Close the upstream connection in a BackgroundTask after streaming completes.
  5. Attach rate-limit headers (X-Allowance-*) to the response.
  6. Fire the usage log event (also in a BackgroundTask — never blocks the client).
"""

import time

import httpx
from fastapi import Request
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTasks

from app.config import Settings
from app.limiting.limiter import get_allowance_headers
from app.logging.usage import log_usage


# Headers that must not be forwarded between hops (RFC 7230 §6.1).
_HOP_BY_HOP = frozenset({
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade',
    # Also strip the incoming host — httpx will set the correct host for upstream.
    'host',
    # Strip incoming content-length; httpx recalculates it.
    'content-length',
    # Service keys authenticate callers to the gateway only — never pass them on.
    'x-service-key',
    # The data API trusts this under the gateway's key, so only the gateway sets it.
    'x-ogdb-user',
})


def _forward_headers(request: Request) -> dict[str, str]:
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != 'authorization'
    }
    headers['Authorization'] = f"Bearer {Settings.DATA_API_KEY}"
    user = getattr(request.state, 'user', None)
    if user and user.get('uuid'):
        headers['X-OGDB-User'] = user['uuid']
    elif getattr(request.state, 'service', None) and Settings.DATA_API_SERVICE_UUID:
        headers['X-OGDB-User'] = Settings.DATA_API_SERVICE_UUID
    return headers


def _get_remote_addr(request: Request) -> str | None:
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.client.host if request.client else None


async def proxy_request(request: Request, path: str) -> StreamingResponse:
    """
    Proxy the request to the data API and stream the response back.
    Rate-limit headers and the usage log are attached/fired after the upstream
    response headers arrive but before the body starts streaming.
    """
    client: httpx.AsyncClient = request.app.state.http_client
    redis_log = request.app.state.redis_log

    upstream_url = f"{Settings.DATA_API_URL}/{path}"
    t_start = time.monotonic()

    # Build the upstream request (don't send it yet — we want streaming).
    upstream_request = client.build_request(
        method=request.method,
        url=upstream_url,
        headers=_forward_headers(request),
        params=request.query_params,
        content=request.stream(),
    )

    response = await client.send(upstream_request, stream=True)

    duration_ms = (time.monotonic() - t_start) * 1000

    # ── Usage logging (fire-and-forget) ───────────────────────────────────────
    user = getattr(request.state, 'user', None)
    source = getattr(request.state, 'source', {})

    log_usage(
        redis_log,
        uid=user['uid'] if user else None,
        tier=user.get('_tier') if user else None,
        remote_addr=_get_remote_addr(request),
        method=request.method,
        path=str(request.url.path),
        query_string=str(request.url.query),
        source_client=source.get('client', ''),
        source_version=source.get('version', ''),
        user_agent=request.headers.get('User-Agent', ''),
        request_size=int(request.headers.get('Content-Length', 0)),
        status_code=response.status_code,
        # Content-Length may not be present for chunked responses.
        response_size=int(response.headers.get('Content-Length', -1)),
        duration_ms=duration_ms,
    )

    # ── Response headers ───────────────────────────────────────────────────────
    # Forward upstream headers, skip hop-by-hop, add rate-limit allowance headers.
    response_headers = {
        k: v for k, v in response.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    response_headers.update(get_allowance_headers(request))

    # ── Stream body ────────────────────────────────────────────────────────────
    # response.aclose() is called in a BackgroundTask so the upstream connection
    # is released only after all bytes have been consumed by the client.
    background = BackgroundTasks()
    background.add_task(response.aclose)

    return StreamingResponse(
        response.aiter_bytes(),
        status_code=response.status_code,
        headers=response_headers,
        background=background,
    )
