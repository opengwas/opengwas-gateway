"""
Authentication middleware.

Runs before every request. On success it sets:
  request.state.user      — Neo4j user dict with an added '_tier' key
  request.state.source    — {'client': str, 'version': str} parsed from X-API-SOURCE
  request.state.service   — name of the calling component, if a service key was used

Requests to /probe/*, the service index (/), /docs and each service's
/{namespace}/openapi.json are passed through unauthenticated.

Service-key auth (internal components, not end users):
  X-Service-Key: <key>  →  accepted if it matches any key in Settings.SERVICE_KEYS

Test-mode bypass (non-prod only):
  X-TEST-MODE-KEY: <static_token>  →  uses the configured test uid, skips JWT
"""

import hmac

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import Settings
from app.auth.jwt import validate_token
from app.auth.user import get_user_by_uid, get_user_tier


_UNAUTHENTICATED_PATHS = {
    '/probe/health', '/probe/readiness', '/', '/docs',
    *(f'/{ns}/openapi.json' for ns in Settings.BACKENDS),
}


def _parse_source_header(request: Request) -> dict:
    """Parse X-API-SOURCE into {client, version}. Mirrors before_request.py logic."""
    source = {'client': '', 'version': ''}
    raw = request.headers.get('X-API-SOURCE', '')
    if raw:
        parts = raw.rsplit('/', maxsplit=1)
        if len(parts) > 1 and any(c.isdigit() for c in parts[1]):
            source['client'] = parts[0]
            source['version'] = parts[1]
        else:
            source['client'] = raw
    return source


def _match_service_key(request: Request) -> str | None:
    """Return the component name whose key matches X-Service-Key, or None."""
    provided = request.headers.get('X-Service-Key', '')
    if not provided:
        return None
    for name, key in Settings.SERVICE_KEYS.items():
        if hmac.compare_digest(provided.encode(), key.encode()):
            return name
    return None


class AuthMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        # Always parse source header — needed for usage logging regardless of auth path.
        request.state.source = _parse_source_header(request)
        request.state.user = None
        request.state.service = None

        # Probe endpoints and root are unauthenticated.
        if request.url.path in _UNAUTHENTICATED_PATHS:
            return await call_next(request)

        # ── Service-key auth (internal components) ────────────────────────────
        if request.headers.get('X-Service-Key'):
            service = _match_service_key(request)
            if service is None:
                return JSONResponse({'message': 'Invalid service key.'}, status_code=401)
            request.state.service = service
            return await call_next(request)

        driver = request.app.state.neo4j

        # ── Test-mode bypass (non-production only) ────────────────────────────
        if Settings.GROUP not in ('prod', 'test'):
            test_key = request.headers.get('X-TEST-MODE-KEY', '')
            if test_key and test_key == Settings.TEST_STATIC_TOKEN:
                user = await get_user_by_uid(driver, Settings.TEST_UID)
                if user:
                    user['_tier'] = get_user_tier(user)
                    request.state.user = user
                    return await call_next(request)

        # ── Standard JWT auth ─────────────────────────────────────────────────
        authorization = request.headers.get('Authorization', '')
        if not authorization:
            return JSONResponse(
                {'message': 'Missing token. Provide a Bearer token in the Authorization header.'},
                status_code=401,
            )

        try:
            user = await validate_token(authorization, driver)
        except Exception as exc:
            detail = getattr(exc, 'detail', str(exc))
            code = getattr(exc, 'status_code', 401)
            return JSONResponse({'message': detail}, status_code=code)

        request.state.user = user
        return await call_next(request)
