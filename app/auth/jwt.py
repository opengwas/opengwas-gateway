"""
JWT validation for the gateway.

Ported from resources/jwt.py in the monolith with the Flask dependency removed.

Important: OpenGWAS JWTs are NOT purely self-contained. The token's `iat` claim
must match the `jwt_timestamp` stored on the User node in Neo4j. This is the
server-side invalidation mechanism: when a user generates a new token via the UI,
their jwt_timestamp is updated and all previously issued tokens are silently
revoked. The Neo4j lookup in validate_token() cannot be skipped.
"""

import time

import jwt as pyjwt
from fastapi import HTTPException, status
from neo4j import AsyncDriver

from app.config import Settings
from app.auth.user import get_user_by_uid, get_user_tier, is_blocked


_INVALID_TOKEN_DETAIL = (
    "Invalid token. Visit https://api.opengwas.io to obtain one and make sure "
    "there are no extra or missing characters around the token when you copy and "
    "paste. If you are using R/ieugwasr, R/TwoSampleMR or derived packages, see "
    "https://mrcieu.github.io/ieugwasr/articles/guide.html#authentication"
)


async def validate_token(authorization: str, driver: AsyncDriver) -> dict:
    """
    Validate a Bearer token and return the user dict with an added '_tier' key.

    Raises HTTPException (401) on any failure.
    """
    token = authorization.removeprefix('Bearer ').strip()

    # 1. Verify signature and standard claims (exp, aud) — stateless.
    try:
        payload = pyjwt.decode(
            token,
            Settings.JWT_PUBLIC_KEY,
            algorithms=['RS256'],
            audience=Settings.JWT_AUDIENCE,
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token has expired. Please generate a new token.")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_INVALID_TOKEN_DETAIL)

    uid = payload.get('sub')
    if not uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=_INVALID_TOKEN_DETAIL)

    # 2. Fetch user from Neo4j — required for server-side invalidation check.
    user = await get_user_by_uid(driver, uid)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User does not exist.")

    # 3. Server-side token invalidation: iat must match the stored jwt_timestamp.
    if 'jwt_timestamp' not in user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Please generate a new token.")

    if (
        int(time.time()) > payload['iat'] + Settings.JWT_VALIDITY
        or payload['iat'] != user['jwt_timestamp']
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Please generate a new token.")

    # 4. Account block check.
    if is_blocked(user):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="This account has been temporarily suspended.")

    # Attach derived tier so downstream middleware can read it without recomputing.
    user['_tier'] = get_user_tier(user)
    return user
