"""
Neo4j user resolution and tier/block helpers.

Ported from queries/user_node.py and middleware/auth.py in the monolith,
with the Flask-Login dependency removed and rewritten for the async Neo4j driver.
"""

import time

from neo4j import AsyncDriver


# ── User lookup ───────────────────────────────────────────────────────────────

async def get_user_by_uid(driver: AsyncDriver, uid: str) -> dict | None:
    """Return the Neo4j User node as a plain dict, or None if not found."""
    async with driver.session() as session:
        result = await session.run(
            "MATCH (u:User {uid: $uid}) RETURN u",
            uid=uid,
        )
        record = await result.single()
        if record is None:
            return None
        return dict(record['u'])


# ── Derived user properties ───────────────────────────────────────────────────

def get_user_tier(user: dict) -> str:
    """
    Map a user's Neo4j tags to a rate-limit tier string.
    Order matters: trial takes precedence over commercial to avoid misclassification
    if a user somehow ends up with both tags during a transition.
    """
    tags = user.get('tags', [])
    if 'trial' in tags:
        return 'TRIAL'
    if 'commercial' in tags:
        return 'COMMERCIAL'
    try:
        # UoB staff/students get a higher allowance via institutional email.
        if user['uid'].split('@')[1] == 'bristol.ac.uk':
            return 'UOB'
    except (KeyError, IndexError):
        pass
    return 'STANDARD'


def is_blocked(user: dict) -> bool:
    """True if the user's account is temporarily blocked."""
    return int(user.get('blocked_until', 0)) > int(time.time())
