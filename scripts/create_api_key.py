"""Create an API key. Prints the raw key once and stores only the hash.

Usage:
    python scripts/create_api_key.py --name alice --scope read,write
    python scripts/create_api_key.py --name bob   --scope read
    python scripts/create_api_key.py --revoke alice
"""
from __future__ import annotations

import argparse
import secrets
import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")

from sqlalchemy import select

from app.api.auth import hash_key
from app.db import session_scope
from app.models import ApiKey


def create(name: str, scope: str) -> str:
    raw = secrets.token_urlsafe(32)
    with session_scope() as s:
        existing = s.execute(select(ApiKey).where(ApiKey.name == name)).scalar_one_or_none()
        if existing:
            raise SystemExit(f"key named '{name}' already exists (use --revoke first)")
        s.add(ApiKey(name=name, key_hash=hash_key(raw), scope=scope))
    return raw


def revoke(name: str) -> None:
    with session_scope() as s:
        row = s.execute(select(ApiKey).where(ApiKey.name == name)).scalar_one_or_none()
        if row is None:
            raise SystemExit(f"no key named '{name}'")
        row.revoked_at = datetime.now(timezone.utc)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=False)
    p.add_argument("--scope", default="read,write")
    p.add_argument("--revoke", metavar="NAME")
    args = p.parse_args()

    if args.revoke:
        revoke(args.revoke)
        print(f"revoked '{args.revoke}'")
        return 0

    if not args.name:
        p.error("--name is required (or use --revoke NAME)")

    raw = create(args.name, args.scope)
    print("=" * 64)
    print(f"  name:  {args.name}")
    print(f"  scope: {args.scope}")
    print(f"  key:   {raw}")
    print("=" * 64)
    print("Store this NOW. It is not recoverable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
