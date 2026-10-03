"""Connect to Postgres and print version + SELECT 1."""
import sys
sys.path.insert(0, ".")

from sqlalchemy import text
from app.db import engine

with engine.connect() as conn:
    one = conn.execute(text("SELECT 1")).scalar()
    version = conn.execute(text("SELECT version()")).scalar()
    print("SELECT 1  =>", one)
    print("Postgres  =>", version)
