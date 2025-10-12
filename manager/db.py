import os
from contextlib import contextmanager
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session


class Base(DeclarativeBase):
    pass


def get_database_url() -> str:
    load_dotenv()
    return os.getenv("DATABASE_URL", "sqlite:///./sassycode.db")


engine = create_engine(get_database_url(), future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)


def init_db() -> None:
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def migrate_db() -> None:
    """Lightweight, SQLite-focused migrations for additive columns.

    Adds newly introduced nullable columns to existing tables if they don't exist.
    Safe to run repeatedly.
    """
    with engine.begin() as conn:
        # Only handle SQLite for now
        dialect_name = conn.dialect.name
        if dialect_name != "sqlite":
            return

        def table_columns(table_name: str) -> set[str]:
            rows = conn.exec_driver_sql(f"PRAGMA table_info('{table_name}')").fetchall()
            return {row[1] for row in rows}  # column name at index 1

        # findings: add extra detail columns if missing
        existing = table_columns("findings")
        adds: list[tuple[str, str]] = []
        if "function_name" not in existing:
            adds.append(("function_name", "TEXT"))
        if "entrypoint" not in existing:
            adds.append(("entrypoint", "TEXT"))
        if "arguments" not in existing:
            adds.append(("arguments", "TEXT"))
        if "root_cause" not in existing:
            adds.append(("root_cause", "TEXT"))
        if "details_json" not in existing:
            adds.append(("details_json", "TEXT"))

        for col, coltype in adds:
            conn.exec_driver_sql(f"ALTER TABLE findings ADD COLUMN {col} {coltype} NULL")

        # unique_findings: create table if not exists (SQLite lacks IF NOT EXISTS for constraints, but CREATE TABLE IF NOT EXISTS is fine)
        conn.exec_driver_sql(
            """
CREATE TABLE IF NOT EXISTS unique_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint VARCHAR(128) NOT NULL,
    file_path TEXT NOT NULL,
    cwe VARCHAR(256),
    function_name VARCHAR(255),
    entrypoint VARCHAR(255),
    first_seen_at DATETIME,
    last_seen_at DATETIME,
    occurrences INTEGER,
    last_line INTEGER,
    last_severity VARCHAR(16),
    last_description TEXT,
    severity VARCHAR(16),
    description TEXT
);
"""
        )

        # Add unique index for (project_id, fingerprint)
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_unique_finding_fingerprint ON unique_findings(project_id, fingerprint)"
        )

        # Add unique_finding_id to findings if missing
        existing = table_columns("findings")
        if "unique_finding_id" not in existing:
            conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN unique_finding_id INTEGER NULL REFERENCES unique_findings(id) ON DELETE SET NULL")

        # Add newly introduced columns if missing on existing DBs
        existing_unique = table_columns("unique_findings")
        for col, coltype in [
            ("severity", "VARCHAR(16)"),
            ("description", "TEXT"),
            ("status", "VARCHAR(24)"),
        ]:
            if col not in existing_unique:
                conn.exec_driver_sql(f"ALTER TABLE unique_findings ADD COLUMN {col} {coltype} NULL")

        # Add ignore_globs to projects if missing
        existing_projects = table_columns("projects")
        if "ignore_globs" not in existing_projects:
            conn.exec_driver_sql("ALTER TABLE projects ADD COLUMN ignore_globs TEXT NULL")

        # Create schedules tables if not exist
        conn.exec_driver_sql(
            """
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(255) NOT NULL,
    cron VARCHAR(64) NOT NULL,
    model VARCHAR(255) NOT NULL,
    deep INTEGER DEFAULT 0,
    created_at DATETIME,
    last_run_at DATETIME
);
"""
        )
        conn.exec_driver_sql(
            """
CREATE TABLE IF NOT EXISTS schedule_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id INTEGER NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE
);
"""
        )


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


