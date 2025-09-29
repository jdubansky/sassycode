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


