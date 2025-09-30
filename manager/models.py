from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    model: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    unique_finding_id: Mapped[Optional[int]] = mapped_column(ForeignKey("unique_findings.id", ondelete="SET NULL"), nullable=True)
    file_path: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)  # comma-separated
    description: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    function_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    entrypoint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    arguments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # comma-separated
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class UniqueFinding(Base):
    __tablename__ = "unique_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(128))
    file_path: Mapped[str] = mapped_column(Text)
    cwe: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    function_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    entrypoint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    last_line: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    last_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Canonical/representative values
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_unique_finding_fingerprint"),
    )


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255))
    cron: Mapped[str] = mapped_column(String(64))  # cron expression
    model: Mapped[str] = mapped_column(String(255), default="gpt-4o-mini")
    deep: Mapped[bool] = mapped_column(Integer, default=0)  # 0/1
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    projects: Mapped[list["ScheduleProject"]] = relationship(back_populates="schedule", cascade="all, delete-orphan")


class ScheduleProject(Base):
    __tablename__ = "schedule_projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    schedule_id: Mapped[int] = mapped_column(ForeignKey("schedules.id", ondelete="CASCADE"))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))

    schedule: Mapped[Schedule] = relationship(back_populates="projects")


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    level: Mapped[str] = mapped_column(String(16), default="INFO")
    message: Mapped[str] = mapped_column(Text)


