import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, case, or_
from croniter import croniter
import time

from .db import init_db, migrate_db, session_scope, SessionLocal
from .models import Project, Scan, Finding, ScanLog, UniqueFinding, Schedule, ScheduleProject


load_dotenv()
app = FastAPI(title="sassycode manager")

base_dir = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(base_dir / "templates"))
templates.env.globals["loads"] = json.loads

static_dir = base_dir / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Track running scan processes
RUNNING_PROCS: dict[int, subprocess.Popen] = {}
RUNNING_LOCK = threading.Lock()
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "2"))
SCAN_SEM = threading.Semaphore(MAX_CONCURRENT_SCANS)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/favicon.ico", include_in_schema=False)
def favicon_redirect():
    return RedirectResponse(url="/static/favicon.svg")


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
def chrome_devtools_probe():
    # Chrome devtools probes this path; return empty JSON instead of 404 noise
    return JSONResponse(content={})


@app.on_event("startup")
def on_startup():
    init_db()
    migrate_db()
    # Start scheduler thread
    t = threading.Thread(target=_scheduler_loop, daemon=True)
    t.start()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    projects = db.query(Project).all()
    # Build per-project unique severity counts (using canonical severity if present, else last_severity)
    counts: dict[int, dict[str, int]] = {}
    for p in projects:
        rows = (
            db.query(
                (UniqueFinding.severity).label("sev"),
                (UniqueFinding.last_severity).label("last_sev"),
            )
            .filter(UniqueFinding.project_id == p.id)
            .all()
        )
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for sev, last_sev in rows:
            s = sev or last_sev or "LOW"
            if s in c:
                c[s] += 1
            else:
                c["LOW"] += 1
        counts[p.id] = c
    return templates.TemplateResponse("index.html", {"request": request, "projects": projects, "counts": counts})
@app.get("/schedules", response_class=HTMLResponse)
def schedules_page(request: Request, db: Session = Depends(get_db)):
    schedules = db.query(Schedule).all()
    projects = db.query(Project).all()
    # Build mapping of schedule_id -> [project names]
    from sqlalchemy import select
    schedule_projects_map: dict[int, list[str]] = {}
    links = db.query(ScheduleProject, Project).join(Project, ScheduleProject.project_id == Project.id).all()
    for link, proj in links:
        schedule_projects_map.setdefault(link.schedule_id, []).append(proj.name)
    return templates.TemplateResponse(
        "schedules.html",
        {"request": request, "schedules": schedules, "projects": projects, "schedule_projects_map": schedule_projects_map},
    )

@app.post("/schedules")
def create_schedule(name: str = Form(...), cron: str = Form(...), model: str = Form(...), deep: str = Form(None), project_ids: str = Form(""), db: Session = Depends(get_db)):
    s = Schedule(name=name, cron=cron, model=model, deep=1 if deep else 0)
    db.add(s)
    db.flush()
    ids = [int(x) for x in (project_ids.split(",") if project_ids else []) if x]
    for pid in ids:
        db.add(ScheduleProject(schedule_id=s.id, project_id=pid))
    db.commit()
    return RedirectResponse(url="/schedules", status_code=303)


@app.post("/schedules/{schedule_id}/delete")
def delete_schedule(schedule_id: int, db: Session = Depends(get_db)):
    s = db.get(Schedule, schedule_id)
    if s:
        db.delete(s)
        db.commit()
    return RedirectResponse(url="/schedules", status_code=303)


@app.post("/projects")
def create_project(name: str = Form(...), path: str = Form(...), db: Session = Depends(get_db)):
    p = Project(name=name, path=path)
    db.add(p)
    db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        return RedirectResponse(url="/", status_code=303)
    scans = db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.id.desc()).all()
    # Expose db and models to template for Unique Findings query
    from . import models as models
    return templates.TemplateResponse("project.html", {"request": request, "project": project, "scans": scans, "db": db, "models": models})


@app.get("/projects/{project_id}/edit", response_class=HTMLResponse)
def edit_project(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("project_edit.html", {"request": request, "project": project})


@app.post("/projects/{project_id}")
def update_project(project_id: int, name: str = Form(...), path: str = Form(...), ignore_globs: str = Form(""), only_filenames: str = Form(""), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        return RedirectResponse(url="/", status_code=303)
    project.name = name
    project.path = path
    project.ignore_globs = ignore_globs or None
    project.only_filenames = only_filenames or None
    db.add(project)
    db.commit()
    return RedirectResponse(url=f"/projects/{project_id}", status_code=303)


@app.post("/projects/{project_id}/delete")
def delete_project(project_id: int, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if project:
        db.delete(project)
        db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/scans")
def trigger_scan(project_id: int = Form(...), model: str = Form(...), deep: str = Form(None), include_related: str = Form(None), concurrency: int = Form(4), branch_name: str = Form(""), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        return RedirectResponse(url="/", status_code=303)

    scan = Scan(project_id=project.id, model=model, status="running", started_at=datetime.utcnow(), scan_type=("branch" if branch_name else "full"), branch_name=(branch_name or None))
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch scanner in background and ingest results
    # Use module invocation to avoid relying on entry-point resolution
    cmd = [
        sys.executable,
        "-m",
        "scanner.cli",
        "scan",
        "--path",
        project.path,
        "--model",
        model,
        "--verbose",
    ]
    if branch_name:
        cmd += ["--branch", branch_name]
    if deep:
        cmd.append("--deep")
    if project.ignore_globs:
        cmd += ["--ignore", project.ignore_globs]
    if include_related:
        cmd.append("--include-related")
    if project.only_filenames:
        cmd += ["--only-names", project.only_filenames]
    if concurrency:
        try:
            c = max(1, int(concurrency))
            cmd += ["--concurrency", str(c)]
        except Exception:
            pass

    # seed a startup log so UI shows activity immediately
    with session_scope() as session:
        session.add(ScanLog(scan_id=scan.id, level="INFO", message=f"Starting scan for {project.path} using {model}"))

    def run_and_ingest(scan_id: int):
        success = False
        try:
            SCAN_SEM.acquire()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            with RUNNING_LOCK:
                RUNNING_PROCS[scan_id] = proc

            stdout_chunks: list[str] = []

            # Readers for both pipes to avoid deadlock
            def _read_stderr():
                assert proc.stderr is not None
                for line in proc.stderr:
                    msg = line.rstrip("\n")
                    print(f"[scanner] {msg}")
                    with session_scope() as session:
                        session.add(ScanLog(scan_id=scan_id, level="INFO", message=msg))

            def _read_stdout():
                assert proc.stdout is not None
                for chunk in proc.stdout:
                    stdout_chunks.append(chunk)

            t_err = threading.Thread(target=_read_stderr, daemon=True)
            t_out = threading.Thread(target=_read_stdout, daemon=True)
            t_err.start(); t_out.start()

            proc.wait()
            t_err.join(timeout=1)
            t_out.join(timeout=1)

            stdout = "".join(stdout_chunks).strip()
            obj = json.loads(stdout) if stdout else {}
            findings = obj.get("findings", [])
            with session_scope() as session:
                for f in findings:
                    # Build fingerprint: file_path + cwe + function_name + entrypoint (normalized)
                    fp_parts = [
                        (f.get("file_path") or "").strip().lower(),
                        ",".join(f.get("cwe", []) or []) if isinstance(f.get("cwe"), list) else (f.get("cwe") or ""),
                        (f.get("function_name") or "").strip().lower(),
                        (f.get("entrypoint") or "").strip().lower(),
                    ]
                    fingerprint = "|".join(fp_parts)

                    # Upsert UniqueFinding
                    uf = session.query(UniqueFinding).filter(
                        UniqueFinding.project_id == project.id,
                        UniqueFinding.fingerprint == fingerprint,
                    ).one_or_none()
                    if uf is None:
                        uf = UniqueFinding(
                            project_id=project.id,
                            fingerprint=fingerprint,
                            file_path=f.get("file_path", ""),
                            cwe=",".join(f.get("cwe", []) or []) or None,
                            function_name=f.get("function_name"),
                            entrypoint=f.get("entrypoint"),
                            last_line=f.get("line"),
                            last_severity=f.get("severity"),
                            last_description=f.get("description"),
                            severity=f.get("severity"),
                            description=f.get("description"),
                        )
                        session.add(uf)
                        session.flush()
                    else:
                        uf.last_seen_at = datetime.utcnow()
                        uf.occurrences = (uf.occurrences or 0) + 1
                        uf.last_line = f.get("line")
                        uf.last_severity = f.get("severity")
                        uf.last_description = f.get("description")
                        # Optionally update canonical severity/description (prefer highest severity)
                        sev = f.get("severity")
                        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                        if sev and (uf.severity is None or sev_order.get(sev, 0) > sev_order.get(uf.severity, 0)):
                            uf.severity = sev
                        if not uf.description and f.get("description"):
                            uf.description = f.get("description")

                    session.add(
                        Finding(
                            scan_id=scan_id,
                            unique_finding_id=uf.id,
                            file_path=f.get("file_path", ""),
                            severity=f.get("severity", "LOW"),
                            line=f.get("line"),
                            rule_id=f.get("rule_id"),
                            cwe=",".join(f.get("cwe", []) or []) or None,
                            description=f.get("description", ""),
                            recommendation=f.get("recommendation"),
                            confidence=f.get("confidence"),
                            function_name=f.get("function_name"),
                            entrypoint=f.get("entrypoint"),
                            arguments=",".join(f.get("arguments", []) or []) or None,
                            root_cause=f.get("root_cause"),
                            details_json=json.dumps(f.get("details")) if f.get("details") else None,
                        )
                    )
                success = True
        except Exception as e:
            with session_scope() as session:
                session.add(ScanLog(scan_id=scan_id, level="ERROR", message=str(e)))
        finally:
            with RUNNING_LOCK:
                RUNNING_PROCS.pop(scan_id, None)
            with session_scope() as session:
                sc = session.get(Scan, scan_id)
                if sc:
                    # Respect external cancellation or failure
                    if sc.status == "running":
                        if success:
                            sc.status = "completed"
                        else:
                            sc.status = "failed"
                    if not sc.completed_at:
                        sc.completed_at = datetime.utcnow()
            SCAN_SEM.release()

    threading.Thread(target=run_and_ingest, args=(scan.id,), daemon=True).start()

    return RedirectResponse(url=f"/projects/{project.id}", status_code=303)


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        return RedirectResponse(url="/", status_code=303)
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_id).order_by(ScanLog.id.asc()).all()
    return templates.TemplateResponse("scan.html", {"request": request, "scan": scan, "findings": findings, "logs": logs})


@app.get("/scans/{scan_id}/logs.json")
def scan_logs_json(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        return {"error": "not_found"}
    logs = db.query(ScanLog).filter(ScanLog.scan_id == scan_id).order_by(ScanLog.id.asc()).all()
    can_cancel = scan.status == "running"
    return {
        "status": scan.status,
        "can_cancel": can_cancel,
        "logs": [
            {"created_at": l.created_at.isoformat(), "level": l.level, "message": l.message}
            for l in logs
        ],
    }


# Ingest endpoint for CI/CD posts from the scanner CLI
@app.post("/api/ingest")
def ingest_results(payload: dict, db: Session = Depends(get_db)):
    # Expected payload: { project_name, project_path, model, generated_at, findings: [...] }
    project_name = payload.get("project_name") or payload.get("project") or "Unnamed"
    project_path = payload.get("project_path") or ""
    model = payload.get("model") or "unknown"
    findings = payload.get("findings") or []
    scan_type = payload.get("scan_type")
    branch_name = payload.get("head_ref") or payload.get("branch_name")
    base_sha = payload.get("base_sha")
    head_sha = payload.get("head_sha")

    # Upsert project by name
    project = db.query(Project).filter(Project.name == project_name).one_or_none()
    if project is None:
        project = Project(name=project_name, path=project_path)
        db.add(project)
        db.flush()
    else:
        # update path if provided
        if project_path:
            project.path = project_path

    # Create a scan row
    scan = Scan(project_id=project.id, model=model, status="completed", started_at=datetime.utcnow(), completed_at=datetime.utcnow(), scan_type=scan_type, branch_name=branch_name, base_sha=base_sha, head_sha=head_sha)
    db.add(scan)
    db.flush()

    # Ingest findings using the same unique finding logic
    for f in findings:
        fp_parts = [
            (f.get("file_path") or "").strip().lower(),
            ",".join(f.get("cwe", []) or []) if isinstance(f.get("cwe"), list) else (f.get("cwe") or ""),
            (f.get("function_name") or "").strip().lower(),
            (f.get("entrypoint") or "").strip().lower(),
        ]
        fingerprint = "|".join(fp_parts)
        uf = db.query(UniqueFinding).filter(UniqueFinding.project_id == project.id, UniqueFinding.fingerprint == fingerprint).one_or_none()
        if uf is None:
            uf = UniqueFinding(project_id=project.id, fingerprint=fingerprint, file_path=f.get("file_path", ""), cwe=",".join(f.get("cwe", []) or []) or None, function_name=f.get("function_name"), entrypoint=f.get("entrypoint"), last_line=f.get("line"), last_severity=f.get("severity"), last_description=f.get("description"), severity=f.get("severity"), description=f.get("description"))
            db.add(uf)
            db.flush()
        else:
            uf.last_seen_at = datetime.utcnow()
            uf.occurrences = (uf.occurrences or 0) + 1
            uf.last_line = f.get("line")
            uf.last_severity = f.get("severity")
            uf.last_description = f.get("description")

        db.add(Finding(scan_id=scan.id, unique_finding_id=uf.id, file_path=f.get("file_path", ""), severity=f.get("severity", "LOW"), line=f.get("line"), rule_id=f.get("rule_id"), cwe=",".join(f.get("cwe", []) or []) or None, description=f.get("description", ""), recommendation=f.get("recommendation"), confidence=f.get("confidence"), function_name=f.get("function_name"), entrypoint=f.get("entrypoint"), arguments=",".join(f.get("arguments", []) or []) or None, root_cause=f.get("root_cause"), details_json=json.dumps(f.get("details")) if f.get("details") else None))

    db.commit()
    return {"status": "ok", "project_id": project.id, "scan_id": scan.id, "num_findings": len(findings)}


def _scheduler_loop():
    while True:
        try:
            with session_scope() as session:
                schedules = session.query(Schedule).all()
                now = datetime.utcnow()
                for s in schedules:
                    base = s.last_run_at or (now - timedelta(minutes=1))
                    itr = croniter(s.cron, base)
                    next_time = itr.get_next(datetime)
                    if next_time <= now:
                        # mark last_run
                        s.last_run_at = now
                        session.flush()
                        # queue scans for selected projects
                        proj_links = session.query(ScheduleProject).filter(ScheduleProject.schedule_id == s.id).all()
                        for link in proj_links:
                            p = session.get(Project, link.project_id)
                            if not p:
                                continue
                            # trigger scan similar to POST /scans
                            scan = Scan(project_id=p.id, model=s.model, status="running", started_at=datetime.utcnow())
                            session.add(scan)
                            session.flush()
                            # seed startup log
                            session.add(ScanLog(scan_id=scan.id, level="INFO", message=f"Scheduled run: {s.name}"))
                            # Build command
                            cmd = [
                                sys.executable,
                                "-m",
                                "scanner.cli",
                                "scan",
                                "--path",
                                p.path,
                                "--model",
                                s.model,
                                "--verbose",
                            ]
                            if s.deep:
                                cmd.append("--deep")
                            # attach ignore globs from project if present
                            if p.ignore_globs:
                                cmd += ["--ignore", p.ignore_globs]
                            if getattr(p, "only_filenames", None):
                                cmd += ["--only-names", p.only_filenames]
                            # include related files context for scheduled runs as well
                            cmd.append("--include-related")

                            def run_and_ingest_bg(scan_id: int, cmd_list: list[str]):
                                # Reuse logic from trigger_scan
                                success = False
                                try:
                                    SCAN_SEM.acquire()
                                    proc = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
                                    with RUNNING_LOCK:
                                        RUNNING_PROCS[scan_id] = proc
                                    stdout_chunks: list[str] = []
                                    assert proc.stderr is not None
                                    for line in proc.stderr:
                                        msg = line.rstrip("\n")
                                        with session_scope() as s2:
                                            s2.add(ScanLog(scan_id=scan_id, level="INFO", message=msg))
                                    if proc.stdout:
                                        stdout_chunks.append(proc.stdout.read() or "")
                                    proc.wait()
                                    stdout = "".join(stdout_chunks).strip()
                                    obj = json.loads(stdout) if stdout else {}
                                    findings = obj.get("findings", [])
                                    with session_scope() as s3:
                                        for f in findings:
                                            # upsert unique (simplified: call existing path by reusing code is complex here)
                                            fp_parts = [
                                                (f.get("file_path") or "").strip().lower(),
                                                ",".join(f.get("cwe", []) or []) if isinstance(f.get("cwe"), list) else (f.get("cwe") or ""),
                                                (f.get("function_name") or "").strip().lower(),
                                                (f.get("entrypoint") or "").strip().lower(),
                                            ]
                                            fingerprint = "|".join(fp_parts)
                                            uf = s3.query(UniqueFinding).filter(UniqueFinding.project_id == p.id, UniqueFinding.fingerprint == fingerprint).one_or_none()
                                            if uf is None:
                                                uf = UniqueFinding(project_id=p.id, fingerprint=fingerprint, file_path=f.get("file_path", ""), cwe=",".join(f.get("cwe", []) or []) or None, function_name=f.get("function_name"), entrypoint=f.get("entrypoint"), last_line=f.get("line"), last_severity=f.get("severity"), last_description=f.get("description"), severity=f.get("severity"), description=f.get("description"))
                                                s3.add(uf)
                                                s3.flush()
                                            else:
                                                uf.last_seen_at = datetime.utcnow()
                                                uf.occurrences = (uf.occurrences or 0) + 1
                                                uf.last_line = f.get("line")
                                                uf.last_severity = f.get("severity")
                                                uf.last_description = f.get("description")
                                            s3.add(Finding(scan_id=scan_id, unique_finding_id=uf.id, file_path=f.get("file_path", ""), severity=f.get("severity", "LOW"), line=f.get("line"), rule_id=f.get("rule_id"), cwe=",".join(f.get("cwe", []) or []) or None, description=f.get("description", ""), recommendation=f.get("recommendation"), confidence=f.get("confidence"), function_name=f.get("function_name"), entrypoint=f.get("entrypoint"), arguments=",".join(f.get("arguments", []) or []) or None, root_cause=f.get("root_cause"), details_json=json.dumps(f.get("details")) if f.get("details") else None))
                                        scx = s3.get(Scan, scan_id)
                                        if scx:
                                            scx.status = "completed"
                                            scx.completed_at = datetime.utcnow()
                                    success = True
                                except Exception:
                                    with session_scope() as s4:
                                        scx = s4.get(Scan, scan_id)
                                        if scx:
                                            scx.status = "failed"
                                            scx.completed_at = datetime.utcnow()
                                finally:
                                    with RUNNING_LOCK:
                                        RUNNING_PROCS.pop(scan_id, None)
                                    SCAN_SEM.release()

                            print(f"[scheduler] triggered {s.name} for project {p.name} (scan #{scan.id})")
                            threading.Thread(target=run_and_ingest_bg, args=(scan.id, cmd), daemon=True).start()
        except Exception as e:
            print(f"[scheduler] error: {e}")
        time.sleep(30)


@app.get("/unique", response_class=HTMLResponse)
def unique_findings_all(
    request: Request,
    q: str = "",
    sort: str = "last_seen_desc",
    page: int = 1,
    page_size: int = 20,
    db: Session = Depends(get_db),
):
    page = max(1, int(page))
    page_size = max(1, min(100, int(page_size)))

    base = db.query(UniqueFinding, Project).join(Project, UniqueFinding.project_id == Project.id)

    if q:
        like = f"%{q}%"
        base = base.filter(or_(
            UniqueFinding.description.like(like),
            UniqueFinding.last_description.like(like),
            UniqueFinding.file_path.like(like),
            UniqueFinding.cwe.like(like),
            UniqueFinding.function_name.like(like),
            UniqueFinding.entrypoint.like(like),
            Project.name.like(like),
        ))

    sev_val = func.coalesce(UniqueFinding.severity, UniqueFinding.last_severity)
    sev_rank = case(
        (sev_val == "CRITICAL", 4),
        (sev_val == "HIGH", 3),
        (sev_val == "MEDIUM", 2),
        (sev_val == "LOW", 1),
        else_=0,
    )

    if sort == "last_seen_asc":
        base = base.order_by(UniqueFinding.last_seen_at.asc().nulls_last())
    elif sort == "severity_desc":
        base = base.order_by(sev_rank.desc(), UniqueFinding.last_seen_at.desc())
    elif sort == "severity_asc":
        base = base.order_by(sev_rank.asc(), UniqueFinding.last_seen_at.desc())
    elif sort == "status_asc":
        base = base.order_by(UniqueFinding.status.asc().nulls_last(), UniqueFinding.last_seen_at.desc())
    elif sort == "status_desc":
        base = base.order_by(UniqueFinding.status.desc().nulls_last(), UniqueFinding.last_seen_at.desc())
    elif sort == "occ_desc":
        base = base.order_by(UniqueFinding.occurrences.desc(), UniqueFinding.last_seen_at.desc())
    elif sort == "occ_asc":
        base = base.order_by(UniqueFinding.occurrences.asc(), UniqueFinding.last_seen_at.desc())
    elif sort == "project_asc":
        base = base.order_by(Project.name.asc(), UniqueFinding.last_seen_at.desc())
    elif sort == "file_asc":
        base = base.order_by(UniqueFinding.file_path.asc())
    else:
        base = base.order_by(UniqueFinding.last_seen_at.desc())

    total = base.count()
    items = base.offset((page - 1) * page_size).limit(page_size).all()

    return templates.TemplateResponse(
        "unique_all.html",
        {
            "request": request,
            "items": items,
            "q": q,
            "sort": sort,
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": (total + page_size - 1) // page_size,
        },
    )


@app.get("/unique_findings/{uf_id}/details.json")
def unique_finding_details(uf_id: int, db: Session = Depends(get_db)):
    uf = db.get(UniqueFinding, uf_id)
    if not uf:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    # Latest finding (any) for base fields
    latest_any = (
        db.query(Finding)
        .filter(Finding.unique_finding_id == uf_id)
        .order_by(Finding.id.desc())
        .first()
    )
    # Latest finding that has deep details
    latest_with_details = (
        db.query(Finding)
        .filter(Finding.unique_finding_id == uf_id, Finding.details_json.isnot(None))
        .order_by(Finding.id.desc())
        .first()
    )
    details = None
    if latest_with_details and latest_with_details.details_json:
        try:
            details = json.loads(latest_with_details.details_json)
        except Exception:
            details = None
    return {
        "unique": {
            "id": uf.id,
            "severity": uf.severity or uf.last_severity,
            "description": uf.description or uf.last_description,
            "file_path": uf.file_path,
            "cwe": uf.cwe,
            "function_name": uf.function_name,
            "entrypoint": uf.entrypoint,
            "occurrences": uf.occurrences,
            "last_seen_at": uf.last_seen_at.isoformat() if uf.last_seen_at else None,
            "status": uf.status,
        },
        "finding": {
            "recommendation": getattr(latest_any, "recommendation", None),
            "function_name": getattr(latest_any, "function_name", None),
            "entrypoint": getattr(latest_any, "entrypoint", None),
            "arguments": getattr(latest_any, "arguments", None),
            "root_cause": getattr(latest_any, "root_cause", None),
            "line": getattr(latest_any, "line", None),
        } if latest_any else None,
        "details": details,
    }


@app.post("/unique_findings/{uf_id}/status")
def set_unique_finding_status(uf_id: int, status: str = Form(...), db: Session = Depends(get_db)):
    uf = db.get(UniqueFinding, uf_id)
    if uf:
        uf.status = status
        db.add(uf)
        db.commit()
    # Redirect back to the project page
    # Find a related project id
    pid = uf.project_id if uf else None
    return RedirectResponse(url=f"/projects/{pid}" if pid else "/", status_code=303)


@app.post("/unique_findings/{uf_id}/delete")
def delete_unique_finding(uf_id: int, db: Session = Depends(get_db)):
    uf = db.get(UniqueFinding, uf_id)
    pid = uf.project_id if uf else None
    if uf:
        db.delete(uf)
        db.commit()
    return RedirectResponse(url=f"/projects/{pid}" if pid else "/", status_code=303)


@app.post("/unique_findings/bulk_status")
def bulk_set_unique_finding_status(status: str = Form(...), ids: str = Form(""), redirect: str = Form("/"), db: Session = Depends(get_db)):
    id_list = [int(x) for x in (ids.split(",") if ids else []) if x.strip().isdigit()]
    if id_list:
        q = db.query(UniqueFinding).filter(UniqueFinding.id.in_(id_list)).all()
        for uf in q:
            uf.status = status
            db.add(uf)
        db.commit()
    return RedirectResponse(url=redirect or "/", status_code=303)


@app.post("/unique_findings/bulk_delete")
def bulk_delete_unique_findings(ids: str = Form(""), redirect: str = Form("/"), db: Session = Depends(get_db)):
    id_list = [int(x) for x in (ids.split(",") if ids else []) if x.strip().isdigit()]
    if id_list:
        q = db.query(UniqueFinding).filter(UniqueFinding.id.in_(id_list)).all()
        for uf in q:
            db.delete(uf)
        db.commit()
    return RedirectResponse(url=redirect or "/", status_code=303)


@app.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        return RedirectResponse(url="/", status_code=303)
    if scan.status != "running":
        return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)
    with RUNNING_LOCK:
        proc = RUNNING_PROCS.get(scan_id)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
    # Wait briefly and force kill if needed
    with RUNNING_LOCK:
        proc = RUNNING_PROCS.get(scan_id)
    if proc and proc.poll() is None:
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    with session_scope() as session:
        session.add(ScanLog(scan_id=scan_id, level="WARN", message="Scan cancelled by user"))
        sc = session.get(Scan, scan_id)
        if sc:
            sc.status = "cancelled"
            sc.completed_at = datetime.utcnow()
    return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)


