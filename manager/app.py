import json
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .db import init_db, migrate_db, session_scope, SessionLocal
from .models import Project, Scan, Finding, ScanLog


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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()
    migrate_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    projects = db.query(Project).all()
    return templates.TemplateResponse("index.html", {"request": request, "projects": projects})


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
    return templates.TemplateResponse("project.html", {"request": request, "project": project, "scans": scans})


@app.get("/projects/{project_id}/edit", response_class=HTMLResponse)
def edit_project(project_id: int, request: Request, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("project_edit.html", {"request": request, "project": project})


@app.post("/projects/{project_id}")
def update_project(project_id: int, name: str = Form(...), path: str = Form(...), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        return RedirectResponse(url="/", status_code=303)
    project.name = name
    project.path = path
    db.add(project)
    db.commit()
    return RedirectResponse(url=f"/projects/{project_id}", status_code=303)


@app.post("/scans")
def trigger_scan(project_id: int = Form(...), model: str = Form(...), deep: str = Form(None), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        return RedirectResponse(url="/", status_code=303)

    scan = Scan(project_id=project.id, model=model, status="running", started_at=datetime.utcnow())
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
    if deep:
        cmd.append("--deep")

    # seed a startup log so UI shows activity immediately
    with session_scope() as session:
        session.add(ScanLog(scan_id=scan.id, level="INFO", message=f"Starting scan for {project.path} using {model}"))

    def run_and_ingest(scan_id: int):
        success = False
        try:
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
                    session.add(
                        Finding(
                            scan_id=scan_id,
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


