import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Dict, Any, Set

from dotenv import load_dotenv
from openai import OpenAI


SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".cpp", ".c", ".h", ".hpp", ".rs", ".kt", ".swift", ".sh", ".yml", ".yaml", ".json",
}

# Directory names to skip anywhere in the tree (case-insensitive by name)
SKIP_DIR_NAMES = {
    ".git", "node_modules", ".venv", "venv", "dist", "build",
    "test", "tests", "doc", "docs","lib","libs","scripts","scripts",
    "tools","packages","etc","etcs","utils","utils"
}


@dataclass
class Finding:
    id: Optional[str]
    file_path: str
    severity: str
    line: Optional[int]
    rule_id: Optional[str]
    cwe: Optional[List[str]]
    description: str
    recommendation: Optional[str]
    confidence: Optional[str]
    function_name: Optional[str] = None
    entrypoint: Optional[str] = None
    arguments: Optional[List[str]] = None
    root_cause: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


def build_ignored(base_path: Path, ignore_patterns: Optional[List[str]]) -> Set[Path]:
    ignored: Set[Path] = set()
    if not ignore_patterns:
        return ignored
    # Resolve patterns relative to base_path
    for pattern in ignore_patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        for p in base_path.glob(pattern):
            try:
                ignored.add(p.resolve())
            except Exception:
                ignored.add(p)
    return ignored


def iter_files(base_path: Path, ignore_patterns: Optional[List[str]] = None) -> Iterable[Path]:
    ignored = build_ignored(base_path, ignore_patterns)
    for root, dirs, files in os.walk(base_path):
        # Skip configured dir names and hidden dirs
        dirs[:] = [
            d for d in dirs
            if d.lower() not in SKIP_DIR_NAMES and not d.startswith(".")
        ]
        for f in files:
            if f.startswith('.'):
                continue
            p = Path(root) / f
            resolved = None
            try:
                resolved = p.resolve()
            except Exception:
                resolved = p
            if resolved in ignored:
                continue
            if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield p


def read_file_safely(p: Path, max_bytes: int) -> str:
    try:
        data = p.read_bytes()
        if len(data) > max_bytes:
            return data[:max_bytes].decode("utf-8", errors="replace") + "\n... [truncated]"
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[error reading file: {e}]"


def analyze_file(client: OpenAI, model: str, file_path: Path, content: str, temperature: float = 0.0, verbose: bool = False) -> List[Finding]:
    system_prompt = (
        "You are a strict SAST engine. Analyze code for security issues. "
        "Return ONLY a JSON object with a 'findings' array. Each finding MUST be: "
        "{id (uuid or null), file_path, severity(one of LOW, MEDIUM, HIGH, CRITICAL), line(int or null), "
        "rule_id(string or null), cwe(array of strings or null), description(string), "
        "recommendation(string with concrete remediation steps), confidence(string or null), "
        "function_name(string or null), entrypoint(string or null), arguments(array of strings or null), "
        "root_cause(string or null)}."
    )

    user_prompt = f"""
File path: {file_path}

Code:
{content}

Provide findings as a JSON object matching the specified schema.
"""

    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        text = resp.choices[0].message.content or "{}"
        obj = json.loads(text)
        raw_findings = obj.get("findings", [])
        findings: List[Finding] = []
        for f in raw_findings:
            findings.append(
                Finding(
                    id=f.get("id"),
                    file_path=str(file_path),
                    severity=f.get("severity", "LOW"),
                    line=f.get("line"),
                    rule_id=f.get("rule_id"),
                    cwe=f.get("cwe"),
                    description=f.get("description", ""),
                    recommendation=f.get("recommendation"),
                    confidence=f.get("confidence"),
                    function_name=f.get("function_name"),
                    entrypoint=f.get("entrypoint"),
                    arguments=f.get("arguments"),
                    root_cause=f.get("root_cause"),
                    details=f.get("details"),
                )
            )
        return findings
    except Exception as e:
        # On model error, return a single LOW severity note
        return [
            Finding(
                id=None,
                file_path=str(file_path),
                severity="LOW",
                line=None,
                rule_id=None,
                cwe=None,
                description=f"Analyzer error: {e}",
                recommendation=None,
                confidence=None,
            )
        ]
def expand_finding(client: OpenAI, model: str, file_path: Path, content: str, finding: Finding, temperature: float = 0.0) -> Dict[str, Any]:
    """Request richer details for a single finding. Returns a details dict."""
    around = 20
    snippet = None
    if finding.line:
        try:
            lines = content.splitlines()
            start = max(1, finding.line - around)
            end = min(len(lines), finding.line + around)
            snippet = "\n".join(lines[start - 1:end])
        except Exception:
            snippet = None

    system_prompt = (
        "You are a senior application security engineer providing concise but deep findings. "
        "Return ONLY a JSON object with keys: explanation, impact, proof_of_concept, fix_suggestion, "
        "references(array of strings of URLs or identifiers), evidence(object with start_line, end_line, snippet)."
    )
    user_prompt = f"""
File path: {file_path}
Finding summary: severity={finding.severity}, line={finding.line}, cwe={finding.cwe}

Code context (may be partial):
{snippet or content}

Provide expanded details as a JSON object matching the specified keys.
"""
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=temperature,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=1200,
        )
        text = resp.choices[0].message.content or "{}"
        obj = json.loads(text)
        evidence = obj.get("evidence") or {}
        if snippet and not evidence.get("snippet") and finding.line:
            evidence = {
                "start_line": max(1, finding.line - around),
                "end_line": (finding.line + around) if finding.line else None,
                "snippet": snippet,
            }
        return {
            "explanation": obj.get("explanation"),
            "impact": obj.get("impact"),
            "proof_of_concept": obj.get("proof_of_concept"),
            "fix_suggestion": obj.get("fix_suggestion"),
            "references": obj.get("references", []),
            "evidence": evidence,
        }
    except Exception as e:
        return {"explanation": f"detail-expansion error: {e}"}



def run_scan(path: Path, model: str, max_bytes: int = 200_000, temperature: float = 0.0, verbose: bool = False, deep: bool = False, deep_limit: int = 10, ignore: Optional[List[str]] = None) -> dict:
    load_dotenv()
    client = OpenAI()

    all_findings: List[Finding] = []
    files_iter = list(iter_files(path, ignore_patterns=ignore)) if verbose else iter_files(path, ignore_patterns=ignore)
    if verbose and isinstance(files_iter, list):
        sys.stderr.write(f"[scanner] Starting scan of {len(files_iter)} files in {path}\n")
        sys.stderr.flush()
    for file_path in files_iter:
        if verbose:
            sys.stderr.write(f"[scanner] Analyzing {file_path}\n")
            sys.stderr.flush()
        content = read_file_safely(file_path, max_bytes)
        file_findings = analyze_file(client, model, file_path, content, temperature, verbose=verbose)
        if deep and file_findings:
            for f in file_findings[:max(0, deep_limit)]:
                if verbose:
                    sys.stderr.write(f"[scanner] Expanding finding at {file_path}:{f.line}\n")
                    sys.stderr.flush()
                f.details = expand_finding(client, model, file_path, content, f, temperature=temperature)
        all_findings.extend(file_findings)

    if verbose:
        sys.stderr.write(f"[scanner] Completed scan. Total findings: {len(all_findings)}\n")
        sys.stderr.flush()
    return {
        "project_path": str(path.resolve()),
        "model": model,
        "generated_at": int(time.time()),
        "findings": [asdict(f) for f in all_findings],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="sassycode-scanner", description="SAST scanner using OpenAI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a project directory")
    p_scan.add_argument("--path", required=True, help="Path to project root")
    p_scan.add_argument("--model", required=True, help="OpenAI model (e.g., gpt-4o-mini)")
    p_scan.add_argument("--max-bytes", type=int, default=200_000, help="Max bytes per file")
    p_scan.add_argument("--temperature", type=float, default=0.0)
    p_scan.add_argument("--verbose", action="store_true", help="Log progress to stderr")
    p_scan.add_argument("--deep", action="store_true", help="Request richer per-finding details")
    p_scan.add_argument("--deep-limit", type=int, default=10, help="Max findings per file to expand")
    p_scan.add_argument("--ignore", help="Comma-separated glob patterns to ignore (relative to path)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.path)
        if not target.exists():
            print(json.dumps({"error": f"path does not exist: {target}"}))
            return 2
        ignore = [s.strip() for s in (args.ignore.split(',') if args.ignore else []) if s.strip()]
        result = run_scan(target, args.model, args.max_bytes, args.temperature, args.verbose, args.deep, args.deep_limit, ignore)
        print(json.dumps(result, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


