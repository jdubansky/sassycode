import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Dict, Any, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time as _time

from dotenv import load_dotenv
from openai import OpenAI


SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".cpp", ".c", ".h", ".hpp", ".rs", ".kt", ".swift", ".sh", ".yml", ".yaml", ".json",
}

# Models that reject non-default temperature (omit temperature for these)
FIXED_TEMP_MODELS = ("gpt-5",)


def is_fixed_temperature_model(model: str) -> bool:
    m = (model or "").lower()
    return any(m.startswith(x) for x in FIXED_TEMP_MODELS)

_CONCURRENCY = 4


def _chat_with_retry(client: OpenAI, params: Dict[str, Any], max_attempts: int = 4) -> Any:
    delay = 0.75
    for attempt in range(1, max_attempts + 1):
        try:
            return client.chat.completions.create(**params)
        except Exception as e:
            msg = str(e)
            retriable = any(code in msg for code in ["429", "timeout", "Temporary failure", "rate limit", "503", "502"]) or hasattr(e, "status_code") and getattr(e, "status_code") in (429, 500, 502, 503)
            if attempt == max_attempts or not retriable:
                raise
            _time.sleep(delay)
            delay *= 1.7

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
    ignored_dirs = [p for p in ignored if p.exists() and p.is_dir()]
    for root, dirs, files in os.walk(base_path):
        # Skip configured dir names and hidden dirs
        pruned_dirs = []
        for d in dirs:
            if d.lower() in SKIP_DIR_NAMES or d.startswith("."):
                continue
            dpath = (Path(root) / d)
            try:
                dres = dpath.resolve()
            except Exception:
                dres = dpath
            # If this directory is under any ignored dir, prune it entirely
            skip = False
            for idp in ignored_dirs:
                try:
                    dres.relative_to(idp)
                    skip = True
                    break
                except Exception:
                    continue
            if not skip:
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs
        for f in files:
            if f.startswith('.'):
                continue
            p = Path(root) / f
            resolved = None
            try:
                resolved = p.resolve()
            except Exception:
                resolved = p
            # Skip if file itself is ignored or it is under an ignored directory
            if resolved in ignored:
                continue
            skip_by_dir = False
            for idp in ignored_dirs:
                try:
                    resolved.relative_to(idp)
                    skip_by_dir = True
                    break
                except Exception:
                    continue
            if skip_by_dir:
                continue
            if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield p


def _parse_imports_for_python(text: str) -> List[str]:
    # Very lightweight parsing; handles lines like: import pkg.mod as x  OR  from pkg.mod import Foo
    imports: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("import "):
            parts = line.split()
            # import a.b.c, d.e → take first token after import
            if len(parts) >= 2:
                target = parts[1].split(",")[0].strip()
                imports.append(target)
        elif line.startswith("from "):
            parts = line.split()
            if len(parts) >= 2:
                imports.append(parts[1])
    return imports


def _parse_imports_for_js(text: str) -> List[str]:
    imports: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        # import ... from '...'
        if line.startswith("import ") and " from " in line and ("'" in line or '"' in line):
            quote = "'" if "'" in line else '"'
            try:
                target = line.split(" from ")[-1].split(quote)[1]
                imports.append(target)
            except Exception:
                pass
        # const x = require('...')
        if "require(" in line:
            try:
                start = line.index("require(") + 8
                segment = line[start:]
                quote = "'" if "'" in segment else '"'
                target = segment.split(quote)[1]
                imports.append(target)
            except Exception:
                pass
    return imports


def build_import_graph(base_path: Path, files: List[Path]) -> Dict[Path, Set[Path]]:
    """Build a simple import graph among project files.
    Only inspects .py, .js, .ts, .jsx, .tsx and resolves local relative imports for JS/TS.
    For Python, attempts to map module paths to files within base_path.
    """
    file_set: Set[Path] = {p.resolve() for p in files}
    graph: Dict[Path, Set[Path]] = {p.resolve(): set() for p in files}

    js_like = {".js", ".ts", ".jsx", ".tsx"}

    # Precompute module name to path candidates for python (best-effort)
    module_to_path: Dict[str, Path] = {}
    for p in files:
        if p.suffix == ".py":
            rel = p.relative_to(base_path)
            mod = ".".join(rel.with_suffix("").parts)
            module_to_path[mod] = p

    def resolve_py_module(mod: str) -> Optional[Path]:
        # Try exact match, then without trailing .__init__
        if mod in module_to_path:
            return module_to_path[mod]
        if mod.endswith(".__init__"):
            m2 = mod.rsplit(".__init__", 1)[0]
            return module_to_path.get(m2)
        # Try progressively trimming
        parts = mod.split(".")
        while parts:
            candidate = base_path.joinpath(*parts).with_suffix(".py")
            if candidate.exists():
                return candidate
            pkg = base_path.joinpath(*parts, "__init__.py")
            if pkg.exists():
                return pkg
            parts = parts[:-1]
        return None

    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        neighbors: Set[Path] = set()
        if p.suffix == ".py":
            for mod in _parse_imports_for_python(text):
                resolved = resolve_py_module(mod)
                if resolved and resolved.resolve() in file_set and resolved.resolve() != p.resolve():
                    neighbors.add(resolved.resolve())
        elif p.suffix in js_like:
            for target in _parse_imports_for_js(text):
                if target.startswith("./") or target.startswith("../"):
                    abs_target = (p.parent / target)
                    # try with extensions
                    candidates = [abs_target]
                    for ext in ["", ".js", ".ts", ".jsx", ".tsx"]:
                        candidates.append(abs_target.with_suffix(ext))
                    for c in candidates:
                        try:
                            rc = c.resolve()
                            if rc in file_set and rc != p.resolve():
                                neighbors.add(rc)
                                break
                        except Exception:
                            continue
        if neighbors:
            graph[p.resolve()].update(neighbors)
            # Add reverse edges for undirected neighborhood traversal
            for n in neighbors:
                graph.setdefault(n, set()).add(p.resolve())
    return graph


def related_files_for(file_path: Path, graph: Dict[Path, Set[Path]], depth: int, limit: int) -> List[Path]:
    start = file_path.resolve()
    if start not in graph or limit <= 0:
        return []
    seen = {start}
    q: List[Tuple[Path, int]] = [(start, 0)]
    out: List[Path] = []
    while q and len(out) < limit:
        cur, d = q.pop(0)
        if d >= depth:
            continue
        for n in graph.get(cur, set()):
            if n in seen:
                continue
            seen.add(n)
            out.append(n)
            if len(out) >= limit:
                break
            q.append((n, d + 1))
    return out


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
        params: Dict[str, Any] = {
            "model": model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if not is_fixed_temperature_model(model):
            params["temperature"] = temperature
        resp = _chat_with_retry(client, params)
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
def expand_finding(client: OpenAI, model: str, file_path: Path, content: str, finding: Finding, temperature: float = 0.0, related_snippets: Optional[List[Tuple[Path, str]]] = None) -> Dict[str, Any]:
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
    related_block = ""
    if related_snippets:
        parts = []
        for rp, rtxt in related_snippets[:5]:
            parts.append(f"\n[Related file: {rp}]\n{rtxt}\n")
        related_block = "\n".join(parts)

    user_prompt = f"""
File path: {file_path}
Finding summary: severity={finding.severity}, line={finding.line}, cwe={finding.cwe}

Code context (may be partial):
{snippet or content}

Related context (optional, partial):
{related_block}

Provide expanded details as a JSON object matching the specified keys.
"""
    try:
        params: Dict[str, Any] = {
            "model": model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 1200,
        }
        if not is_fixed_temperature_model(model):
            params["temperature"] = temperature
        resp = _chat_with_retry(client, params)
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



def run_scan(path: Path, model: str, max_bytes: int = 200_000, temperature: float = 0.0, verbose: bool = False, deep: bool = False, deep_limit: int = 10, ignore: Optional[List[str]] = None, include_related: bool = False, context_depth: int = 1, context_files: int = 5, context_lines: int = 60) -> dict:
    load_dotenv()
    client = OpenAI()

    all_findings: List[Finding] = []
    if verbose and is_fixed_temperature_model(model):
        sys.stderr.write("[scanner] Model enforces fixed temperature; ignoring custom temperature setting\n")
        sys.stderr.flush()
    files_list = list(iter_files(path, ignore_patterns=ignore))
    files_iter = files_list if verbose else files_list
    import_graph: Dict[Path, Set[Path]] = {}
    if include_related:
        if verbose:
            sys.stderr.write("[scanner] Building import graph for related context\n")
            sys.stderr.flush()
        import_graph = build_import_graph(path, files_list)
    if verbose and isinstance(files_iter, list):
        sys.stderr.write(f"[scanner] Starting scan of {len(files_iter)} files in {path}\n")
        sys.stderr.flush()
    if verbose:
        if ignore:
            sys.stderr.write(f"[scanner] Ignore patterns: {ignore}\n")
        sys.stderr.write(f"[scanner] Files to scan after ignores: {len(files_list)}\n")
        sys.stderr.flush()

    def process_file(file_path: Path) -> List[Finding]:
        loc_client = client  # reuse global client; API client is threadsafe for simple requests
        if verbose:
            sys.stderr.write(f"[scanner] Analyzing {file_path}\n")
            sys.stderr.flush()
        content = read_file_safely(file_path, max_bytes)
        file_findings = analyze_file(loc_client, model, file_path, content, temperature, verbose=verbose)
        if deep and file_findings:
            for f in file_findings[:max(0, deep_limit)]:
                if verbose:
                    sys.stderr.write(f"[scanner] Expanding finding at {file_path}:{f.line}\n")
                    sys.stderr.flush()
                related_snippets: Optional[List[Tuple[Path, str]]] = None
                if include_related and import_graph:
                    neighbors = related_files_for(file_path, import_graph, depth=context_depth, limit=context_files)
                    snippets: List[Tuple[Path, str]] = []
                    for nb in neighbors:
                        try:
                            txt = nb.read_text(encoding="utf-8", errors="replace")
                            if len(txt) > context_lines * 200:
                                txt = txt[:context_lines*100] + "\n...\n" + txt[-context_lines*100:]
                            snippets.append((nb, txt))
                        except Exception:
                            continue
                    related_snippets = snippets
                f.details = expand_finding(loc_client, model, file_path, content, f, temperature=temperature, related_snippets=related_snippets)
        return file_findings

    results: List[Finding] = []
    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        future_to_path = {pool.submit(process_file, fp): fp for fp in files_iter}
        for fut in as_completed(future_to_path):
            try:
                findings = fut.result()
                results.extend(findings)
            except Exception as e:
                # Log and continue
                if verbose:
                    sys.stderr.write(f"[scanner] Worker error: {e}\n")
                    sys.stderr.flush()
                continue
    all_findings.extend(results)

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
    p_scan.add_argument("--include-related", action="store_true", help="Include related files context in deep analysis")
    p_scan.add_argument("--context-depth", type=int, default=1, help="Depth in import graph for related files")
    p_scan.add_argument("--context-files", type=int, default=5, help="Max related files")
    p_scan.add_argument("--context-lines", type=int, default=60, help="Approx lines per related snippet budget")
    p_scan.add_argument("--concurrency", type=int, default=4, help="Max parallel file analyses")

    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.path)
        if not target.exists():
            print(json.dumps({"error": f"path does not exist: {target}"}))
            return 2
        ignore = [s.strip() for s in (args.ignore.split(',') if args.ignore else []) if s.strip()]
        global _CONCURRENCY
        _CONCURRENCY = max(1, int(args.concurrency))
        result = run_scan(target, args.model, args.max_bytes, args.temperature, args.verbose, args.deep, args.deep_limit, ignore, args.include_related, args.context_depth, args.context_files, args.context_lines)
        print(json.dumps(result, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


