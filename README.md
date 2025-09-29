# sassycode

Two-part Python project:

- Scanner CLI: runs standalone SAST scans on a folder and prints JSON findings
- Management server: launches scans, ingests results into SQLite, and provides a minimal web UI

## Quickstart

1. Create venv and install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

2. Configure environment

```bash
cp env.example .env
export $(grep -v '^#' .env | xargs)  # or use a shell that auto-loads .env
```

3. Run scanner (standalone)

```bash
sassycode-scanner scan --path /path/to/repo --model gpt-4o-mini
```

Alternate ways to run the scanner (equivalent):

```bash
# 1) Console script (shown above)
sassycode-scanner scan --path "/Users/jeremydubansky/dev/WebGoat/webgoatIT" --model gpt-4o-mini --verbose

# 2) Module invocation (no entrypoint needed)
python -m scanner.cli scan --path "/Users/jeremydubansky/dev/WebGoat/webgoatIT" --model gpt-4o-mini --verbose

# 3) Direct file execution (ensure PYTHONPATH points to repo root)
PYTHONPATH=/Users/jeremydubansky/dev/sassycode \
python /Users/jeremydubansky/dev/sassycode/scanner/cli.py scan --path "/Users/jeremydubansky/dev/WebGoat/webgoatIT" --model gpt-4o-mini --verbose
```

4. Run management server

```bash
sassycode-manager --reload
```

Open http://localhost:8008 to use the UI (default port can be overridden with `--port` or `PORT`).

## Notes

- Requires Python 3.11+
- Uses SQLite by default; see `DATABASE_URL` in `.env`
- OpenAI key required: set `OPENAI_API_KEY`
