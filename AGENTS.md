# AGENTS.md

## Cursor Cloud specific instructions

### Overview

HS_OSINT is a pure-Python (3.11+) CLI tool with **zero third-party dependencies** — everything uses the stdlib. The only dev dependency is `pytest` for running tests.

### Quick reference

| Action | Command |
|---|---|
| Install (editable) | `pip install -e .` |
| Run tests | `python3 -m pytest tests/ -v` |
| Run CLI | `python3 -m hs_osint search "<query>" --format markdown` |
| CLI via script | `hs-osint search "<query>"` (requires `~/.local/bin` on PATH) |

### Caveats

- The `hs-osint` console script installs to `~/.local/bin` which may not be on PATH. Use `python3 -m hs_osint` as a reliable alternative, or prepend `PATH="$HOME/.local/bin:$PATH"`.
- Some providers make live HTTP requests to public APIs (GitHub, Wayback Machine, social platforms). Tests in `tests/` are fully offline and use no network, but CLI searches may need internet access.
- No database, Docker, or external services are required.
- Config is optional — the tool runs with sensible defaults. See `config.example.toml` for API keys and custom provider setup.
