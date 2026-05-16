# HS_OSINT

HS_OSINT is a safe, extensible OSINT search and analysis CLI. It accepts a
query, classifies it, runs configured public or user-owned data providers, and
returns a normalized report with an analysis summary.

The project is designed as a professional OSINT framework you can extend with
your own lawful databases and APIs. It intentionally does **not** collect,
display, or store raw leaked passwords, session tokens, cookies, private keys,
or credential dumps. Breach-related connectors are metadata-only.

## Features

- Query understanding for usernames, emails, domains, URLs, IP addresses,
  phone-like strings, hashes, person names, and free-text keywords.
- Provider-based architecture for public APIs, local datasets, social-profile
  checks, GitHub repository search, Wayback Machine metadata, and breach
  exposure metadata.
- Configurable generic HTTP connector for your own APIs.
- Local dataset connector for CSV, JSON, JSONL, TXT, and SQLite files.
- Optional OpenAI-compatible analysis agent for summarizing findings.
- Safety policy that redacts secrets and requires explicit lawful-use
  acknowledgement for personal-data or breach-metadata providers.

## Quick start

```bash
python3 -m hs_osint search "example.com" --format markdown
python3 -m hs_osint search "@exampleuser" --provider social_profiles --format json
```

Install locally as a console script:

```bash
python3 -m pip install -e .
hs-osint search "example.com"
```

## Configuration

Copy the example config and add your approved APIs or local datasets:

```bash
cp config.example.toml config.toml
```

Then run:

```bash
hs-osint search "example.com" --config config.toml
```

For local files and breach-metadata providers, acknowledge lawful use:

```bash
hs-osint search "user@example.com" \
  --config config.toml \
  --acknowledge-lawful-use
```

## Provider model

Built-in providers:

| Provider | Purpose | Notes |
| --- | --- | --- |
| `github_repositories` | Public GitHub repository search | Uses GitHub public search API. |
| `wayback` | Internet Archive CDX metadata | Searches archived URLs for domains/URLs/emails. |
| `social_profiles` | Public username URL checks | Uses configurable profile URL templates. |
| `local_files` | User-supplied datasets | Supports CSV, JSON, JSONL, TXT, SQLite. Requires acknowledgement. |
| `generic_http` | User-configured JSON APIs | Add services in `config.toml`. |
| `breach_metadata` | Metadata-only exposure checks | No raw credentials. Requires acknowledgement. |

## Adding your own APIs

Add a service under `[[providers.generic_http.services]]`:

```toml
[[providers.generic_http.services]]
name = "my_approved_api"
url = "https://api.example.com/search"
params = { q = "{query}" }
headers = { Authorization = "env:MY_APPROVED_API_TOKEN" }
json_path = "results"
requires_lawful_use_ack = true
metadata_only = true
```

Environment variables are referenced with the `env:` prefix so secrets are not
committed to the repository.

## AI analysis

The tool includes a local rule-based analysis agent by default. To use an
OpenAI-compatible endpoint, configure:

```toml
[ai]
openai_compatible_url = "https://api.openai.com/v1/chat/completions"
api_key_env = "OPENAI_API_KEY"
model = "gpt-4o-mini"
```

The agent prompt instructs the model to avoid exposing secrets, passwords,
tokens, or doxxing guidance.

## Responsible use

Use this tool only on data you are authorized to process, for defensive,
investigative, or compliance purposes. Do not use it to harass, dox, stalk,
steal credentials, bypass access controls, or retrieve private information from
systems where you do not have permission.
