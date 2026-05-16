"""Output formatting."""

from __future__ import annotations

import json
from typing import Any


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def render_markdown(payload: dict[str, Any]) -> str:
    analysis = payload["analysis"]
    results = payload["results"]
    skipped = payload["skipped"]
    agent = payload["agent"]

    lines = [
        "# HS OSINT Report",
        "",
        f"**Query:** `{analysis['normalized']}`",
        f"**Types:** {', '.join(analysis['query_types'])}",
        f"**Intent:** {analysis['intent']}",
    ]
    if analysis["risk_flags"]:
        lines.append(f"**Risk flags:** {', '.join(analysis['risk_flags'])}")

    lines.extend(["", "## Results"])
    if not results:
        lines.append("No matching results returned from enabled providers.")
    for index, result in enumerate(results, start=1):
        url = f" ({result['url']})" if result.get("url") else ""
        lines.extend(
            [
                f"{index}. **{result['title']}** - `{result['provider']}`{url}",
                f"   - Value: {result['value']}",
            ]
        )
        if result.get("snippet"):
            lines.append(f"   - Snippet: {result['snippet']}")
        if result.get("tags"):
            lines.append(f"   - Tags: {', '.join(result['tags'])}")

    if skipped:
        lines.extend(["", "## Skipped providers"])
        for provider, reason in skipped.items():
            lines.append(f"- `{provider}`: {reason}")

    lines.extend(["", "## Agent analysis", "```json", json.dumps(agent, indent=2), "```"])
    return "\n".join(lines)
