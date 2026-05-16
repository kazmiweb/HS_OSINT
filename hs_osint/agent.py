"""Analysis agent for turning raw OSINT results into an operator summary."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from hs_osint.models import QueryAnalysis, SearchResult


class AnalysisAgent:
    """Produces a concise analysis using local rules or an optional LLM API."""

    def __init__(
        self,
        openai_compatible_url: str | None = None,
        api_key_env: str | None = None,
        model: str = "gpt-4o-mini",
    ) -> None:
        self.openai_compatible_url = openai_compatible_url
        self.api_key_env = api_key_env
        self.model = model

    def summarize(self, analysis: QueryAnalysis, results: list[SearchResult]) -> dict[str, object]:
        if self.openai_compatible_url and self.api_key_env and os.getenv(self.api_key_env):
            remote = self._remote_summary(analysis, results)
            if remote:
                return remote
        return self._local_summary(analysis, results)

    def _local_summary(
        self, analysis: QueryAnalysis, results: list[SearchResult]
    ) -> dict[str, object]:
        provider_counts: dict[str, int] = {}
        for result in results:
            provider_counts[result.provider] = provider_counts.get(result.provider, 0) + 1

        confidence = "low"
        if len(results) >= 5 and len(provider_counts) >= 2:
            confidence = "medium"
        if len(results) >= 10 and len(provider_counts) >= 3:
            confidence = "high"

        next_steps = [
            "Validate high-value matches manually before making decisions.",
            "Correlate across at least two independent sources.",
            "Add your approved API keys and local datasets in config.toml for richer coverage.",
        ]
        if "credential_terms" in analysis.risk_flags:
            next_steps.append(
                "Use breach metadata only; do not collect or display raw leaked passwords."
            )

        return {
            "mode": "local_rules",
            "query_types": analysis.query_types,
            "result_count": len(results),
            "providers_hit": provider_counts,
            "confidence": confidence,
            "risk_flags": analysis.risk_flags,
            "next_steps": next_steps,
        }

    def _remote_summary(
        self, analysis: QueryAnalysis, results: list[SearchResult]
    ) -> dict[str, object] | None:
        api_key = os.getenv(self.api_key_env or "")
        if not api_key:
            return None

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an OSINT analyst. Summarize findings, note confidence, "
                        "and avoid exposing secrets, passwords, tokens, or doxxing guidance."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "analysis": analysis.to_dict(),
                            "results": [result.to_dict() for result in results[:20]],
                        }
                    ),
                },
            ],
            "temperature": 0.2,
        }
        request = Request(
            self.openai_compatible_url or "",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "HS-OSINT/0.1",
            },
        )
        try:
            with urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            return None

        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        if not content:
            return None
        return {"mode": "llm", "summary": content}
